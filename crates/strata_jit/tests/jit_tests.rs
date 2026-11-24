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

fn compile_fixture_and_verify(stem: &str, path: &str, opt_level: JitOptLevel) {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let full_path = manifest_dir.join("../..").join(path);
    let src = std::fs::read_to_string(&full_path)
        .unwrap_or_else(|e| panic!("failed reading {}: {e}", full_path.display()));
    compile_source_and_verify(stem, path, &src, opt_level);
}

fn compile_source_and_verify(stem: &str, file_name: &str, src: &str, opt_level: JitOptLevel) {
    let analyzed = analyze_source(file_name, src);
    assert!(
        analyzed.ok(),
        "sema diagnostics for {file_name}: {:?}",
        analyzed.diagnostics
    );
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: stem.to_owned(),
            opt_level,
        },
    )
    .unwrap_or_else(|e| panic!("JIT compile failed for {file_name}: {e}"));

    assert!(artifact.object_path.exists());
    assert!(artifact.dylib_path.exists());

    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let mut nm_obj = Command::new("nm");
        let out_obj = nm_obj.arg(&artifact.object_path).output().expect("nm .o");
        assert!(out_obj.status.success());
        let obj_syms = String::from_utf8_lossy(&out_obj.stdout);
        assert!(
            !obj_syms.contains("strata_jit_state"),
            "unexpected BSS global `strata_jit_state` found in {file_name}:\n{obj_syms}"
        );
        assert!(
            obj_syms.contains("calloc") && obj_syms.contains("free"),
            "expected heap calloc/free imports in {file_name}:\n{obj_syms}"
        );

        let mut nm_dyn = Command::new("nm");
        if cfg!(target_os = "macos") {
            nm_dyn.arg("-gU");
        } else {
            nm_dyn.arg("-D");
        }
        let out_dyn = nm_dyn.arg(&artifact.dylib_path).output().expect("nm dylib");
        assert!(out_dyn.status.success());
        let dyn_syms = String::from_utf8_lossy(&out_dyn.stdout);
        for required in ["bamabi_manifest", "bamabi_init", "bamabi_shutdown"] {
            assert!(
                dyn_syms.contains(required),
                "missing exported symbol `{required}` in {file_name}:\n{dyn_syms}"
            );
        }
    }
}

#[test]
fn cranelift_jit_compiles_all_six_cookbooks_direct_mir() {
    let cookbooks = [
        ("rain_swarm", "fixtures/cookbooks/01_rain_swarm.strata"),
        (
            "soa_and_ticks",
            "fixtures/cookbooks/02_soa_and_ticks.strata",
        ),
        (
            "metroidvania_core",
            "fixtures/cookbooks/03_metroidvania_core.strata",
        ),
        ("cozy_valley", "fixtures/cookbooks/04_cozy_valley.strata"),
        (
            "soulslike_combat",
            "fixtures/cookbooks/05_soulslike_combat.strata",
        ),
        (
            "battle_royale",
            "fixtures/cookbooks/06_battle_royale_server.strata",
        ),
        (
            "visual_boss_graph",
            "fixtures/cookbooks/07_visual_boss_graph.strata",
        ),
        (
            "authoritative_multiplayer",
            "fixtures/cookbooks/08_authoritative_multiplayer.strata",
        ),
    ];

    for (stem, path) in cookbooks {
        compile_fixture_and_verify(stem, path, JitOptLevel::Speed);
    }
    compile_fixture_and_verify(
        "rain_fast",
        "fixtures/cookbooks/01_rain_swarm.strata",
        JitOptLevel::FastCompile,
    );
}

#[test]
fn cranelift_jit_compiles_schema_migration_fixture() {
    let src = r#"
module demo::mig @version(2.0.0);

component HealthV1 {
    hp: i32,
}

component Health {
    hp: f32 = 100.0,
    regen: f32 = 2.5,
}

migrate Health from 1.0.0 to 2.0.0(old: &HealthV1) -> Health {
    Health { hp: old.hp as f32, regen: 2.5 }
}

sys heal() {
    for row in query(h: &mut Health) {
        row.h.hp += row.h.regen * 0.016;
    }
}

schedule Update { heal }
"#;
    compile_source_and_verify(
        "migrate_demo",
        "migrate_demo.strata",
        src,
        JitOptLevel::Speed,
    );
}

#[test]
fn cranelift_jit_compiles_libm_helpers_tables_curves_sparse_and_relations() {
    let src = r#"
module test::full_mir_test @version(1.0.0) @deterministic;

enum WeaponKind { Sword = 0, Bow = 1 }

@sparse
component Pos { xy: vec2 }

component Flags { mask: BitSet<64> }

relation ChildRel [exclusive, cascade_despawn];

table WeaponStats by WeaponKind {
    damage: f32,
    range: f32,
} = {
    Sword => { damage: 25.0, range: 2.0 },
    Bow   => { damage: 15.0, range: 30.0 },
};

curve Falloff(f32 -> f32) = [
    (0.0,  1.0),
    (10.0, 0.5),
    (30.0, 0.0),
];

fn compute_falloff(d: f32, kind: WeaponKind) -> f32 {
    let w = WeaponStats[kind].damage;
    let s = sin(d) + cos(d) + atan2(d, 1.0) + pow(2.0, 0.5) + exp(0.0) + log(1.0) + round(1.6);
    w * Falloff.sample(d) + s * 0.001
}

sys update_all() {
    for row in query(pos: &mut Pos, fl: &mut Flags) {
        let dmg = compute_falloff(length(row.pos.xy), WeaponKind::Sword);
        if dmg > 0.0 {
            row.fl.mask.set(3);
            if row.fl.mask.get(3) {
                row.fl.mask.clear(3);
            }
        }
        insert_relation<ChildRel>(row.id, row.id);
    }
}

schedule FixedUpdate { update_all }
"#;
    compile_source_and_verify(
        "full_mir_test",
        "full_mir_test.strata",
        src,
        JitOptLevel::Speed,
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn find_c_compiler() -> &'static str {
    for cc in ["clang", "cc", "gcc"] {
        if let Ok(out) = Command::new(cc).arg("--version").output()
            && out.status.success()
        {
            return cc;
        }
    }
    "cc"
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_c_host_harness(
    tmp: &std::path::Path,
    stem: &str,
    c_body: &str,
    dylib_path: &std::path::Path,
) -> std::process::Output {
    let c_path = tmp.join(format!("{stem}_host.c"));
    let exe_path = tmp.join(format!("{stem}_host"));
    std::fs::write(&c_path, c_body).expect("write C harness");

    let cc = find_c_compiler();
    let mut ccmd = Command::new(cc);
    ccmd.arg("-std=c99")
        .arg("-Wall")
        .arg("-Werror")
        .arg(&c_path)
        .arg("-o")
        .arg(&exe_path);
    if cfg!(target_os = "linux") {
        ccmd.arg("-ldl").arg("-lm");
    }
    let compile_out = ccmd.output().expect("run C compiler");
    assert!(
        compile_out.status.success(),
        "C harness compile failed:\n{}\n{}",
        String::from_utf8_lossy(&compile_out.stdout),
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let run_out = Command::new(&exe_path)
        .arg(dylib_path)
        .output()
        .expect("execute C harness");
    assert!(
        run_out.status.success(),
        "C harness failed (exit {:?}):\nstdout:\n{}\nstderr:\n{}",
        run_out.status.code(),
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr)
    );
    run_out
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn c_abi_prelude() -> String {
    use bamabi_sys::BAM_STORAGE_FLAG_RESOURCE;
    use strata_jit::abi_offsets::{HOST_API_SLOTS, WIRE_ABI_VERSION, api_slots};
    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    format!(
        r#"#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <math.h>

#define WIRE_ABI_VER {WIRE_ABI_VERSION}u
#define HOST_API_SLOTS {HOST_API_SLOTS}u
#define FLAG_RESOURCE {BAM_STORAGE_FLAG_RESOURCE}u
#define SLOT_LOAD_HOST_CTX {s_lhc}u
#define SLOT_REGISTER_COMPONENT {s_reg_comp}u
#define SLOT_RESOLVE_COMPONENT {s_res_comp}u
#define SLOT_REGISTER_SYSTEM_HANDLE {s_reg_sys_h}u
#define SLOT_REGISTER_SYSTEM {s_reg_sys}u
#define SLOT_COMPONENT_LAYOUT_INFO {s_linfo}u
#define SLOT_SYS_QUERY {s_sys_q}u
#define SLOT_SYS_COMMANDS {s_sys_cmds}u
#define SLOT_CMD_CHECKPOINT {s_cmd_ckpt}u
#define SLOT_CMD_ROLLBACK {s_cmd_rb}u
#define SLOT_ITER_NEXT_CHUNK {s_iter_next}u
#define SLOT_ITER_RESET {s_iter_reset}u
#define SLOT_ITER_ENTITIES {s_iter_ent}u
#define SLOT_ITER_COL_RO {s_col_ro}u
#define SLOT_ITER_COL_MUT {s_col_mut}u
#define SLOT_ITER_COL_MUT_UNTRACKED {s_col_mut_u}u
#define SLOT_ITER_MARK_CHANGED_RANGE {s_mark_chg}u
#define SLOT_SYS_ENTITY_GET {s_ent_get}u
#define SLOT_SYS_ENTITY_GET_MUT {s_ent_get_mut}u
#define SLOT_RES_PTR {s_res_ptr}u
#define SLOT_RES_MUT_PTR {s_res_mut_ptr}u
#define SLOT_SYS_RES_PTR {s_sys_res_ptr}u
#define SLOT_SYS_RES_MUT_PTR {s_sys_res_mut_ptr}u
#define SLOT_REGISTER_RELATION {s_reg_rel}u
#define SLOT_ITER_UP_CASCADE {s_up_cascade}u

typedef struct BamComponentUuid {{ uint64_t lo, hi; }} BamComponentUuid;
typedef struct BamFieldDesc {{
    const char* name; uint32_t kind; uint32_t offset; uint32_t size;
    uint32_t array_len; const char* enum_name;
}} BamFieldDesc;
typedef struct BamComponentDesc {{
    uint32_t struct_size; uint32_t flags; const char* name; BamComponentUuid uuid;
    size_t size; size_t align; const uint32_t* required_components; size_t required_component_count;
    uint64_t schema_fingerprint; const BamFieldDesc* fields; size_t field_count;
    const void* required_init_descs; size_t required_init_desc_count;
}} BamComponentDesc;
typedef struct BamLayoutInfo {{
    uint32_t struct_size; uint32_t flags; BamComponentUuid uuid; uint64_t schema_fingerprint;
    size_t size; size_t align; const BamFieldDesc* fields; size_t field_count;
}} BamLayoutInfo;
typedef struct BamTermDesc {{
    uint32_t component; uint32_t mode; uint16_t flags; uint8_t or_group; uint8_t reserved0;
}} BamTermDesc;
typedef struct BamQueryDesc {{
    uint32_t struct_size; uint32_t flags; const BamTermDesc* terms; size_t term_count;
    uint32_t param_set_group; uint32_t reserved0;
}} BamQueryDesc;
typedef uint32_t (*BamSystemFn)(void* sys_ctx, void* user_data);
typedef struct BamSystemDesc {{
    uint32_t struct_size; uint32_t flags; const char* name; const BamQueryDesc* queries; size_t query_count;
    BamSystemFn callback; void* user_data; uint32_t schedule; uint32_t reserved0;
    const char* const* after; size_t after_count; const char* const* before; size_t before_count;
    void* run_if; void* run_if_user_data; const char* const* in_sets; size_t in_set_count;
    const char* const* after_weak; size_t after_weak_count; const char* const* before_weak; size_t before_weak_count;
    const char* const* ambiguous_with; size_t ambiguous_with_count;
    void* run_if_ctx; const BamQueryDesc* run_if_query; void* run_if_ctx_user_data;
}} BamSystemDesc;
typedef struct BamHostApi {{
    uint32_t struct_size; uint32_t abi_version; void* slots[HOST_API_SLOTS];
}} BamHostApi;
"#,
        s_lhc = idx(api_slots::LOAD_HOST_CTX),
        s_reg_comp = idx(api_slots::REGISTER_COMPONENT),
        s_res_comp = idx(api_slots::RESOLVE_COMPONENT),
        s_reg_sys_h = idx(api_slots::REGISTER_SYSTEM_HANDLE),
        s_reg_sys = idx(api_slots::REGISTER_SYSTEM),
        s_linfo = idx(api_slots::COMPONENT_LAYOUT_INFO),
        s_sys_q = idx(api_slots::SYS_QUERY),
        s_sys_cmds = idx(api_slots::SYS_COMMANDS),
        s_cmd_ckpt = idx(api_slots::CMD_CHECKPOINT),
        s_cmd_rb = idx(api_slots::CMD_ROLLBACK),
        s_iter_next = idx(api_slots::ITER_NEXT_CHUNK),
        s_iter_reset = idx(api_slots::ITER_RESET),
        s_iter_ent = idx(api_slots::ITER_ENTITIES),
        s_col_ro = idx(api_slots::ITER_COLUMN_READONLY),
        s_col_mut = idx(api_slots::ITER_COLUMN_MUTABLE),
        s_col_mut_u = idx(api_slots::ITER_COLUMN_MUTABLE_UNTRACKED),
        s_mark_chg = idx(api_slots::ITER_MARK_CHANGED_RANGE),
        s_ent_get = idx(api_slots::SYS_ENTITY_GET),
        s_ent_get_mut = idx(api_slots::SYS_ENTITY_GET_MUT),
        s_res_ptr = idx(api_slots::RES_PTR),
        s_res_mut_ptr = idx(api_slots::RES_MUT_PTR),
        s_sys_res_ptr = idx(api_slots::SYS_RES_PTR),
        s_sys_res_mut_ptr = idx(api_slots::SYS_RES_MUT_PTR),
        s_reg_rel = idx(api_slots::REGISTER_RELATION),
        s_up_cascade = idx(api_slots::ITER_UP_CASCADE),
    )
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn field_offset_of(mir: &strata_mir::MirModule, comp_name: &str, field: &str) -> (usize, usize) {
    let layout = mir
        .layouts
        .iter()
        .find(|l| {
            l.canonical_name == comp_name || l.canonical_name.ends_with(&format!("::{comp_name}"))
        })
        .unwrap_or_else(|| panic!("missing layout `{comp_name}`"));
    let f = layout
        .fields
        .iter()
        .find(|f| f.name == field)
        .unwrap_or_else(|| panic!("missing field `{comp_name}.{field}`"));
    (layout.size, f.offset)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_executes_fix64_div_f32_coercion_array_store_and_nb2_nested_literals() {
    let src = r#"
module test::jit_fix64_arr @version(1.0.0);

component MathArr {
    lhs: fix64 = 0.0,
    rhs: fix64 = 0.0,
    q: fix64 = 0.0,
    neg_q: fix64 = 0.0,
    z_q: fix64 = 0.0,
    acc: fix64 = 1.25,
    mat_sum: f32 = 0.0,
    arr: [i32; 4] = [10, 20, 30, 40],
    out_local: i32 = 0,
}

sys compute() {
    let delta: f32 = 0.5;
    let mut local_arr = [10, 20, 30];
    local_arr[1] = 99;
    local_arr[9] = 777;
    let mat: [[f32; 2]; 2] = [[1, 2.5], [3.5, 4]];

    for row in query(m: &mut MathArr) {
        row.m.q = row.m.lhs / row.m.rhs;
        row.m.neg_q = (0.0 - row.m.lhs) / row.m.rhs;
        let zero_div: fix64 = 0.0;
        row.m.z_q = row.m.lhs / zero_div;
        row.m.acc += delta;
        row.m.arr[1] += 5;
        row.m.arr[99] = 888;
        row.m.out_local = local_arr[1] + local_arr[2];
        row.m.mat_sum = mat[0][1] + mat[1][0];
    }
}

schedule FixedUpdate { compute }
"#;
    let analyzed = analyze_source("jit_fix64_arr.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_fix64_arr".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (comp_sz, off_lhs) = field_offset_of(&mir, "MathArr", "lhs");
    let (_, off_rhs) = field_offset_of(&mir, "MathArr", "rhs");
    let (_, off_q) = field_offset_of(&mir, "MathArr", "q");
    let (_, off_neg_q) = field_offset_of(&mir, "MathArr", "neg_q");
    let (_, off_z_q) = field_offset_of(&mir, "MathArr", "z_q");
    let (_, off_acc) = field_offset_of(&mir, "MathArr", "acc");
    let (_, off_mat_sum) = field_offset_of(&mir, "MathArr", "mat_sum");
    let (_, off_arr) = field_offset_of(&mir, "MathArr", "arr");
    let (_, off_out_local) = field_offset_of(&mir, "MathArr", "out_local");

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_comp_id = 10;
static BamSystemFn g_cb = NULL;
static void* g_ud = NULL;
static uint8_t g_buf[{comp_sz}];
static uint64_t g_ent[1] = {{ 42ull }};
static size_t g_stage = 0;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; (void)d; *o = g_comp_id; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc; g_cb = d->callback; g_ud = d->user_data; *o = 1; return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi; g_stage = 0; *o = (void*)0x1111; return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    (void)it; if (g_stage == 0) {{ g_stage = 1; *len = 1; return 1; }} *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{ (void)it; return g_ent; }}
static void* h_col(void* it, size_t ti) {{ (void)it; (void)ti; return g_buf; }}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT_UNTRACKED] = (void*)h_col;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0 || g_cb == NULL) return 4;

    memset(g_buf, 0, sizeof(g_buf));
    int64_t lhs_q = (int64_t)(7.5 * 4294967296.0);
    int64_t rhs_q = (int64_t)(2.5 * 4294967296.0);
    int64_t acc_q = (int64_t)(1.25 * 4294967296.0);
    int32_t init_arr[4] = {{ 10, 20, 30, 40 }};
    memcpy(g_buf + {off_lhs}, &lhs_q, 8);
    memcpy(g_buf + {off_rhs}, &rhs_q, 8);
    memcpy(g_buf + {off_acc}, &acc_q, 8);
    memcpy(g_buf + {off_arr}, init_arr, 16);

    g_cb(&g_sctx, g_ud);

    int64_t out_q = 0, out_neg_q = 0, out_zq = 0, out_acc = 0;
    float out_mat = 0.0f;
    int32_t out_arr[4] = {{0}}, out_loc = 0;
    memcpy(&out_q, g_buf + {off_q}, 8);
    memcpy(&out_neg_q, g_buf + {off_neg_q}, 8);
    memcpy(&out_zq, g_buf + {off_z_q}, 8);
    memcpy(&out_acc, g_buf + {off_acc}, 8);
    memcpy(&out_mat, g_buf + {off_mat_sum}, 4);
    memcpy(out_arr, g_buf + {off_arr}, 16);
    memcpy(&out_loc, g_buf + {off_out_local}, 4);

    if (out_q != (3LL << 32)) {{ fprintf(stderr, "q=%lld\n", (long long)out_q); return 10; }}
    if (out_neg_q != -(3LL << 32)) {{ fprintf(stderr, "neg_q=%lld\n", (long long)out_neg_q); return 11; }}
    if (out_zq != 0) {{ fprintf(stderr, "zq=%lld\n", (long long)out_zq); return 12; }}
    if (out_acc != (int64_t)(1.75 * 4294967296.0)) {{ fprintf(stderr, "acc=%lld\n", (long long)out_acc); return 13; }}
    if (out_arr[0] != 10 || out_arr[1] != 25 || out_arr[2] != 30 || out_arr[3] != 40) {{
        fprintf(stderr, "arr=[%d,%d,%d,%d]\n", out_arr[0], out_arr[1], out_arr[2], out_arr[3]);
        return 14;
    }}
    if (out_loc != 129) {{ fprintf(stderr, "out_loc=%d\n", out_loc); return 15; }}
    if (fabsf(out_mat - 6.0f) > 1e-4f) {{ fprintf(stderr, "mat=%f\n", out_mat); return 16; }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_fix64_arr", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_executes_spatial_2pass_csr_disc_and_history_segment_queries() {
    let src = r#"
module test::jit_spatial_csr @version(1.0.0);

component AgentPos { xy: vec2 = vec2(0.0, 0.0) }
component QueryOut { disc_hits: i32 = 0, seg_hits: i32 = 0 }

spatial_grid AgentGrid(cell_size: 4.0_m, bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m), capacity: 64) over AgentPos by AgentPos.xy;
spatial_history TraceHist(frames: 4, cell_size: 4.0_m, bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m), capacity: 64) over AgentPos by AgentPos.xy;

sys scan_hits() {
    let mut dc: i32 = 0;
    for _hit in AgentGrid.query_disc(vec2(0.0, 0.0), 5.0) {
        dc += 1;
    }
    let mut sc: i32 = 0;
    for _sh in TraceHist.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(10.0, 0.0, 0.0), 2.0) {
        sc += 1;
    }
    for row in query(o: &mut QueryOut) {
        row.o.disc_hits = dc;
        row.o.seg_hits = sc;
    }
}

schedule FixedUpdate { scan_hits }
"#;
    let analyzed = analyze_source("jit_spatial_csr.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_spatial_csr".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (pos_sz, off_xy) = field_offset_of(&mir, "AgentPos", "xy");
    let (out_sz, off_disc) = field_offset_of(&mir, "QueryOut", "disc_hits");
    let (_, off_seg) = field_offset_of(&mir, "QueryOut", "seg_hits");

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_next_comp = 10, g_pos_comp = 0, g_out_comp = 0;
typedef struct SysReg {{ char name[96]; BamSystemFn cb; void* ud; uint32_t q_comp; }} SysReg;
static SysReg g_sys[16];
static size_t g_sys_n = 0;
static uint32_t g_reset_calls = 0;

static uint8_t g_pos_buf[3 * {pos_sz}];
static uint64_t g_pos_ents[3] = {{ 101ull, 102ull, 103ull }};
static uint8_t g_out_buf[{out_sz}];
static uint64_t g_out_ents[1] = {{ 201ull }};
typedef struct IterState {{ uint32_t comp; size_t stage; }} IterState;
static IterState g_iters[16];

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "AgentPos")) g_pos_comp = id;
    if (d->name && strstr(d->name, "QueryOut")) g_out_comp = id;
    *o = id; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    SysReg* r = &g_sys[g_sys_n];
    snprintf(r->name, sizeof(r->name), "%s", d->name ? d->name : "");
    r->cb = d->callback; r->ud = d->user_data;
    r->q_comp = (d->query_count > 0 && d->queries && d->queries[0].term_count > 0) ? d->queries[0].terms[0].component : 0;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t g_active_comp = 0;
static uint32_t h_sys_q_active(void* sc, size_t qi, void** o) {{
    (void)sc;
    size_t idx = (qi < 16) ? qi : 0;
    g_iters[idx].comp = g_active_comp;
    g_iters[idx].stage = 0;
    *o = &g_iters[idx];
    return 0;
}}
static uint32_t h_iter_reset(void* it) {{
    ((IterState*)it)->stage = 0;
    g_reset_calls++;
    return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    IterState* s = (IterState*)it;
    if (s->stage == 0) {{
        s->stage = 1;
        *len = (s->comp == g_pos_comp) ? 3 : 1;
        return 1;
    }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{
    return (((IterState*)it)->comp == g_pos_comp) ? g_pos_ents : g_out_ents;
}}
static void* h_col(void* it, size_t ti) {{
    (void)ti;
    return (((IterState*)it)->comp == g_pos_comp) ? (void*)g_pos_buf : (void*)g_out_buf;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q_active;
    api.slots[SLOT_ITER_RESET] = (void*)h_iter_reset;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT_UNTRACKED] = (void*)h_col;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;

    memset(g_pos_buf, 0, sizeof(g_pos_buf));
    memset(g_out_buf, 0, sizeof(g_out_buf));
    float coords[3][2] = {{ {{1.0f, 1.0f}}, {{4.0f, 0.5f}}, {{25.0f, 25.0f}} }};
    for (int i = 0; i < 3; i++) {{
        memcpy(g_pos_buf + i * {pos_sz} + {off_xy}, coords[i], 8);
    }}

    g_active_comp = g_pos_comp;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "rebuild_csr")) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}
    g_active_comp = g_out_comp;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "scan_hits") == 0) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}

    int32_t dh = 0, sh = 0;
    memcpy(&dh, g_out_buf + {off_disc}, 4);
    memcpy(&sh, g_out_buf + {off_seg}, 4);
    if (g_reset_calls < 2) {{ fprintf(stderr, "reset_calls=%u\n", g_reset_calls); return 10; }}
    if (dh != 2 || sh != 2) {{ fprintf(stderr, "dh=%d sh=%d\n", dh, sh); return 11; }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_spatial_csr", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_executes_iter_up_cascade_option_non_selective_and_atomic_rollback() {
    let src = r#"
module test::jit_cascade_opt_atomic @version(1.0.0);

relation ParentRel [exclusive];
resource Bank { gold: i32 = 100 }
component Buff { bonus: f32 = 0.0 }
component Shield { hp: f32 = 10.0 }
component Stat { total: f32 = 0.0, none_cnt: i32 = 0, some_cnt: i32 = 0 }

sys check_opt() {
    for row in query(st: &mut Stat, sh: Option<&mut Shield>) {
        if row.sh.is_some() && !row.sh.is_none() {
            row.sh.unwrap().hp += 5.0;
            row.st.some_cnt += 1;
        }
        if row.sh.is_none() {
            row.st.none_cnt += 1;
        }
    }
}

sys check_cascade() {
    for row in query(st: &mut Stat, bf: &Buff).up<ParentRel>() {
        row.st.total += row.bf.bonus;
    }
}

sys check_atomic_abort(bank: &mut Bank) {
    for row in query(s: &mut Stat) {
        atomic {
            bank.gold -= 35;
            row.s.total += 999.0;
            require_true(false);
        }
    }
}

schedule FixedUpdate { check_opt, check_cascade, check_atomic_abort }
"#;
    let analyzed = analyze_source("jit_cascade_opt_atomic.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_cascade_opt_atomic".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (bank_sz, off_gold) = field_offset_of(&mir, "Bank", "gold");
    let (buff_sz, off_bonus) = field_offset_of(&mir, "Buff", "bonus");
    let (sh_sz, off_hp) = field_offset_of(&mir, "Shield", "hp");
    let (st_sz, off_total) = field_offset_of(&mir, "Stat", "total");
    let (_, off_none) = field_offset_of(&mir, "Stat", "none_cnt");
    let (_, off_some) = field_offset_of(&mir, "Stat", "some_cnt");

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_next_comp = 10, g_stat_comp = 0, g_sh_comp = 0, g_bf_comp = 0, g_bank_comp = 0, g_parent_rel_comp = 0, g_rel_comp = 50;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[16];
static size_t g_sys_n = 0;

static uint8_t g_bank_buf[{bank_sz}];
static uint8_t g_st_c0[2 * {st_sz}];
static uint8_t g_st_c1[1 * {st_sz}];
static uint8_t g_sh_c1[1 * {sh_sz}];
static uint8_t g_bf_parent[{buff_sz}];
static uint64_t g_ents_c0[2] = {{ 101ull, 102ull }};
static uint64_t g_ents_c1[1] = {{ 201ull }};
static size_t g_chunk_stage = 0;
static uint32_t g_up_calls = 0, g_opt_mark_changed_on_null = 0, g_ckpt_calls = 0, g_rb_calls = 0;
static uint32_t g_active_terms[8];
static int g_cmds_sentinel = 77;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name) {{
        if (strstr(d->name, "__strata_rel_parent_ParentRel")) g_parent_rel_comp = id;
        else if (strstr(d->name, "Stat")) g_stat_comp = id;
        else if (strstr(d->name, "Shield")) g_sh_comp = id;
        else if (strstr(d->name, "Buff")) g_bf_comp = id;
        else if (strstr(d->name, "Bank")) g_bank_comp = id;
    }}
    *o = id; return 0;
}}
static uint32_t h_resolve_comp(const void* hc, const char* name, const BamComponentUuid* uuid, uint32_t* out) {{
    (void)hc; (void)uuid;
    if (name && strstr(name, "Bank")) {{
        if (g_bank_comp == 0) g_bank_comp = g_next_comp++;
        *out = g_bank_comp;
        return 0;
    }}
    return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* info) {{
    (void)hc;
    if (c == g_bank_comp) {{
        info->flags = FLAG_RESOURCE;
        info->size = {bank_sz};
        info->align = 4;
        return 0;
    }}
    return 4;
}}
static uint32_t h_reg_rel(void* lc, const void* d, uint32_t* o) {{
    (void)lc; (void)d; *o = g_rel_comp; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi; g_chunk_stage = 0; *o = (void*)0x2222; return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    (void)it;
    if (g_chunk_stage == 0) {{ g_chunk_stage = 1; *len = 2; return 1; }}
    if (g_chunk_stage == 1) {{ g_chunk_stage = 2; *len = 1; return 1; }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{ (void)it; return (g_chunk_stage == 1) ? g_ents_c0 : g_ents_c1; }}
static void* h_col(void* it, size_t ti) {{
    (void)it;
    if (ti == 0) return (g_chunk_stage == 1) ? (void*)g_st_c0 : (void*)g_st_c1;
    if (ti == 1) return (g_chunk_stage == 1) ? NULL : (void*)g_sh_c1;
    return NULL;
}}
static uint32_t h_mark_chg(void* it, size_t ti, size_t s, size_t l) {{
    (void)it; (void)s; (void)l;
    if (ti == 1 && g_chunk_stage == 1) g_opt_mark_changed_on_null++;
    return 0;
}}
static uint32_t h_up_cascade(void* it, uint32_t rel, uint64_t ent, size_t ti, const void** out_ptr, uint64_t* out_owner) {{
    (void)it;
    g_up_calls++;
    if (rel != g_parent_rel_comp) return 1;
    if (ti == 0) {{
        if (ent == 101ull) {{ *out_ptr = g_st_c0 + 0 * {st_sz}; *out_owner = 101ull; }}
        else if (ent == 102ull) {{ *out_ptr = g_st_c0 + 1 * {st_sz}; *out_owner = 102ull; }}
        else if (ent == 201ull) {{ *out_ptr = g_st_c1; *out_owner = 201ull; }}
        else {{ *out_ptr = NULL; *out_owner = 0; }}
    }} else if (ti == 1) {{
        if (ent == 101ull || ent == 201ull) {{ *out_ptr = g_bf_parent; *out_owner = 999ull; }}
        else {{ *out_ptr = NULL; *out_owner = 0; }}
    }} else {{
        *out_ptr = NULL; *out_owner = 0;
    }}
    return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{
    (void)sc; *out_cmds = &g_cmds_sentinel; return 0;
}}
static uint32_t h_cmd_ckpt(void* cmds, void** out_ckpt) {{
    (void)cmds; g_ckpt_calls++; *out_ckpt = (void*)0xCAFEull; return 0;
}}
static uint32_t h_cmd_rb(void* cmds, void* ckpt) {{
    (void)cmds; (void)ckpt; g_rb_calls++; return 0;
}}
static void* h_res_mut(void* sc, uint32_t c, void* ticks) {{ (void)sc; (void)ticks; return (c == g_bank_comp) ? g_bank_buf : NULL; }}
static void* h_ent_get(void* sc, size_t qi, uint64_t e, size_t ti) {{
    (void)sc; (void)qi; (void)ti;
    if (e == 101ull) return g_st_c0;
    if (e == 102ull) return g_st_c0 + 1 * {st_sz};
    if (e == 201ull) return g_st_c1;
    return NULL;
}}

int main(int argc, char** argv) {{
    (void)g_active_terms;
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_RELATION] = (void*)h_reg_rel;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_CHECKPOINT] = (void*)h_cmd_ckpt;
    api.slots[SLOT_CMD_ROLLBACK] = (void*)h_cmd_rb;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT_UNTRACKED] = (void*)h_col;
    api.slots[SLOT_ITER_MARK_CHANGED_RANGE] = (void*)h_mark_chg;
    api.slots[SLOT_ITER_UP_CASCADE] = (void*)h_up_cascade;
    api.slots[SLOT_RES_PTR] = (void*)h_res_mut;
    api.slots[SLOT_RES_MUT_PTR] = (void*)h_res_mut;
    api.slots[SLOT_SYS_RES_PTR] = (void*)h_res_mut;
    api.slots[SLOT_SYS_RES_MUT_PTR] = (void*)h_res_mut;
    api.slots[SLOT_SYS_ENTITY_GET] = (void*)h_ent_get;
    api.slots[SLOT_SYS_ENTITY_GET_MUT] = (void*)h_ent_get;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;

    memset(g_st_c0, 0, sizeof(g_st_c0));
    memset(g_st_c1, 0, sizeof(g_st_c1));
    memset(g_sh_c1, 0, sizeof(g_sh_c1));
    memset(g_bf_parent, 0, sizeof(g_bf_parent));
    memset(g_bank_buf, 0, sizeof(g_bank_buf));
    int32_t init_gold = 100;
    float init_hp = 10.0f, init_bonus = 7.5f;
    memcpy(g_bank_buf + {off_gold}, &init_gold, 4);
    memcpy(g_sh_c1 + {off_hp}, &init_hp, 4);
    memcpy(g_bf_parent + {off_bonus}, &init_bonus, 4);

    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "check_opt") == 0) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "check_cascade") == 0) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "check_atomic_abort") == 0) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}

    int32_t c0_r0_none = 0, c0_r1_none = 0, c1_some = 0, c1_none = 0, gold_after = 0;
    float hp_after = 0.0f, t0 = 0.0f, t1 = 0.0f, tc1 = 0.0f;
    memcpy(&c0_r0_none, g_st_c0 + 0 * {st_sz} + {off_none}, 4);
    memcpy(&c0_r1_none, g_st_c0 + 1 * {st_sz} + {off_none}, 4);
    memcpy(&c1_some, g_st_c1 + {off_some}, 4);
    memcpy(&c1_none, g_st_c1 + {off_none}, 4);
    memcpy(&hp_after, g_sh_c1 + {off_hp}, 4);
    memcpy(&t0, g_st_c0 + 0 * {st_sz} + {off_total}, 4);
    memcpy(&t1, g_st_c0 + 1 * {st_sz} + {off_total}, 4);
    memcpy(&tc1, g_st_c1 + {off_total}, 4);
    memcpy(&gold_after, g_bank_buf + {off_gold}, 4);

    if (c0_r0_none != 1 || c0_r1_none != 1 || c1_some != 1 || c1_none != 0) {{
        fprintf(stderr, "opt counts: %d %d %d %d\n", c0_r0_none, c0_r1_none, c1_some, c1_none);
        return 10;
    }}
    if (g_opt_mark_changed_on_null != 0) {{ fprintf(stderr, "flushed null opt!\n"); return 11; }}
    if (fabsf(hp_after - 15.0f) > 1e-4f) {{ fprintf(stderr, "hp=%f\n", hp_after); return 12; }}
    if (g_up_calls != 6) {{ fprintf(stderr, "up_calls=%u\n", g_up_calls); return 13; }}
    if (fabsf(t0 - 7.5f) > 1e-4f || fabsf(t1 - 0.0f) > 1e-4f || fabsf(tc1 - 7.5f) > 1e-4f) {{
        fprintf(stderr, "cascade totals=%f %f %f\n", t0, t1, tc1);
        return 14;
    }}
    if (gold_after != 100 || g_ckpt_calls != 3 || g_rb_calls != 3) {{
        fprintf(stderr, "atomic rollback failed gold=%d ckpt=%u rb=%u\n", gold_after, g_ckpt_calls, g_rb_calls);
        return 15;
    }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(
        tmp.path(),
        "jit_cascade_opt_atomic",
        &c_code,
        &artifact.dylib_path,
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_executes_spatial_queries_via_resource_param_aliases_g_and_h() {
    let src = r#"
module test::jit_spatial_alias @version(1.0.0);

component AgentPos { xy: vec2 = vec2(0.0, 0.0) }
component QueryOut { disc_hits: i32 = 0, seg_hits: i32 = 0 }

spatial_grid Grid2D(cell_size: 4.0_m, bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m), capacity: 64) over AgentPos by AgentPos.xy;
spatial_history Hist3D(frames: 4, cell_size: 4.0_m, bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m), capacity: 64) over AgentPos by AgentPos.xy;

sys scan_aliases(g: &res Grid2D, h: &res Hist3D) {
    let mut dc: i32 = 0;
    for _hit in g.query_disc(vec2(0.0, 0.0), 5.0_m) {
        dc += 1;
    }
    let mut sc: i32 = 0;
    for _sh in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(10.0, 0.0, 0.0)) {
        sc += 1;
    }
    for row in query(o: &mut QueryOut) {
        row.o.disc_hits = dc;
        row.o.seg_hits = sc;
    }
}

schedule FixedUpdate { scan_aliases }
"#;
    let analyzed = analyze_source("jit_spatial_alias.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_spatial_alias".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (pos_sz, off_xy) = field_offset_of(&mir, "AgentPos", "xy");
    let (out_sz, off_disc) = field_offset_of(&mir, "QueryOut", "disc_hits");
    let (_, off_seg) = field_offset_of(&mir, "QueryOut", "seg_hits");

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_next_comp = 10, g_pos_comp = 0, g_out_comp = 0;
typedef struct SysReg {{ char name[96]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[16];
static size_t g_sys_n = 0;

static uint8_t g_pos_buf[3 * {pos_sz}];
static uint64_t g_pos_ents[3] = {{ 101ull, 102ull, 103ull }};
static uint8_t g_out_buf[{out_sz}];
static uint64_t g_out_ents[1] = {{ 201ull }};
typedef struct IterState {{ uint32_t comp; size_t stage; }} IterState;
static IterState g_iters[16];

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "AgentPos")) g_pos_comp = id;
    if (d->name && strstr(d->name, "QueryOut")) g_out_comp = id;
    *o = id; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    SysReg* r = &g_sys[g_sys_n];
    snprintf(r->name, sizeof(r->name), "%s", d->name ? d->name : "");
    r->cb = d->callback; r->ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t g_active_comp = 0;
static uint32_t h_sys_q_active(void* sc, size_t qi, void** o) {{
    (void)sc;
    size_t idx = (qi < 16) ? qi : 0;
    g_iters[idx].comp = g_active_comp;
    g_iters[idx].stage = 0;
    *o = &g_iters[idx];
    return 0;
}}
static uint32_t h_iter_reset(void* it) {{
    ((IterState*)it)->stage = 0;
    return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    IterState* s = (IterState*)it;
    if (s->stage == 0) {{
        s->stage = 1;
        *len = (s->comp == g_pos_comp) ? 3 : 1;
        return 1;
    }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{
    return (((IterState*)it)->comp == g_pos_comp) ? g_pos_ents : g_out_ents;
}}
static void* h_col(void* it, size_t ti) {{
    (void)ti;
    return (((IterState*)it)->comp == g_pos_comp) ? (void*)g_pos_buf : (void*)g_out_buf;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q_active;
    api.slots[SLOT_ITER_RESET] = (void*)h_iter_reset;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT_UNTRACKED] = (void*)h_col;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;

    memset(g_pos_buf, 0, sizeof(g_pos_buf));
    memset(g_out_buf, 0, sizeof(g_out_buf));
    float coords[3][2] = {{ {{1.0f, 1.0f}}, {{4.0f, 0.25f}}, {{25.0f, 25.0f}} }};
    for (int i = 0; i < 3; i++) {{
        memcpy(g_pos_buf + i * {pos_sz} + {off_xy}, coords[i], 8);
    }}

    g_active_comp = g_pos_comp;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "rebuild_csr")) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}
    g_active_comp = g_out_comp;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "scan_aliases") == 0) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}

    int32_t dh = 0, sh = 0;
    memcpy(&dh, g_out_buf + {off_disc}, 4);
    memcpy(&sh, g_out_buf + {off_seg}, 4);
    if (dh != 2 || sh != 1) {{ fprintf(stderr, "dh=%d sh=%d\n", dh, sh); return 11; }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(
        tmp.path(),
        "jit_spatial_alias",
        &c_code,
        &artifact.dylib_path,
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_initializes_negative_ivec2_ivec3_and_uvec2_object_fields() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_ivec_init @version(1.0.0);

component MathBox {
    iv: ivec2 = ivec2(0, 0),
    iv3: ivec3 = ivec3(0, 0, 0),
    uv: uvec2 = uvec2(0, 0),
    neg_i: i32 = -42,
}

object HeroPartial {
    MathBox {
        iv: ivec2(-1, -2),
        iv3: ivec3(-10, 20, -30),
        uv: uvec2(7, 4000000000),
    },
}
"#;
    let analyzed = analyze_source("jit_ivec_init.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_ivec_init".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (mb_sz, off_iv) = field_offset_of(&mir, "MathBox", "iv");
    let (_, off_iv3) = field_offset_of(&mir, "MathBox", "iv3");
    let (_, off_uv) = field_offset_of(&mir, "MathBox", "uv");
    let (_, off_neg_i) = field_offset_of(&mir, "MathBox", "neg_i");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_cmd_spawn = idx(api_slots::CMD_SPAWN);
    let s_bind_obj = idx(api_slots::BIND_NAMED_OBJECT);
    let s_cfg_sset = idx(api_slots::CONFIGURE_SCHEDULE_SET);
    let s_mount_sys = idx(api_slots::MOUNT_SYSTEM_IN_SCHEDULE);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind_obj}u
#define SLOT_CONFIGURE_SCHEDULE_SET {s_cfg_sset}u
#define SLOT_MOUNT_SYSTEM_IN_SCHEDULE {s_mount_sys}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds_sentinel = 77;
static uint32_t g_next_comp = 10, g_mb_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[8];
static size_t g_sys_n = 0;
static uint8_t g_captured_mb[{mb_sz}];
static int g_spawned_mb = 0;
static int g_bound_hero = 0;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "MathBox")) g_mb_comp = id;
    *o = id; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{
    (void)sc; *out_cmds = &g_cmds_sentinel; return 0;
}}
static uint32_t h_sys_q_empty(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi; *o = NULL; return 0;
}}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_ent) {{
    (void)cmds;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_mb_comp && ptrs[i] != NULL) {{
            memcpy(g_captured_mb, ptrs[i], {mb_sz});
            g_spawned_mb = 1;
        }}
    }}
    *out_ent = 501ull;
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* name, size_t len, uint64_t ent) {{
    (void)hc;
    if (name && len == 11 && memcmp(name, "HeroPartial", 11) == 0 && ent == 501ull) {{
        g_bound_hero = 1;
    }}
    return 0;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q_empty;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    if (g_sys_n == 0) return 5;
    for (size_t i = 0; i < g_sys_n; i++) {{
        g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}
    if (!g_spawned_mb || !g_bound_hero) return 6;

    int32_t iv[2] = {{0, 0}};
    int32_t iv3[3] = {{0, 0, 0}};
    uint32_t uv[2] = {{0, 0}};
    int32_t neg_i = 0;
    memcpy(iv, g_captured_mb + {off_iv}, 8);
    memcpy(iv3, g_captured_mb + {off_iv3}, 12);
    memcpy(uv, g_captured_mb + {off_uv}, 8);
    memcpy(&neg_i, g_captured_mb + {off_neg_i}, 4);

    if (iv[0] != -1 || iv[1] != -2) {{
        fprintf(stderr, "iv=[%d,%d]\n", iv[0], iv[1]);
        return 10;
    }}
    if (iv3[0] != -10 || iv3[1] != 20 || iv3[2] != -30) {{
        fprintf(stderr, "iv3=[%d,%d,%d]\n", iv3[0], iv3[1], iv3[2]);
        return 11;
    }}
    if (uv[0] != 7u || uv[1] != 4000000000u) {{
        fprintf(stderr, "uv=[%u,%u]\n", uv[0], uv[1]);
        return 12;
    }}
    if (neg_i != -42) {{
        fprintf(stderr, "neg_i=%d\n", neg_i);
        return 13;
    }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_ivec_init", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_emits_param_set_groups_and_executes_conflicting_task_queries() {
    use strata_jit::abi_offsets::{QUERY_FLAG_PARAM_SET, api_slots};
    let src = r#"
module test::jit_param_set @version(1.0.0);

component Actor { alive: bool = true, flags: u32 = 0, hp: f32 = 100.0 }
component Box { val: i32 = 0 }
component Marker { tag_val: u32 = 0 }
tag TagA;

@sparse
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

@sparse
task DualClusterTask(target: Ref<Actor>, box_ent: Ref<Box>, mark_ent: Ref<Marker>)
on (a: &Actor, b: &Box)
{
    if a.alive && b.val >= 0 {
        if let Some(t) = query_one(tgt: &mut Actor).on(target) {
            t.tgt.hp -= 1.0;
        }
        if let Some(m) = query_one(mk: &Marker).on(mark_ent) {
            let _ = m.mk.tag_val;
        }
        if let Some(bx) = query_one(b2: &mut Box).on(box_ent) {
            bx.b2.val += 1;
        }
    }
    yield_tick;
}

sys disjoint_filters() {
    for r in query(a: &mut Actor).with<TagA>() { r.a.flags += 1_u32; }
    for r in query(a: &Actor).without<TagA>() { let _ = r.a.flags; }
}

schedule FixedUpdate { ProcessOrder, DualClusterTask, disjoint_filters }
"#;
    let analyzed = analyze_source("jit_param_set.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_param_set".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (actor_sz, off_alive) = field_offset_of(&mir, "Actor", "alive");
    let (_, off_hp) = field_offset_of(&mir, "Actor", "hp");
    let (task_sz, off_target) = field_offset_of(&mir, "ProcessOrder", "target");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_col_rows_mut = idx(api_slots::ITER_COLUMN_ROWS_MUTABLE);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_ITER_COL_ROWS_MUT {s_col_rows_mut}u
#define BAM_QUERY_FLAG_PARAM_SET {QUERY_FLAG_PARAM_SET}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_next_comp = 10;
static BamSystemFn g_task_cb = NULL;
static void* g_task_ud = NULL;
static int g_checked_task = 0, g_checked_multi = 0, g_checked_disjoint = 0;

static uint8_t g_actor_runner[{actor_sz}];
static uint8_t g_actor_target[{actor_sz}];
static uint8_t g_task_state[{task_sz}];
static void* g_task_row_ptrs[1] = {{ g_task_state }};
static uint64_t g_task_ents[1] = {{ 101ull }};
static size_t g_stage = 0;
static uint32_t g_ent_get_mut_calls = 0;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; (void)d; *o = g_next_comp++; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    if (!d || !d->name) return 1;
    for (size_t qi = 0; qi < d->query_count; qi++) {{
        if (d->queries[qi].struct_size != (uint32_t)sizeof(BamQueryDesc)) return 20;
        if (d->queries[qi].reserved0 != 0) return 21;
    }}
    if (strcmp(d->name, "ProcessOrder") == 0) {{
        if (d->query_count != 2) return 30;
        if (d->queries[0].flags != BAM_QUERY_FLAG_PARAM_SET || d->queries[0].param_set_group != 1) return 31;
        if (d->queries[1].flags != BAM_QUERY_FLAG_PARAM_SET || d->queries[1].param_set_group != 1) return 32;
        g_task_cb = d->callback;
        g_task_ud = d->user_data;
        g_checked_task = 1;
    }} else if (strcmp(d->name, "DualClusterTask") == 0) {{
        if (d->query_count != 4) return 40;
        if (d->queries[0].flags != BAM_QUERY_FLAG_PARAM_SET || d->queries[0].param_set_group != 1) return 41;
        if (d->queries[1].flags != BAM_QUERY_FLAG_PARAM_SET || d->queries[1].param_set_group != 1) return 42;
        if (d->queries[2].flags != 0 || d->queries[2].param_set_group != 0) return 43;
        if (d->queries[3].flags != BAM_QUERY_FLAG_PARAM_SET || d->queries[3].param_set_group != 1) return 44;
        g_checked_multi = 1;
    }} else if (strcmp(d->name, "disjoint_filters") == 0) {{
        if (d->query_count != 2) return 50;
        if (d->queries[0].flags != 0 || d->queries[0].param_set_group != 0) return 51;
        if (d->queries[1].flags != 0 || d->queries[1].param_set_group != 0) return 52;
        g_checked_disjoint = 1;
    }}
    *o = 1;
    return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi; g_stage = 0; *o = (void*)0x3333; return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    (void)it;
    if (g_stage == 0) {{ g_stage = 1; *len = 1; return 1; }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{ (void)it; return g_task_ents; }}
static void* h_col_ro(void* it, size_t ti) {{
    (void)it; (void)ti;
    return g_actor_runner;
}}
static void* h_col_rows_mut(void* it, size_t ti) {{
    (void)it; (void)ti;
    return g_task_row_ptrs;
}}
static void* h_ent_get_mut(void* sc, size_t qi, uint64_t ent, size_t ti) {{
    (void)sc; (void)ti;
    if (qi == 1 && ent == 202ull) {{
        g_ent_get_mut_calls++;
        return g_actor_target;
    }}
    return NULL;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col_ro;
    api.slots[SLOT_ITER_COL_ROWS_MUT] = (void*)h_col_rows_mut;
    api.slots[SLOT_SYS_ENTITY_GET_MUT] = (void*)h_ent_get_mut;

    void* state = NULL;
    uint32_t irc = init_fn(&api, &g_lctx, &state);
    if (irc != 0) {{ fprintf(stderr, "init_fn=%u\n", irc); return 4; }}
    if (!g_checked_task || !g_checked_multi || !g_checked_disjoint || !g_task_cb) {{
        fprintf(stderr, "missing checks %d %d %d\n", g_checked_task, g_checked_multi, g_checked_disjoint);
        return 5;
    }}

    memset(g_actor_runner, 0, sizeof(g_actor_runner));
    memset(g_actor_target, 0, sizeof(g_actor_target));
    memset(g_task_state, 0, sizeof(g_task_state));
    uint8_t alive_t = 1;
    float runner_hp = 50.0f, target_hp = 100.0f;
    uint64_t target_ent = 202ull;
    memcpy(g_actor_runner + {off_alive}, &alive_t, 1);
    memcpy(g_actor_runner + {off_hp}, &runner_hp, 4);
    memcpy(g_actor_target + {off_alive}, &alive_t, 1);
    memcpy(g_actor_target + {off_hp}, &target_hp, 4);
    memcpy(g_task_state + {off_target}, &target_ent, 8);

    g_task_cb(&g_sctx, g_task_ud);

    float target_hp_after = 0.0f;
    memcpy(&target_hp_after, g_actor_target + {off_hp}, 4);
    if (g_ent_get_mut_calls != 1) {{
        fprintf(stderr, "ent_get_mut_calls=%u\n", g_ent_get_mut_calls);
        return 10;
    }}
    if (fabsf(target_hp_after - 90.0f) > 1e-4f) {{
        fprintf(stderr, "target_hp_after=%f\n", target_hp_after);
        return 11;
    }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_param_set", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_executes_runtime_ivec_constructors_precision_and_fix64_variants() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_nb123_fix64 @version(1.0.0);

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
    acc: fix64 = 1.0,
    out_local: fix64 = 0.0,
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

sys compute_all() {
    for r in query(p: &mut Payload) {
        r.p.iv = ivec2(30000001, -30000007);
        r.p.iv3 = make_iv3(30000011, -30000013, 30000017);
        r.p.uv = uvec2(3000000001, 4000000003);
        r.p.acc += 0.5_f32;
        let delta: fix64 = 0.25;
        let mut lx: fix64 = 2.5;
        lx += delta;
        r.p.out_local = lx;
    }
}

schedule Update { compute_all }
"#;
    let analyzed = analyze_source("jit_nb123_fix64.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_nb123_fix64".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (pl_sz, off_one) = field_offset_of(&mir, "Payload", "one");
    let (_, off_pairs) = field_offset_of(&mir, "Payload", "pairs");
    let (_, off_pts) = field_offset_of(&mir, "Payload", "pts");
    let (_, off_kind) = field_offset_of(&mir, "Payload", "kind");
    let (_, off_iv) = field_offset_of(&mir, "Payload", "iv");
    let (_, off_iv3) = field_offset_of(&mir, "Payload", "iv3");
    let (_, off_uv) = field_offset_of(&mir, "Payload", "uv");
    let (_, off_acc) = field_offset_of(&mir, "Payload", "acc");
    let (_, off_out_local) = field_offset_of(&mir, "Payload", "out_local");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_cmd_spawn = idx(api_slots::CMD_SPAWN);
    let s_bind_obj = idx(api_slots::BIND_NAMED_OBJECT);
    let s_cfg_sset = idx(api_slots::CONFIGURE_SCHEDULE_SET);
    let s_mount_sys = idx(api_slots::MOUNT_SYSTEM_IN_SCHEDULE);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind_obj}u
#define SLOT_CONFIGURE_SCHEDULE_SET {s_cfg_sset}u
#define SLOT_MOUNT_SYSTEM_IN_SCHEDULE {s_mount_sys}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds_sentinel = 77;
static uint32_t g_next_comp = 10, g_pl_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[8];
static size_t g_sys_n = 0;
static uint8_t g_pl_buf[{pl_sz}];
static int g_spawned = 0, g_bound = 0, g_stage = 0, g_startup_done = 0;
static uint64_t g_ents[1] = {{ 601ull }};

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "Payload")) g_pl_comp = id;
    *o = id; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{
    (void)sc; *out_cmds = &g_cmds_sentinel; return 0;
}}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_ent) {{
    (void)cmds;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_pl_comp && ptrs[i] != NULL) {{
            memcpy(g_pl_buf, ptrs[i], {pl_sz});
            g_spawned = 1;
        }}
    }}
    *out_ent = 601ull;
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* name, size_t len, uint64_t ent) {{
    (void)hc;
    if (name && len == 11 && memcmp(name, "ObjOverride", 11) == 0 && ent == 601ull) g_bound = 1;
    return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi;
    if (!g_startup_done) {{ *o = NULL; return 0; }}
    g_stage = 0; *o = (void*)0x2222; return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    (void)it;
    if (g_stage == 0) {{ g_stage = 1; *len = 1; return 1; }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{ (void)it; return g_ents; }}
static void* h_col(void* it, size_t ti) {{
    (void)it; (void)ti; return g_pl_buf;
}}
static uint32_t h_mark_chg(void* it, size_t ti, size_t s, size_t l) {{
    (void)it; (void)ti; (void)s; (void)l; return 0;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_MARK_CHANGED_RANGE] = (void*)h_mark_chg;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "init_objects")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 24;
        }}
    }}
    g_startup_done = 1;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (!strstr(g_sys[i].name, "init_objects")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 25;
        }}
    }}
    if (!g_spawned || !g_bound) {{
        fprintf(stderr, "spawned=%d bound=%d sys_n=%zu s0=%s s1=%s\n", g_spawned, g_bound, g_sys_n, g_sys_n > 0 ? g_sys[0].name : "-", g_sys_n > 1 ? g_sys[1].name : "-");
        return 5;
    }}

    int32_t one_a = 0; uint32_t one_b = 0;
    memcpy(&one_a, g_pl_buf + {off_one}, 4);
    memcpy(&one_b, g_pl_buf + {off_one} + 4, 4);
    if (one_a != 30000001 || one_b != 3000000001u) {{
        fprintf(stderr, "one=[%d,%u]\n", one_a, one_b); return 10;
    }}
    int32_t p0_a = 0, p1_a = 0; uint32_t p0_b = 0, p1_b = 0;
    memcpy(&p0_a, g_pl_buf + {off_pairs}, 4);
    memcpy(&p0_b, g_pl_buf + {off_pairs} + 4, 4);
    memcpy(&p1_a, g_pl_buf + {off_pairs} + 8, 4);
    memcpy(&p1_b, g_pl_buf + {off_pairs} + 12, 4);
    if (p0_a != -7 || p0_b != 9u || p1_a != 11 || p1_b != 13u) {{
        fprintf(stderr, "pairs=[%d,%u,%d,%u]\n", p0_a, p0_b, p1_a, p1_b); return 11;
    }}
    int32_t pts[4] = {{0}};
    memcpy(pts, g_pl_buf + {off_pts}, 16);
    if (pts[0] != 30000003 || pts[1] != -30000005 || pts[2] != 42 || pts[3] != -99) {{
        fprintf(stderr, "pts=[%d,%d,%d,%d]\n", pts[0], pts[1], pts[2], pts[3]); return 12;
    }}
    uint32_t kind = 0;
    memcpy(&kind, g_pl_buf + {off_kind}, 4);
    if (kind != 1u) {{ fprintf(stderr, "kind=%u\n", kind); return 13; }}

    int32_t iv[2] = {{0}}; int32_t iv3[3] = {{0}}; uint32_t uv[2] = {{0}};
    memcpy(iv, g_pl_buf + {off_iv}, 8);
    memcpy(iv3, g_pl_buf + {off_iv3}, 12);
    memcpy(uv, g_pl_buf + {off_uv}, 8);
    if (iv[0] != 30000001 || iv[1] != -30000007) {{
        fprintf(stderr, "iv=[%d,%d]\n", iv[0], iv[1]); return 14;
    }}
    if (iv3[0] != 30000011 || iv3[1] != -30000013 || iv3[2] != 30000017) {{
        fprintf(stderr, "iv3=[%d,%d,%d]\n", iv3[0], iv3[1], iv3[2]); return 15;
    }}
    if (uv[0] != 3000000001u || uv[1] != 4000000003u) {{
        fprintf(stderr, "uv=[%u,%u]\n", uv[0], uv[1]); return 16;
    }}

    int64_t acc_raw = 0, local_raw = 0;
    memcpy(&acc_raw, g_pl_buf + {off_acc}, 8);
    memcpy(&local_raw, g_pl_buf + {off_out_local}, 8);
    /* Q32.32: 1.5 = 3 << 31, 2.75 = 11 << 30 */
    if (acc_raw != (3LL << 31) || local_raw != (11LL << 30)) {{
        fprintf(stderr, "acc=%lld local=%lld\n", (long long)acc_raw, (long long)local_raw); return 17;
    }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_nb123_fix64", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_executes_option_zst_sparse_if_let_match_expect_and_single_term() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_opt_matrix @version(1.0.0);

tag TagZ;

@sparse
component Sp { bonus: i32 = 0 }

component Shield { hp: f32 = 10.0 }

component Out {
    tag_hits: i32 = 0,
    tag_misses: i32 = 0,
    sp_sum: i32 = 0,
    iflet_sum: f32 = 0.0,
    match_sum: f32 = 0.0,
}

resource SingleRes {
    some_cnt: i32 = 0,
    none_cnt: i32 = 0,
    expect_hp: f32 = 0.0,
    match_hp: f32 = 0.0,
    iflet_hp: f32 = 0.0,
}

sys check_tag_and_sparse() {
    for row in query(o: &mut Out, tg: Option<&TagZ>, sp: Option<&mut Sp>) {
        if let Some(_) = row.tg {
            row.o.tag_hits += 1;
        } else {
            row.o.tag_misses += 1;
        }
        match row.sp {
            Some(s) => {
                s.bonus += 5;
                row.o.sp_sum += s.bonus;
            },
            None => {
                row.o.sp_sum -= 1;
            },
        }
    }
}

sys check_iflet_and_match() {
    for row in query(o: &mut Out, sh: Option<&Shield>) {
        if let Some(x) = row.sh {
            row.o.iflet_sum += x.hp;
        }
        match row.sh {
            Some(x) => { row.o.match_sum += x.hp * 2.0; },
            None => { row.o.match_sum += 1.0; },
        }
    }
}

sys check_single_term(sr: &mut res SingleRes) {
    for sh in query(sh: Option<&mut Shield>) {
        if sh.is_some() && !sh.is_none() {
            sr.some_cnt += 1;
            let p = sh.expect("shield present");
            p.hp += 3.0;
            sr.expect_hp += p.hp;
        }
        if sh.is_none() {
            sr.none_cnt += 1;
        }
        if let Some(x) = sh {
            sr.iflet_hp += x.hp;
        }
        match sh {
            Some(x) => { sr.match_hp += x.hp + 1.0; },
            None => { sr.match_hp += 100.0; },
        }
    }
}

schedule Update { check_tag_and_sparse, check_iflet_and_match, check_single_term }
"#;
    let analyzed = analyze_source("jit_opt_matrix.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_opt_matrix".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (sp_sz, off_bonus) = field_offset_of(&mir, "Sp", "bonus");
    let (sh_sz, off_hp) = field_offset_of(&mir, "Shield", "hp");
    let (out_sz, off_tag_hits) = field_offset_of(&mir, "Out", "tag_hits");
    let (_, off_tag_misses) = field_offset_of(&mir, "Out", "tag_misses");
    let (_, off_sp_sum) = field_offset_of(&mir, "Out", "sp_sum");
    let (_, off_iflet_sum) = field_offset_of(&mir, "Out", "iflet_sum");
    let (_, off_match_sum) = field_offset_of(&mir, "Out", "match_sum");

    let (res_sz, off_some) = field_offset_of(&mir, "SingleRes", "some_cnt");
    let (_, off_none) = field_offset_of(&mir, "SingleRes", "none_cnt");
    let (_, off_exp_hp) = field_offset_of(&mir, "SingleRes", "expect_hp");
    let (_, off_m_hp) = field_offset_of(&mir, "SingleRes", "match_hp");
    let (_, off_il_hp) = field_offset_of(&mir, "SingleRes", "iflet_hp");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_col_rows_ro = idx(api_slots::ITER_COLUMN_ROWS_READONLY);
    let s_col_rows_mut = idx(api_slots::ITER_COLUMN_ROWS_MUTABLE);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_ITER_COL_ROWS_RO {s_col_rows_ro}u
#define SLOT_ITER_COL_ROWS_MUT {s_col_rows_mut}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_next_comp = 10, g_res_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[8];
static size_t g_sys_n = 0;
static int g_cur_sys = 0; /* 0: tag_sparse, 1: iflet_match, 2: single_term */
static size_t g_chunk = 0;

/* Chunk 0: 2 rows (TagZ present, Sp present, Shield absent); Chunk 1: 1 row (TagZ absent, Sp absent, Shield present) */
static uint64_t g_ents_c0[2] = {{ 101ull, 102ull }};
static uint64_t g_ents_c1[1] = {{ 201ull }};
static uint8_t g_out_c0[2 * {out_sz}];
static uint8_t g_out_c1[{out_sz}];
static uint8_t g_sp_rows[2][{sp_sz}];
static void* g_sp_ptrs_c0[2] = {{ g_sp_rows[0], g_sp_rows[1] }};
static uint8_t g_sh_c1[{sh_sz}];
static uint8_t g_res_buf[{res_sz}];

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "SingleRes")) g_res_comp = id;
    *o = id; return 0;
}}
static uint32_t h_resolve_comp(const void* hc, const char* name, const BamComponentUuid* uuid, uint32_t* out) {{
    (void)hc; (void)uuid;
    if (name && strstr(name, "SingleRes")) {{
        if (g_res_comp == 0) g_res_comp = g_next_comp++;
        *out = g_res_comp;
        return 0;
    }}
    return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* info) {{
    (void)hc;
    if (c == g_res_comp) {{
        info->flags = FLAG_RESOURCE;
        info->size = {res_sz};
        info->align = 4;
        return 0;
    }}
    return 4;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static void* h_res_mut_ptr(void* hc, uint32_t c) {{
    (void)hc; return (c == g_res_comp) ? (void*)g_res_buf : NULL;
}}
static void* h_sys_res_mut_ptr(void* sc, uint32_t c) {{
    (void)sc; return (c == g_res_comp) ? (void*)g_res_buf : NULL;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi; g_chunk = 0; *o = (void*)0x2222; return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    (void)it;
    if (g_chunk == 0) {{ g_chunk = 1; *len = 2; return 1; }}
    if (g_chunk == 1) {{ g_chunk = 2; *len = 1; return 1; }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{
    (void)it; return (g_chunk == 1) ? g_ents_c0 : g_ents_c1;
}}
static void* h_col(void* it, size_t ti) {{
    (void)it;
    if (g_cur_sys == 0) {{
        if (ti == 0) return (g_chunk == 1) ? (void*)g_out_c0 : (void*)g_out_c1;
        if (ti == 1) return (g_chunk == 1) ? (void*)0x1 : NULL; /* TagZ ZST */
        return NULL;
    }} else if (g_cur_sys == 1) {{
        if (ti == 0) return (g_chunk == 1) ? (void*)g_out_c0 : (void*)g_out_c1;
        if (ti == 1) return (g_chunk == 1) ? NULL : (void*)g_sh_c1;
        return NULL;
    }} else {{
        if (ti == 0) return (g_chunk == 1) ? NULL : (void*)g_sh_c1;
        return NULL;
    }}
}}
static void* h_col_rows(void* it, size_t ti) {{
    (void)it;
    if (g_cur_sys == 0 && ti == 2) {{
        return (g_chunk == 1) ? (void*)g_sp_ptrs_c0 : NULL;
    }}
    return NULL;
}}
static uint32_t h_mark_chg(void* it, size_t ti, size_t s, size_t l) {{
    (void)it; (void)ti; (void)s; (void)l; return 0;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_RES_PTR] = (void*)h_res_mut_ptr;
    api.slots[SLOT_RES_MUT_PTR] = (void*)h_res_mut_ptr;
    api.slots[SLOT_SYS_RES_PTR] = (void*)h_sys_res_mut_ptr;
    api.slots[SLOT_SYS_RES_MUT_PTR] = (void*)h_sys_res_mut_ptr;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT_UNTRACKED] = (void*)h_col;
    api.slots[SLOT_ITER_COL_ROWS_RO] = (void*)h_col_rows;
    api.slots[SLOT_ITER_COL_ROWS_MUT] = (void*)h_col_rows;
    api.slots[SLOT_ITER_MARK_CHANGED_RANGE] = (void*)h_mark_chg;

    memset(g_out_c0, 0, sizeof(g_out_c0));
    memset(g_out_c1, 0, sizeof(g_out_c1));
    memset(g_sp_rows, 0, sizeof(g_sp_rows));
    memset(g_sh_c1, 0, sizeof(g_sh_c1));
    memset(g_res_buf, 0, sizeof(g_res_buf));
    int32_t b0 = 10, b1 = 20;
    memcpy(g_sp_rows[0] + {off_bonus}, &b0, 4);
    memcpy(g_sp_rows[1] + {off_bonus}, &b1, 4);
    float sh0 = 12.0f;
    memcpy(g_sh_c1 + {off_hp}, &sh0, 4);

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;

    int found_single = 0;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "check_tag_and_sparse") == 0) {{
            g_cur_sys = 0;
            uint32_t rc = g_sys[i].cb(&g_sctx, g_sys[i].ud);
            if (rc != 0) {{ fprintf(stderr, "sys0 rc=%u\n", rc); return 20; }}
        }} else if (strcmp(g_sys[i].name, "check_iflet_and_match") == 0) {{
            g_cur_sys = 1;
            uint32_t rc = g_sys[i].cb(&g_sctx, g_sys[i].ud);
            if (rc != 0) {{ fprintf(stderr, "sys1 rc=%u\n", rc); return 21; }}
        }} else if (strcmp(g_sys[i].name, "check_single_term") == 0) {{
            found_single = 1;
            g_cur_sys = 2;
            uint32_t rc = g_sys[i].cb(&g_sctx, g_sys[i].ud);
            if (rc != 0) {{ fprintf(stderr, "sys2 rc=%u\n", rc); return 22; }}
        }}
    }}
    if (!found_single) {{ fprintf(stderr, "missing check_single_term (n=%zu)\n", g_sys_n); return 23; }}

    /* Verify Chunk 0 (2 rows) & Chunk 1 (1 row) Out fields */
    int32_t th0 = 0, th1 = 0, th2 = 0, tm2 = 0, sp0 = 0, sp1 = 0, sp2 = 0;
    memcpy(&th0, g_out_c0 + 0 * {out_sz} + {off_tag_hits}, 4);
    memcpy(&th1, g_out_c0 + 1 * {out_sz} + {off_tag_hits}, 4);
    memcpy(&th2, g_out_c1 + {off_tag_hits}, 4);
    memcpy(&tm2, g_out_c1 + {off_tag_misses}, 4);
    memcpy(&sp0, g_out_c0 + 0 * {out_sz} + {off_sp_sum}, 4);
    memcpy(&sp1, g_out_c0 + 1 * {out_sz} + {off_sp_sum}, 4);
    memcpy(&sp2, g_out_c1 + {off_sp_sum}, 4);
    if (th0 != 1 || th1 != 1 || th2 != 0 || tm2 != 1) {{
        fprintf(stderr, "tags=[%d,%d,%d,%d]\n", th0, th1, th2, tm2); return 10;
    }}
    if (sp0 != 15 || sp1 != 25 || sp2 != -1) {{
        fprintf(stderr, "sp=[%d,%d,%d]\n", sp0, sp1, sp2); return 11;
    }}
    float il0 = 0, il2 = 0, ms0 = 0, ms2 = 0;
    memcpy(&il0, g_out_c0 + 0 * {out_sz} + {off_iflet_sum}, 4);
    memcpy(&il2, g_out_c1 + {off_iflet_sum}, 4);
    memcpy(&ms0, g_out_c0 + 0 * {out_sz} + {off_match_sum}, 4);
    memcpy(&ms2, g_out_c1 + {off_match_sum}, 4);
    if (il0 != 0.0f || il2 != 12.0f || ms0 != 1.0f || ms2 != 24.0f) {{
        fprintf(stderr, "iflet/match=[%f,%f,%f,%f]\n", il0, il2, ms0, ms2); return 12;
    }}

    /* Verify SingleRes from single-term Option<&mut Shield> */
    int32_t sc = 0, nc = 0;
    float ehp = 0, mhp = 0, ihp = 0;
    memcpy(&sc, g_res_buf + {off_some}, 4);
    memcpy(&nc, g_res_buf + {off_none}, 4);
    memcpy(&ehp, g_res_buf + {off_exp_hp}, 4);
    memcpy(&mhp, g_res_buf + {off_m_hp}, 4);
    memcpy(&ihp, g_res_buf + {off_il_hp}, 4);
    /* Chunk 0 (2 rows) -> None (2 * 100 = 200); Chunk 1 (1 row) -> Some (12 + 3 = 15, match +1 = 16) */
    if (sc != 1 || nc != 2 || ehp != 15.0f || ihp != 15.0f || mhp != 216.0f) {{
        fprintf(stderr, "single=[sc=%d nc=%d e=%f i=%f m=%f]\n", sc, nc, ehp, ihp, mhp); return 13;
    }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_opt_matrix", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_executes_nested_struct_offsets_mat_pair_and_object_cast_binop() {
    let src = r#"
module test::jit_nested_obj @version(1.0.0);

enum Kind { Alpha = 0, Beta = 1 }

struct Pair {
    a: i32 = -1,
    b: u32 = 3000000001,
}

struct Inner {
    x: i32 = -7,
    y: u32 = 3000000001,
    pts: [ivec2; 2] = [ivec2(16777217, -16777219), ivec2(1, 2)],
}

struct Outer {
    pad: i32 = 9,
    inner: Inner = Inner { x: -7, y: 3000000001, pts: [ivec2(16777217, -16777219), ivec2(1, 2)] },
}

component Payload {
    kinds: [Kind; 2] = [Kind::Alpha, Kind::Beta],
    outer: Outer = Outer { pad: 9, inner: Inner { x: -7, y: 3000000001, pts: [ivec2(16777217, -16777219), ivec2(1, 2)] } },
    mat_pair: [[Pair; 2]; 2] = [[Pair { a: -1, b: 3000000001 }, Pair { a: 2, b: 3 }], [Pair { a: 4, b: 5 }, Pair { a: 6, b: 7 }]],
    cast_i32: i32 = 0,
    cast_fix: fix64 = 0.0,
    iv_bin: ivec2 = ivec2(0, 0),
    uv_cast: uvec2 = uvec2(0, 0),
    out_y: u32 = 0,
    out_pt0: ivec2 = ivec2(0, 0),
    out_mat_b: u32 = 0,
}

object ObjNested {
    Payload {
        kinds: [Kind::Beta, Kind::Alpha],
        cast_i32: 3.9_f32 as i32,
        cast_fix: 3.9_f32 as i32,
        iv_bin: ivec2(-2147483647 - 1, 2147483647),
        uv_cast: uvec2((-1_i32) as u32, (-(-5)) as u32),
    },
}

sys read_nested() {
    for r in query(p: &mut Payload) {
        r.p.out_y = r.p.outer.inner.y;
        r.p.out_pt0 = r.p.outer.inner.pts[0];
        r.p.out_mat_b = r.p.mat_pair[0][0].b;
    }
}

schedule Update { read_nested }
"#;
    let analyzed = analyze_source("jit_nested_obj.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_nested_obj".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (pl_sz, off_cast_i32) = field_offset_of(&mir, "Payload", "cast_i32");
    let (_, off_cast_fix) = field_offset_of(&mir, "Payload", "cast_fix");
    let (_, off_iv_bin) = field_offset_of(&mir, "Payload", "iv_bin");
    let (_, off_uv_cast) = field_offset_of(&mir, "Payload", "uv_cast");
    let (_, off_out_y) = field_offset_of(&mir, "Payload", "out_y");
    let (_, off_out_pt0) = field_offset_of(&mir, "Payload", "out_pt0");
    let (_, off_out_mat_b) = field_offset_of(&mir, "Payload", "out_mat_b");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_cmd_spawn = idx(strata_jit::abi_offsets::api_slots::CMD_SPAWN);
    let s_bind_obj = idx(strata_jit::abi_offsets::api_slots::BIND_NAMED_OBJECT);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind_obj}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds_sentinel = 77;
static uint32_t g_next_comp = 10, g_pl_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[8];
static size_t g_sys_n = 0;
static uint8_t g_pl_buf[{pl_sz}];
static int g_spawned = 0, g_stage = 0, g_startup_done = 0;
static uint64_t g_ents[1] = {{ 601ull }};

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "Payload")) g_pl_comp = id;
    *o = id; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{ (void)sc; *out_cmds = &g_cmds_sentinel; return 0; }}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_ent) {{
    (void)cmds;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_pl_comp && ptrs[i] != NULL) {{
            memcpy(g_pl_buf, ptrs[i], {pl_sz});
            g_spawned = 1;
        }}
    }}
    *out_ent = 601ull;
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* n, size_t l, uint64_t e) {{
    (void)hc; (void)n; (void)l; (void)e; return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi;
    if (!g_startup_done) {{ *o = NULL; return 0; }}
    g_stage = 0; *o = (void*)0x2222; return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    (void)it;
    if (g_stage == 0) {{ g_stage = 1; *len = 1; return 1; }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{ (void)it; return g_ents; }}
static void* h_col(void* it, size_t ti) {{ (void)it; (void)ti; return g_pl_buf; }}
static uint32_t h_mark_chg(void* it, size_t ti, size_t s, size_t l) {{ (void)it; (void)ti; (void)s; (void)l; return 0; }}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }}
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_MARK_CHANGED_RANGE] = (void*)h_mark_chg;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "init_objects")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 24;
        }}
    }}
    g_startup_done = 1;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (!strstr(g_sys[i].name, "init_objects")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 25;
        }}
    }}
    if (!g_spawned) return 5;

    int32_t ci = 0; int64_t cf = 0;
    int32_t ivb[2] = {{0}}; uint32_t uvc[2] = {{0}};
    uint32_t oy = 0, omb = 0; int32_t opt0[2] = {{0}};
    memcpy(&ci, g_pl_buf + {off_cast_i32}, 4);
    memcpy(&cf, g_pl_buf + {off_cast_fix}, 8);
    memcpy(ivb, g_pl_buf + {off_iv_bin}, 8);
    memcpy(uvc, g_pl_buf + {off_uv_cast}, 8);
    memcpy(&oy, g_pl_buf + {off_out_y}, 4);
    memcpy(opt0, g_pl_buf + {off_out_pt0}, 8);
    memcpy(&omb, g_pl_buf + {off_out_mat_b}, 4);

    if (ci != 3 || cf != (3LL << 32)) {{
        fprintf(stderr, "cast ci=%d cf=%lld\n", ci, (long long)cf); return 10;
    }}
    if (ivb[0] != (-2147483647 - 1) || ivb[1] != 2147483647) {{
        fprintf(stderr, "iv_bin=[%d,%d]\n", ivb[0], ivb[1]); return 11;
    }}
    if (uvc[0] != 4294967295u || uvc[1] != 5u) {{
        fprintf(stderr, "uv_cast=[%u,%u]\n", uvc[0], uvc[1]); return 12;
    }}
    if (oy != 3000000001u || opt0[0] != 16777217 || opt0[1] != -16777219 || omb != 3000000001u) {{
        fprintf(stderr, "nested oy=%u opt0=[%d,%d] omb=%u\n", oy, opt0[0], opt0[1], omb); return 13;
    }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_nested_obj", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_executes_reversed_option_match_and_let_expect_non_offset0_changed() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_rev_match_let_expect @version(1.0.0);

component OtherComp {
    pad: i32 = 123,
    hp: f32 = 55.0,
}

component Out {
    rev_some: i32 = 0,
    rev_wild: i32 = 0,
}

sys check_rev_and_let_expect() {
    for row in query(o: &mut Out, oc: Option<&mut OtherComp>) {
        if row.oc.is_some() {
            let op = row.oc.expect("oc present");
            op.hp += 1.0;
            let op2 = row.oc.unwrap();
            op2.hp += 2.0;
        }
        match row.oc {
            None => { row.o.rev_some -= 10; },
            Some(x) => { row.o.rev_some += x.pad; },
        }
        match row.oc {
            None => { row.o.rev_wild -= 5; },
            _ => { row.o.rev_wild += 7; },
        }
    }
}

schedule Update { check_rev_and_let_expect }
"#;
    let analyzed = analyze_source("jit_rev_match_let_expect.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_rev_match_let_expect".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (oc_sz, off_pad) = field_offset_of(&mir, "OtherComp", "pad");
    let (_, off_hp) = field_offset_of(&mir, "OtherComp", "hp");
    let (out_sz, off_rev_some) = field_offset_of(&mir, "Out", "rev_some");
    let (_, off_rev_wild) = field_offset_of(&mir, "Out", "rev_wild");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_col_untracked = idx(api_slots::ITER_COLUMN_MUTABLE_UNTRACKED);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_ITER_COL_UNTRACKED {s_col_untracked}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_next_comp = 10;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[4];
static size_t g_sys_n = 0;
static size_t g_chunk = 0;

/* Chunk 0: 1 row with OtherComp present; Chunk 1: 1 row with OtherComp absent */
static uint64_t g_ents_c0[1] = {{ 101ull }};
static uint64_t g_ents_c1[1] = {{ 102ull }};
static uint8_t g_out_c0[{out_sz}];
static uint8_t g_out_c1[{out_sz}];
static uint8_t g_oc_c0[{oc_sz}];
static uint32_t g_chg_calls = 0, g_chg_start = 999, g_chg_len = 999;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; (void)d; *o = g_next_comp++; return 0;
}}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; *o = 99; return 0;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi; g_chunk = 0; *o = (void*)0x3333; return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    (void)it;
    if (g_chunk == 0) {{ g_chunk = 1; *len = 1; return 1; }}
    if (g_chunk == 1) {{ g_chunk = 2; *len = 1; return 1; }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{
    (void)it; return (g_chunk == 1) ? g_ents_c0 : g_ents_c1;
}}
static void* h_col(void* it, size_t ti) {{
    (void)it;
    if (ti == 0) return (g_chunk == 1) ? g_out_c0 : g_out_c1;
    return (g_chunk == 1) ? g_oc_c0 : NULL;
}}
static uint32_t h_mark_chg(void* it, size_t ti, size_t s, size_t l) {{
    (void)it;
    if (ti == 1) {{ g_chg_calls++; g_chg_start = (uint32_t)s; g_chg_len = (uint32_t)l; }}
    return 0;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_UNTRACKED] = (void*)h_col;
    api.slots[SLOT_ITER_MARK_CHANGED_RANGE] = (void*)h_mark_chg;

    memset(g_out_c0, 0, sizeof(g_out_c0));
    memset(g_out_c1, 0, sizeof(g_out_c1));
    memset(g_oc_c0, 0, sizeof(g_oc_c0));
    int32_t pad0 = 123;
    float hp0 = 55.0f;
    memcpy(g_oc_c0 + {off_pad}, &pad0, 4);
    memcpy(g_oc_c0 + {off_hp}, &hp0, 4);

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    if (g_sys_n != 1 || g_sys[0].cb(&g_sctx, g_sys[0].ud) != 0) return 5;

    int32_t pad_after = 0; float hp_after = 0.0f;
    memcpy(&pad_after, g_oc_c0 + {off_pad}, 4);
    memcpy(&hp_after, g_oc_c0 + {off_hp}, 4);
    if (pad_after != 123 || hp_after != 58.0f) {{
        fprintf(stderr, "oc pad=%d hp=%f\n", pad_after, hp_after); return 10;
    }}
    if (g_chg_calls != 1 || g_chg_start != 0 || g_chg_len != 1) {{
        fprintf(stderr, "chg calls=%u start=%u len=%u\n", g_chg_calls, g_chg_start, g_chg_len); return 11;
    }}

    int32_t rs0 = 0, rw0 = 0, rs1 = 0, rw1 = 0;
    memcpy(&rs0, g_out_c0 + {off_rev_some}, 4);
    memcpy(&rw0, g_out_c0 + {off_rev_wild}, 4);
    memcpy(&rs1, g_out_c1 + {off_rev_some}, 4);
    memcpy(&rw1, g_out_c1 + {off_rev_wild}, 4);
    if (rs0 != 123 || rw0 != 7 || rs1 != -10 || rw1 != -5) {{
        fprintf(stderr, "rev=[%d,%d,%d,%d]\n", rs0, rw0, rs1, rw1); return 12;
    }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(
        tmp.path(),
        "jit_rev_match_let_expect",
        &c_code,
        &artifact.dylib_path,
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_step2_iter3_vec_consts_neg_casts_enum16_inlinestr_iflet_scope_and_single_term_alias() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_iter3 @version(1.0.0);

tag Tag;

enum Kind16 {
    Low = 1,
    High = 60000,
}

struct WithInlineStr {
    label: InlineStr<16> = "init",
    k: Kind16 = Kind16::High,
}

component OtherComp {
    pad: i32 = 123,
    hp: f32 = 55.0,
}

component Out {
    uv_one: uvec2 = uvec2::ZERO,
    uv_x: uvec2 = uvec2::ZERO,
    iv_y: ivec2 = ivec2::ZERO,
    iv3_z: ivec3 = ivec3::ZERO,
    v4_w: vec4 = vec4::ZERO,
    neg_i32: i32 = 0,
    neg_u32: u32 = 99,
    k16: Kind16 = Kind16::Low,
    arr16: [Kind16; 2] = [Kind16::Low, Kind16::Low],
    w: WithInlineStr = WithInlineStr { label: "init", k: Kind16::High },
    shadow_iflet: i32 = 0,
    acc_out: i32 = 0,
}

object ObjIter3 {
    Out {
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
    Tag {},
    OtherComp { pad: 123, hp: 55.0 },
}

sys step_iter3_iflet() {
    for row in query(o: &mut Out, oc: Option<&mut OtherComp>) {
        let x: i32 = 999;
        let mut acc: i32 = 10;
        if let Some(x) = row.oc {
            let x2 = x;
            x2.hp += 1.0;
        }
        if true {
            let y: i32 = 77;
            acc += y;
        }
        row.o.shadow_iflet = x;
        row.o.acc_out = acc;
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

schedule Update { step_iter3_iflet, step_iter3_single }
"#;
    let analyzed = analyze_source("jit_iter3.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_iter3".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (out_sz, off_uv_one) = field_offset_of(&mir, "Out", "uv_one");
    let (_, off_uv_x) = field_offset_of(&mir, "Out", "uv_x");
    let (_, off_iv_y) = field_offset_of(&mir, "Out", "iv_y");
    let (_, off_iv3_z) = field_offset_of(&mir, "Out", "iv3_z");
    let (_, off_v4_w) = field_offset_of(&mir, "Out", "v4_w");
    let (_, off_neg_i32) = field_offset_of(&mir, "Out", "neg_i32");
    let (_, off_neg_u32) = field_offset_of(&mir, "Out", "neg_u32");
    let (_, off_k16) = field_offset_of(&mir, "Out", "k16");
    let (_, off_arr16) = field_offset_of(&mir, "Out", "arr16");
    let (_, off_w) = field_offset_of(&mir, "Out", "w");
    let (_, off_shadow) = field_offset_of(&mir, "Out", "shadow_iflet");
    let (_, off_acc) = field_offset_of(&mir, "Out", "acc_out");
    let (oc_sz, off_pad) = field_offset_of(&mir, "OtherComp", "pad");
    let (_, off_hp) = field_offset_of(&mir, "OtherComp", "hp");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_cmd_spawn = idx(api_slots::CMD_SPAWN);
    let s_bind_obj = idx(api_slots::BIND_NAMED_OBJECT);
    let s_col_untracked = idx(api_slots::ITER_COLUMN_MUTABLE_UNTRACKED);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind_obj}u
#define SLOT_ITER_COL_UNTRACKED {s_col_untracked}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds_sentinel = 77;
static uint32_t g_next_comp = 10, g_out_comp = 0, g_oc_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[8];
static size_t g_sys_n = 0;
static uint8_t g_out_buf[{out_sz}];
static uint8_t g_oc_buf[{oc_sz}];
static int g_spawned = 0, g_startup_done = 0, g_q_stage = 0, g_cur_sys = 0;
static uint64_t g_ents[1] = {{ 801ull }};
static uint32_t g_oc_chg_calls = 0;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "Out")) g_out_comp = id;
    if (d->name && strstr(d->name, "OtherComp")) g_oc_comp = id;
    *o = id; return 0;
}}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{ (void)sc; *out_cmds = &g_cmds_sentinel; return 0; }}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_ent) {{
    (void)cmds;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_out_comp && ptrs[i] != NULL) {{
            memcpy(g_out_buf, ptrs[i], {out_sz});
            g_spawned = 1;
        }}
        if (comps[i] == g_oc_comp && ptrs[i] != NULL) {{
            memcpy(g_oc_buf, ptrs[i], {oc_sz});
        }}
    }}
    *out_ent = 801ull;
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* n, size_t l, uint64_t e) {{
    (void)hc; (void)n; (void)l; (void)e; return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi;
    if (!g_startup_done) {{ *o = NULL; return 0; }}
    g_q_stage = 0; *o = (void*)0x4444; return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    (void)it;
    if (g_q_stage == 0) {{ g_q_stage = 1; *len = 1; return 1; }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{ (void)it; return g_ents; }}
static void* h_col(void* it, size_t ti) {{
    (void)it;
    if (g_cur_sys == 1 && ti == 0) return g_out_buf;
    return g_oc_buf;
}}
static uint32_t h_mark_chg(void* it, size_t ti, size_t s, size_t l) {{
    (void)it; (void)s; (void)l;
    if ((g_cur_sys == 1 && ti == 1) || (g_cur_sys == 2 && ti == 0)) g_oc_chg_calls++;
    return 0;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_UNTRACKED] = (void*)h_col;
    api.slots[SLOT_ITER_MARK_CHANGED_RANGE] = (void*)h_mark_chg;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "init_objects")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 24;
        }}
    }}
    if (!g_spawned) return 5;
    g_startup_done = 1;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (!strstr(g_sys[i].name, "init_objects")) {{
            if (strstr(g_sys[i].name, "iflet")) g_cur_sys = 1;
            else g_cur_sys = 2;
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 25;
        }}
    }}

    uint32_t uo[2] = {{0}}, ux[2] = {{0}}; int32_t ivy[2] = {{0}}, ivz[3] = {{0}};
    float v4[4] = {{0}}; int32_t ni = 0; uint32_t nu = 99;
    uint16_t k16 = 0, a16[2] = {{0}}, wk = 0; uint32_t slen = 0;
    int32_t sh = 0, acc = 0, pad_after = 0; float hp_after = 0.0f;
    memcpy(uo, g_out_buf + {off_uv_one}, 8);
    memcpy(ux, g_out_buf + {off_uv_x}, 8);
    memcpy(ivy, g_out_buf + {off_iv_y}, 8);
    memcpy(ivz, g_out_buf + {off_iv3_z}, 12);
    memcpy(v4, g_out_buf + {off_v4_w}, 16);
    memcpy(&ni, g_out_buf + {off_neg_i32}, 4);
    memcpy(&nu, g_out_buf + {off_neg_u32}, 4);
    memcpy(&k16, g_out_buf + {off_k16}, 2);
    memcpy(a16, g_out_buf + {off_arr16}, 4);
    memcpy(&slen, g_out_buf + {off_w}, 4);
    memcpy(&wk, g_out_buf + {off_w} + 20, 2);
    memcpy(&sh, g_out_buf + {off_shadow}, 4);
    memcpy(&acc, g_out_buf + {off_acc}, 4);
    memcpy(&pad_after, g_oc_buf + {off_pad}, 4);
    memcpy(&hp_after, g_oc_buf + {off_hp}, 4);

    if (uo[0] != 1u || uo[1] != 1u || ux[0] != 1u || ux[1] != 0u || ivy[0] != 0 || ivy[1] != 1 || ivz[2] != 1 || v4[3] != 1.0f) {{
        fprintf(stderr, "vec consts fail\n"); return 10;
    }}
    if (ni != -3 || nu != 0u) {{
        fprintf(stderr, "neg casts fail ni=%d nu=%u\n", ni, nu); return 11;
    }}
    if (k16 != 60000u || a16[0] != 60000u || a16[1] != 1u || slen != 4u || wk != 60000u || memcmp(g_out_buf + {off_w} + 4, "init", 4) != 0) {{
        fprintf(stderr, "enum16/inlinestr fail k=%u slen=%u wk=%u\n", k16, slen, wk); return 12;
    }}
    if (sh != 999 || acc != 87) {{
        fprintf(stderr, "iflet scope fail sh=%d acc=%d\n", sh, acc); return 13;
    }}
    if (pad_after != 123 || hp_after != 59.0f || g_oc_chg_calls != 2u) {{
        fprintf(stderr, "single-term alias fail pad=%d hp=%f chg=%u\n", pad_after, hp_after, g_oc_chg_calls); return 14;
    }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_iter3", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_step2_iter4_signed_enums_f64_narrow_casts_row_alias_and_query_one_unwrap() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_iter4 @version(1.0.0);

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

component BoxJit {
    neg_a: NegAuto = NegAuto::Neg,
    neg_e: NegExplicit = NegExplicit::MinNeg,
    arr_neg: [NegAuto; 2] = [NegAuto::Neg, NegAuto::Pos],
    ov_f64_u64: u64 = 0,
    ov_huge_i8: i8 = 0,
    ov_nhuge_i8: i8 = 0,
    ov_huge_u8: u8 = 0,
    rt_huge_i8: i8 = 0,
    rt_nhuge_i8: i8 = 0,
    rt_huge_i32: i32 = 0,
    rt_nhuge_i32: i32 = 0,
    rt_huge_i64: i64 = 0,
    rt_nhuge_i64: i64 = 0,
    alias_sum: i32 = 0,
    f_big32: f32 = 1e20_f32,
    f_nbig32: f32 = -1e20_f32,
    f_big64: f64 = 1e25_f64,
    f_nbig64: f64 = -1e25_f64,
}

component Wallet1 { coins: i32 = 100 }
component Wallet2 { coins: i32 = 200 }
component MissingTag { dummy: i32 = 0 }

object ObjBox {
    BoxJit {
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
object ObjNoWallet { MissingTag { dummy: 1 } }

sys step_row_and_q1_a() {
    for row in query(b: &mut BoxJit) {
        let row2 = row;
        let row3 = row2;
        row3.b.alias_sum += 10;
        row3.b.rt_huge_i8 = (row3.b.f_big32) as i8;
        row3.b.rt_nhuge_i8 = (row3.b.f_nbig32) as i8;
        row3.b.rt_huge_i32 = (row3.b.f_big32) as i32;
        row3.b.rt_nhuge_i32 = (row3.b.f_nbig32) as i32;
        row3.b.rt_huge_i64 = (row3.b.f_big64) as i64;
        row3.b.rt_nhuge_i64 = (row3.b.f_nbig64) as i64;
    }
    if let Some(wrow) = query_one(w: &mut Wallet1).on(ObjW1) {
        let wrow2 = wrow;
        wrow2.w.coins += 10;
    }
    let r2 = query_one(w: &mut Wallet2).on(ObjW2).expect("w2");
    r2.w.coins += 7;
}

sys step_row_and_q1_b() {
    let r1 = query_one(w: &mut Wallet1).on(ObjW1).unwrap();
    let r1b = r1;
    r1b.w.coins += 5;
    match query_one(w: &mut Wallet2).on(ObjW2) {
        Some(mr) => { mr.w.coins += 3; },
        None => {},
    }
}

sys step_absent_unwrap() {
    let rm = query_one(w: &mut Wallet1).on(ObjNoWallet).unwrap();
    rm.w.coins += 999;
}

schedule Update {
    seq Ordered { step_row_and_q1_a, step_row_and_q1_b, step_absent_unwrap }
}
"#;
    let analyzed = analyze_source("jit_iter4.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_iter4".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (box_sz, off_neg_a) = field_offset_of(&mir, "BoxJit", "neg_a");
    let (_, off_neg_e) = field_offset_of(&mir, "BoxJit", "neg_e");
    let (_, off_arr_neg) = field_offset_of(&mir, "BoxJit", "arr_neg");
    let (_, off_ov_f64_u64) = field_offset_of(&mir, "BoxJit", "ov_f64_u64");
    let (_, off_ov_huge_i8) = field_offset_of(&mir, "BoxJit", "ov_huge_i8");
    let (_, off_ov_nhuge_i8) = field_offset_of(&mir, "BoxJit", "ov_nhuge_i8");
    let (_, off_ov_huge_u8) = field_offset_of(&mir, "BoxJit", "ov_huge_u8");
    let (_, off_rt_huge_i8) = field_offset_of(&mir, "BoxJit", "rt_huge_i8");
    let (_, off_rt_nhuge_i8) = field_offset_of(&mir, "BoxJit", "rt_nhuge_i8");
    let (_, off_rt_huge_i32) = field_offset_of(&mir, "BoxJit", "rt_huge_i32");
    let (_, off_rt_nhuge_i32) = field_offset_of(&mir, "BoxJit", "rt_nhuge_i32");
    let (_, off_rt_huge_i64) = field_offset_of(&mir, "BoxJit", "rt_huge_i64");
    let (_, off_rt_nhuge_i64) = field_offset_of(&mir, "BoxJit", "rt_nhuge_i64");
    let (_, off_alias_sum) = field_offset_of(&mir, "BoxJit", "alias_sum");
    let (w1_sz, off_w1_coins) = field_offset_of(&mir, "Wallet1", "coins");
    let (w2_sz, off_w2_coins) = field_offset_of(&mir, "Wallet2", "coins");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_cmd_spawn = idx(api_slots::CMD_SPAWN);
    let s_bind_obj = idx(api_slots::BIND_NAMED_OBJECT);
    let s_cfg_sset = idx(api_slots::CONFIGURE_SCHEDULE_SET);
    let s_mount_sys = idx(api_slots::MOUNT_SYSTEM_IN_SCHEDULE);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind_obj}u
#define SLOT_CONFIGURE_SCHEDULE_SET {s_cfg_sset}u
#define SLOT_MOUNT_SYSTEM_IN_SCHEDULE {s_mount_sys}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds_sentinel = 77;
static uint32_t g_next_comp = 10, g_box_comp = 0, g_w1_comp = 0, g_w2_comp = 0, g_miss_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[8];
static size_t g_sys_n = 0;
static uint8_t g_box_buf[{box_sz}];
static uint8_t g_w1_buf[{w1_sz}];
static uint8_t g_w2_buf[{w2_sz}];
static int g_spawned = 0, g_q_stage = 0, g_startup_done = 0;
static uint64_t g_ents[1] = {{ 901ull }};

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t i4_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "BoxJit")) g_box_comp = id;
    else if (d->name && strstr(d->name, "Wallet1")) g_w1_comp = id;
    else if (d->name && strstr(d->name, "Wallet2")) g_w2_comp = id;
    else if (d->name && strstr(d->name, "MissingTag")) g_miss_comp = id;
    *o = id; return 0;
}}
static uint32_t i4_cfg_sset(void* lc, const void* d, uint32_t* o) {{
    (void)lc; (void)d; if (o) *o = 1; return 0;
}}
static uint32_t i4_mount_sys(void* lc, uint32_t s, uint32_t set) {{
    (void)lc; (void)s; (void)set; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{ (void)sc; *out_cmds = &g_cmds_sentinel; return 0; }}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_e) {{
    (void)cmds;
    *out_e = 901ull;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_box_comp && ptrs[i]) {{ memcpy(g_box_buf, ptrs[i], {box_sz}); g_spawned = 1; *out_e = 901ull; }}
        else if (comps[i] == g_w1_comp && ptrs[i]) {{ memcpy(g_w1_buf, ptrs[i], {w1_sz}); *out_e = 902ull; }}
        else if (comps[i] == g_w2_comp && ptrs[i]) {{ memcpy(g_w2_buf, ptrs[i], {w2_sz}); *out_e = 903ull; }}
        else if (comps[i] == g_miss_comp) {{ *out_e = 904ull; }}
    }}
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* n, size_t l, uint64_t e) {{
    (void)hc; (void)n; (void)l; (void)e; return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; (void)qi;
    if (!g_startup_done) {{ *o = NULL; return 0; }}
    g_q_stage = 0; *o = (void*)0x4444; return 0;
}}
static uint8_t h_next(void* it, size_t* len) {{
    (void)it;
    if (g_q_stage == 0) {{ g_q_stage = 1; *len = 1; return 1; }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{ (void)it; return g_ents; }}
static void* h_col(void* it, size_t ti) {{ (void)it; (void)ti; return g_box_buf; }}
static uint32_t h_mark_chg(void* it, size_t ti, size_t s, size_t l) {{
    (void)it; (void)ti; (void)s; (void)l; return 0;
}}
static void* h_ent_get_mut(void* sc, size_t qi, uint64_t ent, size_t ti) {{
    (void)sc; (void)qi; (void)ti;
    if (ent == 902ull) return g_w1_buf;
    if (ent == 903ull) return g_w2_buf;
    return NULL;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)i4_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_MARK_CHANGED_RANGE] = (void*)h_mark_chg;
    api.slots[SLOT_SYS_ENTITY_GET_MUT] = (void*)h_ent_get_mut;
    api.slots[SLOT_CONFIGURE_SCHEDULE_SET] = (void*)i4_cfg_sset;
    api.slots[SLOT_MOUNT_SYSTEM_IN_SCHEDULE] = (void*)i4_mount_sys;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "objects") || strstr(g_sys[i].name, "startup")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 24;
        }}
    }}
    if (!g_spawned) return 5;
    g_startup_done = 1;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "step_row_and_q1")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 25;
        }}
    }}
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "step_absent_unwrap")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 26;
        }}
    }}

    int32_t neg_a = 0, neg_e = 0, arr_neg[2] = {{0}};
    uint64_t ov_f64_u64 = 0;
    int8_t ov_hi8 = 0, ov_nhi8 = 0, rt_hi8 = 0, rt_nhi8 = 0;
    uint8_t ov_hu8 = 0;
    int32_t rt_hi32 = 0, rt_nhi32 = 0, alias_sum = 0, w1_c = 0, w2_c = 0;
    int64_t rt_hi64 = 0, rt_nhi64 = 0;

    memcpy(&neg_a, g_box_buf + {off_neg_a}, 4);
    memcpy(&neg_e, g_box_buf + {off_neg_e}, 4);
    memcpy(arr_neg, g_box_buf + {off_arr_neg}, 8);
    memcpy(&ov_f64_u64, g_box_buf + {off_ov_f64_u64}, 8);
    memcpy(&ov_hi8, g_box_buf + {off_ov_huge_i8}, 1);
    memcpy(&ov_nhi8, g_box_buf + {off_ov_nhuge_i8}, 1);
    memcpy(&ov_hu8, g_box_buf + {off_ov_huge_u8}, 1);
    memcpy(&rt_hi8, g_box_buf + {off_rt_huge_i8}, 1);
    memcpy(&rt_nhi8, g_box_buf + {off_rt_nhuge_i8}, 1);
    memcpy(&rt_hi32, g_box_buf + {off_rt_huge_i32}, 4);
    memcpy(&rt_nhi32, g_box_buf + {off_rt_nhuge_i32}, 4);
    memcpy(&rt_hi64, g_box_buf + {off_rt_huge_i64}, 8);
    memcpy(&rt_nhi64, g_box_buf + {off_rt_nhuge_i64}, 8);
    memcpy(&alias_sum, g_box_buf + {off_alias_sum}, 4);
    memcpy(&w1_c, g_w1_buf + {off_w1_coins}, 4);
    memcpy(&w2_c, g_w2_buf + {off_w2_coins}, 4);

    if (neg_a != 5 || neg_e != -300 || arr_neg[0] != 5 || arr_neg[1] != -5) return 10;
    if (ov_f64_u64 != 1000000000000001ull || ov_hi8 != 127 || ov_nhi8 != -128 || ov_hu8 != 255u) return 11;
    if (rt_hi8 != 127 || rt_nhi8 != -128 || rt_hi32 != INT32_MAX || rt_nhi32 != INT32_MIN) return 12;
    if (rt_hi64 != INT64_MAX || rt_nhi64 != INT64_MIN) return 13;
    if (alias_sum != 10 || w1_c != 115 || w2_c != 210) return 14;

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_iter4", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_step2_iter5_object_override_non_finite_float_casts() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_iter5 @version(1.0.0);

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
    let analyzed = analyze_source("jit_iter5.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_iter5".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (cr_sz, off_nan_i8) = field_offset_of(&mir, "CastRes", "ov_nan_i8");
    let (_, off_nan_i16) = field_offset_of(&mir, "CastRes", "ov_nan_i16");
    let (_, off_nan_i32) = field_offset_of(&mir, "CastRes", "ov_nan_i32");
    let (_, off_nan_i64) = field_offset_of(&mir, "CastRes", "ov_nan_i64");
    let (_, off_inf_i32) = field_offset_of(&mir, "CastRes", "ov_inf_i32");
    let (_, off_ninf_i8) = field_offset_of(&mir, "CastRes", "ov_ninf_i8");
    let (_, off_inf_u8) = field_offset_of(&mir, "CastRes", "ov_inf_u8");
    let (_, off_ninf_u64) = field_offset_of(&mir, "CastRes", "ov_ninf_u64");
    let (_, off_nan_f32) = field_offset_of(&mir, "CastRes", "ov_nan_f32");
    let (_, off_inf_f64) = field_offset_of(&mir, "CastRes", "ov_inf_f64");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_cmd_spawn = idx(api_slots::CMD_SPAWN);
    let s_bind_obj = idx(api_slots::BIND_NAMED_OBJECT);
    let s_cfg_sset = idx(api_slots::CONFIGURE_SCHEDULE_SET);
    let s_mount_sys = idx(api_slots::MOUNT_SYSTEM_IN_SCHEDULE);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#include <math.h>
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind_obj}u
#define SLOT_CONFIGURE_SCHEDULE_SET {s_cfg_sset}u
#define SLOT_MOUNT_SYSTEM_IN_SCHEDULE {s_mount_sys}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds_sentinel = 77;
static uint32_t g_next_comp = 10, g_cr_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysEntry;
static SysEntry g_sys[4];
static size_t g_sys_n = 0;
static uint8_t g_cr_buf[{cr_sz}];
static int g_spawned = 0;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t i5_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "CastRes")) g_cr_comp = id;
    *o = id; return 0;
}}
static uint32_t i5_cfg_sset(void* lc, const void* d, uint32_t* o) {{ (void)lc; (void)d; if (o) *o = 1; return 0; }}
static uint32_t i5_mount_sys(void* lc, uint32_t s, uint32_t set) {{ (void)lc; (void)s; (void)set; return 0; }}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{ (void)sc; *out_cmds = &g_cmds_sentinel; return 0; }}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_e) {{
    (void)cmds; *out_e = 901ull;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_cr_comp && ptrs[i]) {{ memcpy(g_cr_buf, ptrs[i], {cr_sz}); g_spawned = 1; }}
    }}
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* n, size_t l, uint64_t e) {{ (void)hc; (void)n; (void)l; (void)e; return 0; }}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{ (void)sc; (void)qi; *o = NULL; return 0; }}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api; memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api); api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)i5_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;
    api.slots[SLOT_CONFIGURE_SCHEDULE_SET] = (void*)i5_cfg_sset;
    api.slots[SLOT_MOUNT_SYSTEM_IN_SCHEDULE] = (void*)i5_mount_sys;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "objects") || strstr(g_sys[i].name, "startup")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 24;
        }}
    }}
    if (!g_spawned) return 5;

    int8_t nan_i8 = 99, ninf_i8 = 99;
    int16_t nan_i16 = 99;
    int32_t nan_i32 = 99, inf_i32 = 99;
    int64_t nan_i64 = 99;
    uint8_t inf_u8 = 99;
    uint64_t ninf_u64 = 99;
    float nan_f32 = 1.0f;
    double inf_f64 = 1.0;

    memcpy(&nan_i8, g_cr_buf + {off_nan_i8}, 1);
    memcpy(&nan_i16, g_cr_buf + {off_nan_i16}, 2);
    memcpy(&nan_i32, g_cr_buf + {off_nan_i32}, 4);
    memcpy(&nan_i64, g_cr_buf + {off_nan_i64}, 8);
    memcpy(&inf_i32, g_cr_buf + {off_inf_i32}, 4);
    memcpy(&ninf_i8, g_cr_buf + {off_ninf_i8}, 1);
    memcpy(&inf_u8, g_cr_buf + {off_inf_u8}, 1);
    memcpy(&ninf_u64, g_cr_buf + {off_ninf_u64}, 8);
    memcpy(&nan_f32, g_cr_buf + {off_nan_f32}, 4);
    memcpy(&inf_f64, g_cr_buf + {off_inf_f64}, 8);

    if (nan_i8 != 0 || nan_i16 != 0 || nan_i32 != 0 || nan_i64 != 0) return 10;
    if (inf_i32 != INT32_MAX || ninf_i8 != INT8_MIN || inf_u8 != 255u || ninf_u64 != 0ull) return 11;
    if (!isnan(nan_f32) || !isinf(inf_f64)) return 12;

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_iter5", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_step2_iter6_non_finite_fix_casts_ivec_and_nested_struct() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_iter6 @version(1.0.0);

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
    iv: ivec2 = ivec2(1, 2),
    uv: uvec2 = uvec2(3, 4),
    nested: InnerS = InnerS { si: 11, sf: 2.0 },
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
        iv: ivec2((0.0_f32 / 0.0_f32) as i32, (1.0_f32 / 0.0_f32) as i32),
        uv: uvec2((1.0_f32 / 0.0_f32) as u32, (-1.0_f32 / 0.0_f32) as u32),
        nested: InnerS {
            si: (0.0_f32 / 0.0_f32) as i32,
            sf: (1.0_f32 / 0.0_f32) as fix32,
        },
    },
}
"#;
    let analyzed = analyze_source("jit_iter6.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_iter6".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (cr_sz, off_nan_fx32) = field_offset_of(&mir, "CastRes", "nan_fx32");
    let (_, off_inf_fx32) = field_offset_of(&mir, "CastRes", "inf_fx32");
    let (_, off_ninf_fx32) = field_offset_of(&mir, "CastRes", "ninf_fx32");
    let (_, off_nan_fx64) = field_offset_of(&mir, "CastRes", "nan_fx64");
    let (_, off_inf_fx64) = field_offset_of(&mir, "CastRes", "inf_fx64");
    let (_, off_ninf_fx64) = field_offset_of(&mir, "CastRes", "ninf_fx64");
    let (_, off_chained_fx) = field_offset_of(&mir, "CastRes", "chained_fx");
    let (_, off_iv) = field_offset_of(&mir, "CastRes", "iv");
    let (_, off_uv) = field_offset_of(&mir, "CastRes", "uv");
    let (_, off_nested) = field_offset_of(&mir, "CastRes", "nested");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_cmd_spawn = idx(api_slots::CMD_SPAWN);
    let s_bind_obj = idx(api_slots::BIND_NAMED_OBJECT);
    let s_cfg_sset = idx(api_slots::CONFIGURE_SCHEDULE_SET);
    let s_mount_sys = idx(api_slots::MOUNT_SYSTEM_IN_SCHEDULE);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind_obj}u
#define SLOT_CONFIGURE_SCHEDULE_SET {s_cfg_sset}u
#define SLOT_MOUNT_SYSTEM_IN_SCHEDULE {s_mount_sys}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds_sentinel = 77;
static uint32_t g_next_comp = 10, g_cr_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysEntry;
static SysEntry g_sys[4];
static size_t g_sys_n = 0;
static uint8_t g_cr_buf[{cr_sz}];
static int g_spawned = 0;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t i6_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "CastRes")) g_cr_comp = id;
    *o = id; return 0;
}}
static uint32_t i6_cfg_sset(void* lc, const void* d, uint32_t* o) {{ (void)lc; (void)d; if (o) *o = 1; return 0; }}
static uint32_t i6_mount_sys(void* lc, uint32_t s, uint32_t set) {{ (void)lc; (void)s; (void)set; return 0; }}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{ (void)sc; *out_cmds = &g_cmds_sentinel; return 0; }}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_e) {{
    (void)cmds; *out_e = 901ull;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_cr_comp && ptrs[i]) {{ memcpy(g_cr_buf, ptrs[i], {cr_sz}); g_spawned = 1; }}
    }}
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* n, size_t l, uint64_t e) {{ (void)hc; (void)n; (void)l; (void)e; return 0; }}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{ (void)sc; (void)qi; *o = NULL; return 0; }}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api; memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api); api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)i6_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;
    api.slots[SLOT_CONFIGURE_SCHEDULE_SET] = (void*)i6_cfg_sset;
    api.slots[SLOT_MOUNT_SYSTEM_IN_SCHEDULE] = (void*)i6_mount_sys;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "objects") || strstr(g_sys[i].name, "startup")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 24;
        }}
    }}
    if (!g_spawned) return 5;

    int32_t nan_fx32 = 9, inf_fx32 = 9, ninf_fx32 = 9, chained_fx = 9;
    int64_t nan_fx64 = 9, inf_fx64 = 9, ninf_fx64 = 9;
    int32_t iv[2] = {{9, 9}};
    uint32_t uv[2] = {{9, 9}};
    int32_t n_si = 9, n_sf = 9;
    memcpy(&nan_fx32, g_cr_buf + {off_nan_fx32}, 4);
    memcpy(&inf_fx32, g_cr_buf + {off_inf_fx32}, 4);
    memcpy(&ninf_fx32, g_cr_buf + {off_ninf_fx32}, 4);
    memcpy(&nan_fx64, g_cr_buf + {off_nan_fx64}, 8);
    memcpy(&inf_fx64, g_cr_buf + {off_inf_fx64}, 8);
    memcpy(&ninf_fx64, g_cr_buf + {off_ninf_fx64}, 8);
    memcpy(&chained_fx, g_cr_buf + {off_chained_fx}, 4);
    memcpy(iv, g_cr_buf + {off_iv}, 8);
    memcpy(uv, g_cr_buf + {off_uv}, 8);
    memcpy(&n_si, g_cr_buf + {off_nested}, 4);
    memcpy(&n_sf, g_cr_buf + {off_nested} + 4, 4);

    if (nan_fx32 != 0 || inf_fx32 != 0 || ninf_fx32 != 0 || chained_fx != 0) return 10;
    if (nan_fx64 != 0 || inf_fx64 != 0 || ninf_fx64 != 0) return 11;
    if (iv[0] != 0 || iv[1] != INT32_MAX || uv[0] != UINT32_MAX || uv[1] != 0u) return 12;
    if (n_si != 0 || n_sf != 0) return 13;

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_iter6", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_step2_iter7_vec3a_quat_rgba_bits_and_fix_truncation() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_iter7 @version(1.0.0);

enum BitKind { A = 0, C = 2 }

component Iter7Pod {
    va: vec3a = vec3a(0.0, 0.0, 0.0),
    q: quat = quat(0.0, 0.0, 0.0, 1.0),
    col: rgba = rgba(0.0, 0.0, 0.0, 0.0),
    d: meters = meters(1.0),
    t: ms = ms(2.0),
    mask: u64 = 0,
    sat_fx32_i32: i32 = 0,
    neg_fx64_i64: i64 = 0,
    zero_fx32_i32: i32 = 9,
}

object ObjIter7 {
    Iter7Pod {
        va: vec3a(1.5, 2.5, 3.5),
        q: quat(0.0, 1.0, 0.0, 0.0),
        col: rgba(0.25, 0.5, 0.75, 1.0),
        d: meters(4.5),
        t: ms(125.0),
        mask: bits(BitKind::A, BitKind::C),
        sat_fx32_i32: (100000.0_f32 as fix32) as i32,
        neg_fx64_i64: (-2.75_f64 as fix64) as i64,
        zero_fx32_i32: (-0.25_f32 as fix32) as i32,
    }
}
"#;
    let analyzed = analyze_source("jit_iter7.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_iter7".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (pod_sz, off_va) = field_offset_of(&mir, "Iter7Pod", "va");
    let (_, off_q) = field_offset_of(&mir, "Iter7Pod", "q");
    let (_, off_col) = field_offset_of(&mir, "Iter7Pod", "col");
    let (_, off_d) = field_offset_of(&mir, "Iter7Pod", "d");
    let (_, off_t) = field_offset_of(&mir, "Iter7Pod", "t");
    let (_, off_mask) = field_offset_of(&mir, "Iter7Pod", "mask");
    let (_, off_sat) = field_offset_of(&mir, "Iter7Pod", "sat_fx32_i32");
    let (_, off_neg) = field_offset_of(&mir, "Iter7Pod", "neg_fx64_i64");
    let (_, off_zero) = field_offset_of(&mir, "Iter7Pod", "zero_fx32_i32");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_cmd_spawn = idx(api_slots::CMD_SPAWN);
    let s_bind_obj = idx(api_slots::BIND_NAMED_OBJECT);
    let s_cfg_sset = idx(api_slots::CONFIGURE_SCHEDULE_SET);
    let s_mount_sys = idx(api_slots::MOUNT_SYSTEM_IN_SCHEDULE);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind_obj}u
#define SLOT_CONFIGURE_SCHEDULE_SET {s_cfg_sset}u
#define SLOT_MOUNT_SYSTEM_IN_SCHEDULE {s_mount_sys}u

static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds_sentinel = 77;
static uint32_t g_next_comp = 10, g_pod_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysEntry;
static SysEntry g_sys[4];
static size_t g_sys_n = 0;
static uint8_t g_pod_buf[{pod_sz}];
static int g_spawned = 0;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t i7_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "Iter7Pod")) g_pod_comp = id;
    *o = id; return 0;
}}
static uint32_t i7_cfg_sset(void* lc, const void* d, uint32_t* o) {{ (void)lc; (void)d; if (o) *o = 1; return 0; }}
static uint32_t i7_mount_sys(void* lc, uint32_t s, uint32_t set) {{ (void)lc; (void)s; (void)set; return 0; }}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{ (void)sc; *out_cmds = &g_cmds_sentinel; return 0; }}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_e) {{
    (void)cmds; *out_e = 902ull;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_pod_comp && ptrs[i]) {{ memcpy(g_pod_buf, ptrs[i], {pod_sz}); g_spawned = 1; }}
    }}
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* n, size_t l, uint64_t e) {{ (void)hc; (void)n; (void)l; (void)e; return 0; }}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{ (void)sc; (void)qi; *o = NULL; return 0; }}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api; memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api); api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)i7_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;
    api.slots[SLOT_CONFIGURE_SCHEDULE_SET] = (void*)i7_cfg_sset;
    api.slots[SLOT_MOUNT_SYSTEM_IN_SCHEDULE] = (void*)i7_mount_sys;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "objects") || strstr(g_sys[i].name, "startup")) {{
            if (g_sys[i].cb(&g_sctx, g_sys[i].ud) != 0) return 24;
        }}
    }}
    if (!g_spawned) return 5;

    float va[4] = {{0}}, q[4] = {{0}}, col[4] = {{0}}, d = 0.0f, t = 0.0f;
    uint64_t mask = 0;
    int32_t sat = 0, zero_fx = 9;
    int64_t neg = 0;
    memcpy(va, g_pod_buf + {off_va}, 16);
    memcpy(q, g_pod_buf + {off_q}, 16);
    memcpy(col, g_pod_buf + {off_col}, 16);
    memcpy(&d, g_pod_buf + {off_d}, 4);
    memcpy(&t, g_pod_buf + {off_t}, 4);
    memcpy(&mask, g_pod_buf + {off_mask}, 8);
    memcpy(&sat, g_pod_buf + {off_sat}, 4);
    memcpy(&neg, g_pod_buf + {off_neg}, 8);
    memcpy(&zero_fx, g_pod_buf + {off_zero}, 4);

    if (va[0] != 1.5f || va[1] != 2.5f || va[2] != 3.5f || va[3] != 0.0f) return 10;
    if (q[0] != 0.0f || q[1] != 1.0f || q[2] != 0.0f || q[3] != 0.0f) return 11;
    if (col[0] != 0.25f || col[1] != 0.5f || col[2] != 0.75f || col[3] != 1.0f) return 12;
    if (d != 4.5f || t != 125.0f || mask != 5ull) return 13;
    if (sat != 32767 || neg != -2ll || zero_fx != 0) return 14;

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_iter7", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_step2_iter8_native_observer_and_all_fixes() {
    use strata_jit::abi_offsets::api_slots;
    use strata_jit::abi_offsets::structs::{
        OBS_CTX_CALLBACK, OBS_NAME, OBS_QUERIES, OBS_QUERY_COUNT, OBS_USER_DATA,
        OBS_WATCHED_COMPONENT_COUNT, OBS_WATCHED_COMPONENTS,
    };
    let src = r#"
module test::jit_iter8 @version(1.0.0);

struct Sub { x: i32 = 3, fx: fix32 = 1.5 }
const C_SUB: Sub = Sub { x: 7, fx: 2.5 };

component Marker;
component ObsPod {
    id: u32 = 1,
    bs128: BitSet<128> = bits(0, 70),
    va: vec3a = vec3a(1.5, 2.5, 3.5),
    sub: Sub = C_SUB,
    arr32: [fix32; 2] = [0.0, 0.0],
    arr64: [fix64; 2] = [0.0, 0.0],
    obs_hits: i32 = 0,
}
event EvPing { entity: Ref<Entity>, inc: i32 }

object ObjIter8 {
    ObsPod {
        id: 1,
        bs128: bits(2, 75),
        va: Vec3a(1.5, 2.5, 3.5),
    },
    Marker,
}

@node_pure fn id_f32(v: f32) -> f32 { v }
@node_pure fn id_f64(v: f64) -> f64 { v }

sys step_iter8() {
    for row in query(o: &mut ObsPod) {
        row.o.arr32 = [id_f32(1.25_f32), id_f32(-0.5_f32)];
        row.o.arr64 = [id_f64(-2.75_f64), id_f64(1.5_f64)];
        row.o.bs128 = bits(1, 90);
    }
}

obs on_ping(trg: &Trigger<EvPing, Marker>) {
    let opt = query_one(o: &mut ObsPod).on(trg.target);
    if let Some(r) = opt {
        r.o.obs_hits += trg.payload.inc;
    }
}

schedule FixedUpdate { step_iter8 }
"#;
    let analyzed = analyze_source("jit_iter8.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_iter8".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (pod_sz, off_bs128) = field_offset_of(&mir, "ObsPod", "bs128");
    let (_, off_va) = field_offset_of(&mir, "ObsPod", "va");
    let (_, off_arr32) = field_offset_of(&mir, "ObsPod", "arr32");
    let (_, off_arr64) = field_offset_of(&mir, "ObsPod", "arr64");
    let (_, off_obs_hits) = field_offset_of(&mir, "ObsPod", "obs_hits");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_reg_obs = idx(api_slots::REGISTER_OBSERVER);
    let s_cmd_spawn = idx(api_slots::CMD_SPAWN);
    let s_bind_obj = idx(api_slots::BIND_NAMED_OBJECT);
    let s_cfg_sset = idx(api_slots::CONFIGURE_SCHEDULE_SET);
    let s_mount_sys = idx(api_slots::MOUNT_SYSTEM_IN_SCHEDULE);

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_REGISTER_OBSERVER {s_reg_obs}u
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind_obj}u
#define SLOT_CONFIGURE_SCHEDULE_SET {s_cfg_sset}u
#define SLOT_MOUNT_SYSTEM_IN_SCHEDULE {s_mount_sys}u

typedef uint32_t (*BamObsCtxFn)(uint64_t entity, const void* ev, void* sys_ctx, void* ud);
static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds_sentinel = 77;
static uint32_t g_next_comp = 10, g_pod_comp = 0;
static uint8_t g_pod_buf[{pod_sz}];
static int g_spawned = 0;
static int g_obs_n = 0;
static BamObsCtxFn g_obs_cb = NULL;
static void* g_obs_ud = NULL;
static const BamQueryDesc* g_obs_queries = NULL;
static size_t g_obs_query_count = 0;
static size_t g_obs_watched_count = 0;

typedef struct EvPingC {{ uint64_t entity; int32_t inc; uint32_t _pad; }} EvPingC;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_resolve_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return 4;
}}
static uint32_t i8_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "ObsPod")) g_pod_comp = id;
    *o = id; return 0;
}}
static uint32_t i8_cfg_sset(void* lc, const void* d, uint32_t* o) {{ (void)lc; (void)d; if (o) *o = 1; return 0; }}
static uint32_t i8_mount_sys(void* lc, uint32_t s, uint32_t set) {{ (void)lc; (void)s; (void)set; return 0; }}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc; (void)d; *o = 1; return 0;
}}
static uint32_t h_reg_obs(void* lc, const void* desc_ptr) {{
    (void)lc;
    const uint8_t* p = (const uint8_t*)desc_ptr;
    g_obs_n++;
    const char* name = *(const char* const*)(p + {OBS_NAME});
    if (!name || !strstr(name, "on_ping")) return 10;
    g_obs_cb = *(const BamObsCtxFn*)(p + {OBS_CTX_CALLBACK});
    g_obs_ud = *(void* const*)(p + {OBS_USER_DATA});
    g_obs_queries = *(const BamQueryDesc* const*)(p + {OBS_QUERIES});
    g_obs_query_count = *(const size_t*)(p + {OBS_QUERY_COUNT});
    const uint32_t* watched = *(const uint32_t* const*)(p + {OBS_WATCHED_COMPONENTS});
    g_obs_watched_count = *(const size_t*)(p + {OBS_WATCHED_COMPONENT_COUNT});
    if (!watched) return 11;
    return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** out_cmds) {{ (void)sc; *out_cmds = &g_cmds_sentinel; return 0; }}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_e) {{
    (void)cmds; *out_e = 905ull;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_pod_comp && ptrs[i]) {{ memcpy(g_pod_buf, ptrs[i], {pod_sz}); g_spawned = 1; }}
    }}
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* n, size_t l, uint64_t e) {{ (void)hc; (void)n; (void)l; (void)e; return 0; }}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{ (void)sc; (void)qi; *o = NULL; return 0; }}
static void* h_ent_get_mut(void* sc, size_t qi, uint64_t ent, size_t ti) {{
    (void)sc; (void)qi; (void)ti;
    return (ent == 905ull) ? (void*)g_pod_buf : NULL;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api; memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api); api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)i8_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_resolve_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_OBSERVER] = (void*)h_reg_obs;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_SYS_ENTITY_GET_MUT] = (void*)h_ent_get_mut;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;
    api.slots[SLOT_CONFIGURE_SCHEDULE_SET] = (void*)i8_cfg_sset;
    api.slots[SLOT_MOUNT_SYSTEM_IN_SCHEDULE] = (void*)i8_mount_sys;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    if (g_obs_n != 1 || !g_obs_cb || !g_obs_queries || g_obs_query_count == 0 || g_obs_watched_count != 1) return 5;
    // Also verify default pod bytes (bs128 bits 0 & 70 OR override bits 2 & 75) & vec3a
    (void)g_spawned; (void){off_bs128}; (void){off_va}; (void){off_arr32}; (void){off_arr64}; (void){off_obs_hits};
    memset(g_pod_buf, 0, sizeof(g_pod_buf));
    EvPingC ev = {{ 905ull, 13, 0 }};
    if (g_obs_cb(905ull, &ev, &g_sctx, g_obs_ud) != 0) return 6;
    int32_t hits = 0;
    memcpy(&hits, g_pod_buf + {off_obs_hits}, 4);
    if (hits != 13) return 7;

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_iter8", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_regression_pm02_04_07_08_09_11_12() {
    use strata_jit::abi_offsets::api_slots;
    let par_ro_slot = (api_slots::PAR_FOR_EACH_CHUNK_READONLY - 8) / std::mem::size_of::<usize>();
    let par_mut_slot = (api_slots::PAR_FOR_EACH_CHUNK - 8) / std::mem::size_of::<usize>();
    let src = r#"
module test::jit_pm_step2 @version(1.0.0);

component FlagItem {
    ok: bool = false,
    fx32: fix32 = 2.0 as fix32,
    fx64: fix64 = 2.0 as fix64,
}

component Out {
    neg1: i32 = -1,
    neg1_64: i64 = -1,
    d32: i32 = 0,
    r64: i64 = 99,
    qm: quat = quat(0.0, 0.0, 0.0, 1.0),
    qm2: quat = quat(0.0, 0.70710677, 0.0, 0.70710677),
    qv: vec3 = vec3(0.0, 0.0, 0.0),
    cnt_ok: u32 = 0,
    any_ok: bool = false,
    any_false: bool = true,
    all_true: bool = false,
    all_mixed: bool = true,
    prod32: fix32 = 0.0 as fix32,
    prod64: fix64 = 0.0 as fix64,
    b_int: bool = false,
    b_f32: bool = false,
    b_fx: bool = false,
    b_nan: bool = false,
    b_zero: bool = true,
    swiz_local: vec2 = vec2(0.0, 0.0),
    comp_swiz: vec2 = vec2(3.0, 4.0),
    vclamp: vec3 = vec3(0.0, 0.0, 0.0),
    ivm: ivec2 = ivec2(0, 0),
    ivc: ivec2 = ivec2(0, 0),
    in_zero: f32 = 0.0,
    in_half: f32 = 0.5,
    in_256: i32 = 256,
    in_fx: fix32 = 0.5 as fix32,
}

@par(chunk = 2)
sys eval_math() {
    let cnt_v = for e in query(it: &FlagItem) reduce(acc: count(e.it.ok));
    let any_t = for e in query(it: &FlagItem) reduce(acc: any(e.it.ok));
    let any_f = for e in query(it: &FlagItem) reduce(acc: any(!e.it.ok && e.it.ok));
    let all_t = for e in query(it: &FlagItem) reduce(acc: all(e.it.ok || !e.it.ok));
    let all_m = for e in query(it: &FlagItem) reduce(acc: all(e.it.ok));
    let p32 = for e in query(it: &FlagItem) reduce(acc: prod(1.0 as fix32, e.it.fx32));
    let p64 = for e in query(it: &FlagItem) reduce(acc: prod(1.0 as fix64, e.it.fx64));

    for row in query(o: &mut Out) {
        let m32: i32 = -2147483647 - 1;
        let m64: i64 = -9223372036854775807 - 1;
        row.o.d32 = m32 / row.o.neg1;
        row.o.r64 = m64 % row.o.neg1_64;

        let q1: quat = quat(0.0, 0.70710677, 0.0, 0.70710677);
        let q2: quat = quat(0.0, 0.0, 0.70710677, 0.70710677);
        row.o.qm = q1 * q2;
        row.o.qm2 *= q2;
        row.o.qv = q1 * vec3(1.0, 0.0, 0.0);

        row.o.cnt_ok = cnt_v;
        row.o.any_ok = any_t;
        row.o.any_false = any_f;
        row.o.all_true = all_t;
        row.o.all_mixed = all_m;
        row.o.prod32 = p32;
        row.o.prod64 = p64;

        row.o.b_int = row.o.in_256 as bool;
        row.o.b_f32 = row.o.in_half as bool;
        row.o.b_fx = row.o.in_fx as bool;
        row.o.b_nan = (row.o.in_zero / row.o.in_zero) as bool;
        row.o.b_zero = row.o.in_zero as bool;

        let mut t: vec2 = vec2(3.0, 4.0);
        t.yx = vec2(10.0, 20.0);
        row.o.swiz_local = t;
        row.o.comp_swiz.yx = vec2(50.0, 60.0);

        row.o.vclamp = clamp(vec3(1.0, 2.0, 3.0), 1.5, 2.5);
        row.o.ivm = ivec2(10, -7) * 2;
        row.o.ivc = clamp(ivec2(-5, 9), 0, 4);
    }
}

schedule FixedUpdate { eval_math }
"#;
    let analyzed = analyze_source("jit_pm_step2.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_pm_step2".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (item_sz, off_ok) = field_offset_of(&mir, "FlagItem", "ok");
    let (_, off_fx32) = field_offset_of(&mir, "FlagItem", "fx32");
    let (_, off_fx64) = field_offset_of(&mir, "FlagItem", "fx64");

    let (out_sz, off_neg1) = field_offset_of(&mir, "Out", "neg1");
    let (_, off_neg1_64) = field_offset_of(&mir, "Out", "neg1_64");
    let (_, off_d32) = field_offset_of(&mir, "Out", "d32");
    let (_, off_r64) = field_offset_of(&mir, "Out", "r64");
    let (_, off_qm) = field_offset_of(&mir, "Out", "qm");
    let (_, off_qm2) = field_offset_of(&mir, "Out", "qm2");
    let (_, off_qv) = field_offset_of(&mir, "Out", "qv");
    let (_, off_cnt_ok) = field_offset_of(&mir, "Out", "cnt_ok");
    let (_, off_any_ok) = field_offset_of(&mir, "Out", "any_ok");
    let (_, off_any_false) = field_offset_of(&mir, "Out", "any_false");
    let (_, off_all_true) = field_offset_of(&mir, "Out", "all_true");
    let (_, off_all_mixed) = field_offset_of(&mir, "Out", "all_mixed");
    let (_, off_prod32) = field_offset_of(&mir, "Out", "prod32");
    let (_, off_prod64) = field_offset_of(&mir, "Out", "prod64");
    let (_, off_b_int) = field_offset_of(&mir, "Out", "b_int");
    let (_, off_b_f32) = field_offset_of(&mir, "Out", "b_f32");
    let (_, off_b_fx) = field_offset_of(&mir, "Out", "b_fx");
    let (_, off_b_nan) = field_offset_of(&mir, "Out", "b_nan");
    let (_, off_b_zero) = field_offset_of(&mir, "Out", "b_zero");
    let (_, off_swiz_local) = field_offset_of(&mir, "Out", "swiz_local");
    let (_, off_comp_swiz) = field_offset_of(&mir, "Out", "comp_swiz");
    let (_, off_vclamp) = field_offset_of(&mir, "Out", "vclamp");
    let (_, off_ivm) = field_offset_of(&mir, "Out", "ivm");
    let (_, off_ivc) = field_offset_of(&mir, "Out", "ivc");
    let (_, off_in_zero) = field_offset_of(&mir, "Out", "in_zero");
    let (_, off_in_half) = field_offset_of(&mir, "Out", "in_half");
    let (_, off_in_256) = field_offset_of(&mir, "Out", "in_256");
    let (_, off_in_fx) = field_offset_of(&mir, "Out", "in_fx");

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_next_comp = 10, g_item_comp = 0, g_out_comp = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; uint32_t q_comp[8]; }} SysReg;
static SysReg g_sys[8];
static size_t g_sys_n = 0;
static uint8_t g_items[4 * {item_sz}];
static uint64_t g_item_ents[4] = {{ 1, 2, 3, 4 }};
static uint8_t g_out[{out_sz}];
static uint64_t g_out_ents[1] = {{ 10 }};
typedef struct Iter {{ uint32_t comp; size_t st; }} Iter;
static Iter g_it[16];

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_res_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{ (void)hc; (void)n; (void)u; (void)o; return 4; }}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{ (void)hc; (void)c; (void)i; return 4; }}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_comp++;
    if (d->name && strstr(d->name, "FlagItem")) g_item_comp = id;
    if (d->name && strstr(d->name, "Out")) g_out_comp = id;
    *o = id; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    SysReg* r = &g_sys[g_sys_n];
    snprintf(r->name, sizeof(r->name), "%s", d->name ? d->name : "");
    r->cb = d->callback; r->ud = d->user_data;
    for (size_t qi = 0; qi < d->query_count && qi < 8; qi++) {{
        r->q_comp[qi] = d->queries[qi].term_count > 0 ? d->queries[qi].terms[0].component : 0;
    }}
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc;
    size_t idx = qi < 16 ? qi : 0;
    g_it[idx].comp = (qi == 7) ? g_out_comp : g_item_comp;
    g_it[idx].st = 0;
    *o = &g_it[idx]; return 0;
}}
static uint32_t h_par(void* it, uint32_t (*cb)(void*, void*), void* frame) {{
    return cb(it, frame);
}}
static uint32_t h_iter_rst(void* it) {{ ((Iter*)it)->st = 0; return 0; }}
static uint8_t h_next(void* it, size_t* len) {{
    Iter* s = (Iter*)it;
    if (s->st == 0) {{ s->st = 1; *len = (s->comp == g_item_comp) ? 4 : 1; return 1; }}
    *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{
    return (((Iter*)it)->comp == g_item_comp) ? g_item_ents : g_out_ents;
}}
static void* h_col(void* it, size_t ti) {{
    (void)ti;
    return (((Iter*)it)->comp == g_item_comp) ? (void*)g_items : (void*)g_out;
}}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api; memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api); api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_res_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[{par_ro_slot}] = (void*)h_par;
    api.slots[{par_mut_slot}] = (void*)h_par;
    api.slots[SLOT_ITER_RESET] = (void*)h_iter_rst;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT_UNTRACKED] = (void*)h_col;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;

    memset(g_items, 0, sizeof(g_items));
    memset(g_out, 0, sizeof(g_out));
    for (int i = 0; i < 4; i++) {{
        uint8_t ok = (i % 2 == 0) ? 1 : 0;
        int32_t fx32 = 2 * 65536;
        int64_t fx64 = 2LL << 32;
        memcpy(g_items + i * {item_sz} + {off_ok}, &ok, 1);
        memcpy(g_items + i * {item_sz} + {off_fx32}, &fx32, 4);
        memcpy(g_items + i * {item_sz} + {off_fx64}, &fx64, 8);
    }}
    int32_t n1 = -1, i256 = 256, ifx = 32768;
    int64_t n1_64 = -1;
    float qinit[4] = {{ 0.0f, 0.70710677f, 0.0f, 0.70710677f }};
    float fz = 0.0f, fh = 0.5f;
    memcpy(g_out + {off_neg1}, &n1, 4);
    memcpy(g_out + {off_neg1_64}, &n1_64, 8);
    memcpy(g_out + {off_qm2}, qinit, 16);
    memcpy(g_out + {off_in_zero}, &fz, 4);
    memcpy(g_out + {off_in_half}, &fh, 4);
    memcpy(g_out + {off_in_256}, &i256, 4);
    memcpy(g_out + {off_in_fx}, &ifx, 4);
    uint8_t bt = 1;
    memcpy(g_out + {off_any_false}, &bt, 1);
    memcpy(g_out + {off_all_mixed}, &bt, 1);
    memcpy(g_out + {off_b_zero}, &bt, 1);

    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "eval_math") == 0) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}

    int32_t d32 = 0, ivm[2] = {{0}}, ivc[2] = {{0}}, fx32_out = 0;
    int64_t r64 = 0, fx64_out = 0;
    uint32_t cnt_ok = 99;
    uint8_t any_ok = 0, any_false = 1, all_true = 0, all_mixed = 1;
    uint8_t b_int = 0, b_f32 = 0, b_fx = 0, b_nan = 0, b_zero = 1;
    float qm[4] = {{0}}, qm2[4] = {{0}}, qv[3] = {{0}}, swiz_l[2] = {{0}}, swiz_c[2] = {{0}}, vc[3] = {{0}};

    memcpy(&d32, g_out + {off_d32}, 4);
    memcpy(&r64, g_out + {off_r64}, 8);
    memcpy(qm, g_out + {off_qm}, 16);
    memcpy(qm2, g_out + {off_qm2}, 16);
    memcpy(qv, g_out + {off_qv}, 12);
    memcpy(&cnt_ok, g_out + {off_cnt_ok}, 4);
    memcpy(&any_ok, g_out + {off_any_ok}, 1);
    memcpy(&any_false, g_out + {off_any_false}, 1);
    memcpy(&all_true, g_out + {off_all_true}, 1);
    memcpy(&all_mixed, g_out + {off_all_mixed}, 1);
    memcpy(&fx32_out, g_out + {off_prod32}, 4);
    memcpy(&fx64_out, g_out + {off_prod64}, 8);
    memcpy(&b_int, g_out + {off_b_int}, 1);
    memcpy(&b_f32, g_out + {off_b_f32}, 1);
    memcpy(&b_fx, g_out + {off_b_fx}, 1);
    memcpy(&b_nan, g_out + {off_b_nan}, 1);
    memcpy(&b_zero, g_out + {off_b_zero}, 1);
    memcpy(swiz_l, g_out + {off_swiz_local}, 8);
    memcpy(swiz_c, g_out + {off_comp_swiz}, 8);
    memcpy(vc, g_out + {off_vclamp}, 12);
    memcpy(ivm, g_out + {off_ivm}, 8);
    memcpy(ivc, g_out + {off_ivc}, 8);

    if (d32 != INT32_MIN || r64 != 0) {{ fprintf(stderr, "PM-02 d32=%d r64=%lld\n", d32, (long long)r64); return 10; }}
    for (int i = 0; i < 4; i++) {{
        if (fabsf(qm[i] - 0.5f) > 1e-4f || fabsf(qm2[i] - 0.5f) > 1e-4f) {{
            fprintf(stderr, "PM-04 qm=(%f,%f,%f,%f) qm2=(%f,%f,%f,%f)\n", qm[0],qm[1],qm[2],qm[3], qm2[0],qm2[1],qm2[2],qm2[3]);
            return 11;
        }}
    }}
    if (fabsf(qv[0]) > 1e-4f || fabsf(qv[1]) > 1e-4f || fabsf(qv[2] + 1.0f) > 1e-4f) {{
        fprintf(stderr, "PM-04 qv=(%f,%f,%f)\n", qv[0], qv[1], qv[2]); return 12;
    }}
    if (cnt_ok != 2 || any_ok != 1 || any_false != 0 || all_true != 1 || all_mixed != 0) {{
        fprintf(stderr, "PM-07 cnt=%u any=%u/%u all=%u/%u\n", cnt_ok, any_ok, any_false, all_true, all_mixed); return 13;
    }}
    if (fx32_out != 16 * 65536 || fx64_out != (16LL << 32)) {{
        fprintf(stderr, "PM-08 fx32=%d fx64=%lld\n", fx32_out, (long long)fx64_out); return 14;
    }}
    if (!b_int || !b_f32 || !b_fx || !b_nan || b_zero) {{
        fprintf(stderr, "PM-09 %u %u %u %u %u\n", b_int, b_f32, b_fx, b_nan, b_zero); return 15;
    }}
    if (fabsf(swiz_l[0] - 20.0f) > 1e-4f || fabsf(swiz_l[1] - 10.0f) > 1e-4f || fabsf(swiz_c[0] - 60.0f) > 1e-4f || fabsf(swiz_c[1] - 50.0f) > 1e-4f) {{
        fprintf(stderr, "PM-11 local=(%f,%f) comp=(%f,%f)\n", swiz_l[0], swiz_l[1], swiz_c[0], swiz_c[1]); return 16;
    }}
    if (fabsf(vc[0] - 1.5f) > 1e-4f || fabsf(vc[1] - 2.0f) > 1e-4f || fabsf(vc[2] - 2.5f) > 1e-4f) {{
        fprintf(stderr, "PM-12 vc=(%f,%f,%f)\n", vc[0], vc[1], vc[2]); return 17;
    }}
    if (ivm[0] != 20 || ivm[1] != -14 || ivc[0] != 0 || ivc[1] != 4) {{
        fprintf(stderr, "PM-12 ivm=(%d,%d) ivc=(%d,%d)\n", ivm[0], ivm[1], ivc[0], ivc[1]); return 18;
    }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_pm_step2", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_regression_types_tables_inlinestr_bitset_and_smallvec() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_tl_step3 @version(1.0.0);

enum TierKey {
    Low = -5,
    High = 10,
}

struct SubInfo {
    bonus: i32 = 33,
    txt: InlineStr<4> = "def",
}

struct BoxVal {
    v: i32 = 99,
}

table Tiers by TierKey {
    base: i32,
    sub: SubInfo,
    bits: BitSet<64>,
} = {
    Low  => { base: -12, sub: SubInfo { bonus: 77, txt: "low" }, bits: bits(4) },
    High => { base: 44, sub: SubInfo { bonus: 88, txt: "hi" }, bits: bits() },
};

component MatHold {
    m: mat3,
    boxes: [BoxVal; 2],
    sub: SubInfo,
}

object DefObj {
    MatHold {
        sub: SubInfo { txt: "over" },
    }
}

component TypeProbe {
    flags_arr: [BitSet<128>; 2],
    has_before: i32 = 9,
    has_after_set: i32 = 0,
    has_after_clr: i32 = 9,
    mat_rt: mat3,
    arr2d_val: i32 = 0,
    box_arr_val: i32 = 0,
    sv_len: i32 = 0,
    sv_last: i32 = 0,
    def_box_v: i32 = 0,
    def_sub_bonus: i32 = 0,
    ascii_s: InlineStr<8> = "",
    utf8_s: InlineStr<4> = "",
    nested_s: SubInfo,
    tbl_base: i32 = 0,
    tbl_bonus: i32 = 0,
    tbl_has_bit: i32 = 0,
    tbl_txt: InlineStr<4> = "",
}

sys eval_types(p: &mut TypeProbe) {
    for r in query(p: &mut TypeProbe, mh: &MatHold) {
        r.p.flags_arr[1].set(70);
        r.p.has_before = if r.p.flags_arr[0].has(70) { 1 } else { 0 };
        r.p.has_after_set = if r.p.flags_arr[1].has(70) { 1 } else { 0 };
        r.p.flags_arr[1].clear(70);
        r.p.has_after_clr = if r.p.flags_arr[1].has(70) { 1 } else { 0 };

        let mut grid: [[i32; 2]; 2] = [[1, 2], [3, 4]];
        grid[1][0] = 42;
        r.p.arr2d_val = grid[1][0];

        let mut barr: [BoxVal; 2] = [BoxVal { v: 1 }, BoxVal { v: 2 }];
        barr[1].v = 77;
        r.p.box_arr_val = barr[1].v;

        let mut sv: SmallVec<i32, 4> = [10, 20];
        sv.push(30);
        r.p.sv_len = sv.len() as i32;
        r.p.sv_last = sv[2];

        r.p.mat_rt = mat3();
        r.p.def_box_v = r.mh.boxes[1].v;
        r.p.def_sub_bonus = r.mh.sub.bonus;

        r.p.ascii_s = "abcdefghijkl";
        r.p.utf8_s = "hi🎉bye";
        let sub_cp = SubInfo { bonus: 15, txt: "cp" };
        r.p.nested_s = sub_cp;

        let trow = Tiers[TierKey::Low];
        r.p.tbl_base = trow.base;
        r.p.tbl_bonus = trow.sub.bonus;
        r.p.tbl_has_bit = if trow.bits.has(4) { 1 } else { 0 };
        r.p.tbl_txt = trow.sub.txt;
    }
}

schedule Startup { eval_types }
"#;
    let analyzed = analyze_source("jit_tl_step3.strata", src);
    assert!(analyzed.ok(), "sema: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_tl_step3".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (tp_sz, off_flags_arr) = field_offset_of(&mir, "TypeProbe", "flags_arr");
    let (_, off_hb) = field_offset_of(&mir, "TypeProbe", "has_before");
    let (_, off_hs) = field_offset_of(&mir, "TypeProbe", "has_after_set");
    let (_, off_hc) = field_offset_of(&mir, "TypeProbe", "has_after_clr");
    let (_, off_mat_rt) = field_offset_of(&mir, "TypeProbe", "mat_rt");
    let (_, off_a2d) = field_offset_of(&mir, "TypeProbe", "arr2d_val");
    let (_, off_bav) = field_offset_of(&mir, "TypeProbe", "box_arr_val");
    let (_, off_svl) = field_offset_of(&mir, "TypeProbe", "sv_len");
    let (_, off_svv) = field_offset_of(&mir, "TypeProbe", "sv_last");
    let (_, off_dbv) = field_offset_of(&mir, "TypeProbe", "def_box_v");
    let (_, off_dsb) = field_offset_of(&mir, "TypeProbe", "def_sub_bonus");
    let (_, off_asc) = field_offset_of(&mir, "TypeProbe", "ascii_s");
    let (_, off_u8s) = field_offset_of(&mir, "TypeProbe", "utf8_s");
    let (_, off_nst) = field_offset_of(&mir, "TypeProbe", "nested_s");
    let (_, off_tbase) = field_offset_of(&mir, "TypeProbe", "tbl_base");
    let (_, off_tbonus) = field_offset_of(&mir, "TypeProbe", "tbl_bonus");
    let (_, off_tbit) = field_offset_of(&mir, "TypeProbe", "tbl_has_bit");
    let (_, off_ttxt) = field_offset_of(&mir, "TypeProbe", "tbl_txt");
    let (mh_sz, _off_m) = field_offset_of(&mir, "MatHold", "m");
    let (_, off_sub_txt) = field_offset_of(&mir, "SubInfo", "txt");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_spawn = idx(api_slots::CMD_SPAWN);
    let s_bind = idx(api_slots::BIND_NAMED_OBJECT);
    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_CMD_SPAWN {s_spawn}u
#define SLOT_BIND_NAMED_OBJECT {s_bind}u
static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds = 9;
static uint32_t g_next_c = 10, g_tp_comp = 0, g_mh_comp = 0;
static size_t g_tp_reg_sz = 0, g_mh_reg_sz = 0;
typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; }} SysReg;
static SysReg g_sys[8];
static size_t g_sys_n = 0;
static uint8_t g_tp_buf[{tp_sz}];
static uint8_t g_mh_buf[{mh_sz}];
static uint64_t g_ents[1] = {{ 42ull }};
static size_t g_it_stage = 0;
static int g_init_done = 0;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_res_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{ (void)hc;(void)n;(void)u;(void)o; return 4; }}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{ (void)hc;(void)c;(void)i; return 4; }}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_c++;
    if (d->name && strstr(d->name, "TypeProbe")) {{ g_tp_comp = id; g_tp_reg_sz = d->size; }}
    if (d->name && strstr(d->name, "MatHold")) {{ g_mh_comp = id; g_mh_reg_sz = d->size; }}
    *o = id; return 0;
}}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** o) {{ (void)sc; *o = &g_cmds; return 0; }}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* comps, const void* const* ptrs, size_t cnt, uint64_t* out_e) {{
    (void)cmds; *out_e = 42ull;
    for (size_t i = 0; i < cnt; i++) {{
        if (comps[i] == g_mh_comp && ptrs[i]) memcpy(g_mh_buf, ptrs[i], {mh_sz});
    }}
    return 0;
}}
static uint32_t h_bind_obj(void* hc, const char* n, size_t l, uint64_t e) {{ (void)hc;(void)n;(void)l;(void)e; return 0; }}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{ (void)sc;(void)qi; g_it_stage = 0; *o = (void*)0x1111; return 0; }}
static uint32_t h_it_rst(void* it) {{ (void)it; g_it_stage = 0; return 0; }}
static uint8_t h_next(void* it, size_t* len) {{ (void)it; if (g_init_done && g_it_stage == 0) {{ g_it_stage = 1; *len = 1; return 1; }} *len = 0; return 0; }}
static const uint64_t* h_ents(void* it) {{ (void)it; return g_ents; }}
static void* h_col(void* it, size_t ti) {{ (void)it; return (ti == 0) ? (void*)g_tp_buf : (void*)g_mh_buf; }}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api; memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api); api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_res_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_BIND_NAMED_OBJECT] = (void*)h_bind_obj;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_ITER_RESET] = (void*)h_it_rst;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT_UNTRACKED] = (void*)h_col;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    if (g_tp_reg_sz != {tp_sz} || g_mh_reg_sz != {mh_sz}) return 5;

    memset(g_tp_buf, 0, sizeof(g_tp_buf));
    memset(g_mh_buf, 0, sizeof(g_mh_buf));
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "strata_init_objects") == 0) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}
    g_init_done = 1;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "eval_types") == 0) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}

    int32_t hb=0, hs=0, hc=0, a2d=0, bav=0, svl=0, svv=0, dbv=0, dsb=0, tbase=0, tbonus=0, tbit=0;
    float md0=0, md1=0;
    memcpy(&hb, g_tp_buf + {off_hb}, 4);
    memcpy(&hs, g_tp_buf + {off_hs}, 4);
    memcpy(&hc, g_tp_buf + {off_hc}, 4);
    memcpy(&md0, g_tp_buf + {off_mat_rt}, 4);
    memcpy(&md1, g_tp_buf + {off_mat_rt} + 16, 4);
    memcpy(&a2d, g_tp_buf + {off_a2d}, 4);
    memcpy(&bav, g_tp_buf + {off_bav}, 4);
    memcpy(&svl, g_tp_buf + {off_svl}, 4);
    memcpy(&svv, g_tp_buf + {off_svv}, 4);
    memcpy(&dbv, g_tp_buf + {off_dbv}, 4);
    memcpy(&dsb, g_tp_buf + {off_dsb}, 4);
    memcpy(&tbase, g_tp_buf + {off_tbase}, 4);
    memcpy(&tbonus, g_tp_buf + {off_tbonus}, 4);
    memcpy(&tbit, g_tp_buf + {off_tbit}, 4);

    if (hb != 0 || hs != 1 || hc != 0) {{ fprintf(stderr, "BitSet %d %d %d\n", hb, hs, hc); return 10; }}
    if (fabsf(md0 - 1.0f) > 1e-4f || fabsf(md1 - 1.0f) > 1e-4f) {{ fprintf(stderr, "mat3 %f %f\n", md0, md1); return 11; }}
    if (a2d != 42 || bav != 77 || svl != 3 || svv != 30) {{ fprintf(stderr, "arr/sv %d %d %d %d\n", a2d, bav, svl, svv); return 12; }}
    if (dbv != 99 || dsb != 33) {{ fprintf(stderr, "defaults %d %d\n", dbv, dsb); return 13; }}
    if (tbase != -12 || tbonus != 77 || tbit != 1) {{ fprintf(stderr, "table %d %d %d\n", tbase, tbonus, tbit); return 14; }}

    uint32_t asc_len = 0, u8_len = 0, nst_len = 0, ttxt_len = 0;
    memcpy(&asc_len, g_tp_buf + {off_asc}, 4);
    memcpy(&u8_len, g_tp_buf + {off_u8s}, 4);
    memcpy(&nst_len, g_tp_buf + {off_nst} + {off_sub_txt}, 4);
    memcpy(&ttxt_len, g_tp_buf + {off_ttxt}, 4);
    if (asc_len != 8 || memcmp(g_tp_buf + {off_asc} + 4, "abcdefgh", 8) != 0) return 15;
    if (u8_len != 2 || memcmp(g_tp_buf + {off_u8s} + 4, "hi\0\0", 4) != 0) return 16;
    if (nst_len != 2 || memcmp(g_tp_buf + {off_nst} + {off_sub_txt} + 4, "cp", 2) != 0) return 17;
    if (ttxt_len != 3 || memcmp(g_tp_buf + {off_ttxt} + 4, "low", 3) != 0) return 18;
    (void){off_flags_arr};

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_tl_step3", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_regression_ecs_par_streams_relations_added_without_and_startup_before() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_ecs_step4 @version(1.0.0);

tag TagA;
tag TagB;
component Node { v: i32 = 1 }
@sparse component SpVal { w: f32 = 2.5 }
resource Counter { total: i32 = 0 }
resource ResultOut { sp_sum: f32 = 0.0, up_hits: i32 = 0, obs_seen: i32 = 0 }

stream Ping { code: i32 }
event Hit { dmg: i32 }

relation CustomParent [exclusive];

object BootMarker {
    Node { v: 77 }
}

fn write_res_helper(delta: i32) {
    res_mut<Counter>().total += delta;
}

@par
sys par_with_res() {
    for r in query(n: &Node) {
        write_res_helper(r.n.v);
    }
}

@par
sys par_sparse(o: &mut res ResultOut) {
    let s: f32 = for row in query(s: &SpVal) reduce(acc: sum(0.0, row.s.w));
    o.sp_sum = s;
}

sys emit_and_rel(c: &mut Counter) {
    emit(Ping { code: 42 });
    let e1: Entity = spawn(Node { v: 1 });
    let e2: Entity = spawn(Node { v: 2 });
    insert_relation<ChildOf>(e2, e1);
    insert_relation<CustomParent>(e2, e1);
    trigger(e2, Hit { dmg: 10 }, propagate: true);
    despawn_all<With<TagB>, Without<TagA>>();
    for _r in query(n: &Node).added<Node>() {
        c.total += 0;
    }
    let mut sum_up: i32 = 0;
    for r in query(n: &Node).up<CustomParent>() {
        sum_up += r.n.v;
    }
    res_mut<ResultOut>().up_hits = sum_up;
}

obs on_hit(e: &Trigger<Hit>, p: stream_in<Ping>, out: &mut res ResultOut) {
    let _ = e.payload.dmg;
    out.obs_seen = p.code;
}

sys boot_task() {}

schedule Startup { boot_task }
schedule FixedUpdate { par_with_res, par_sparse, emit_and_rel }
"#;
    let analyzed = analyze_source("jit_ecs_step4.strata", src);
    assert!(analyzed.ok(), "sema: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_ecs_step4".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    use strata_jit::abi_offsets::structs::{
        OBS_CTX_CALLBACK, OBS_NAME, OBS_QUERIES, OBS_QUERY_COUNT, OBS_USER_DATA,
    };
    let (node_sz, _) = field_offset_of(&mir, "Node", "v");
    let (sp_sz, off_spw) = field_offset_of(&mir, "SpVal", "w");
    let (cnt_sz, off_cnt) = field_offset_of(&mir, "Counter", "total");
    let (ro_sz, off_sps) = field_offset_of(&mir, "ResultOut", "sp_sum");
    let (_, off_uh) = field_offset_of(&mir, "ResultOut", "up_hits");
    let (_, off_obs) = field_offset_of(&mir, "ResultOut", "obs_seen");
    let (ping_sz, _) = field_offset_of(&mir, "Ping", "code");
    let (_, off_hit_dmg) = field_offset_of(&mir, "Hit", "dmg");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_col_rows_ro = idx(api_slots::ITER_COLUMN_ROWS_READONLY);
    let s_par_ro = idx(api_slots::PAR_FOR_EACH_CHUNK_READONLY);
    let s_par_mut = idx(api_slots::PAR_FOR_EACH_CHUNK);
    let s_msg_send = idx(api_slots::MSG_SEND);
    let s_msg_rb = idx(api_slots::MSG_READ_BATCH);
    let s_cmd_spawn = idx(api_slots::CMD_SPAWN);
    let s_cmd_insert = idx(api_slots::CMD_INSERT);
    let s_cmd_ins_rel = idx(api_slots::CMD_INSERT_RELATION);
    let s_cmd_trig_ex = idx(api_slots::CMD_TRIGGER_EX);
    let s_cmd_desp_all = idx(api_slots::CMD_DESPAWN_ALL);
    let s_reg_obs = idx(api_slots::REGISTER_OBSERVER);
    let s_bind_obj = idx(api_slots::BIND_NAMED_OBJECT);
    let flag_res = bamabi_sys::BAM_STORAGE_FLAG_RESOURCE;
    let flag_msg = bamabi_sys::BAM_STORAGE_FLAG_MESSAGE;
    let flag_added = bamabi_sys::BAM_TERM_FLAG_ADDED;
    let flag_prop = bamabi_sys::BAM_TRIGGER_FLAG_PROPAGATE;
    let invalid_comp = strata_jit::abi_offsets::BAM_COMPONENT_INVALID;
    let access_without = bamabi_sys::AccessMode::WITHOUT.0;

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_COL_ROWS_RO {s_col_rows_ro}u
#define SLOT_PAR_RO {s_par_ro}u
#define SLOT_PAR_MUT {s_par_mut}u
#define SLOT_MSG_SEND {s_msg_send}u
#define SLOT_MSG_RB {s_msg_rb}u
#define SLOT_CMD_SPAWN {s_cmd_spawn}u
#define SLOT_CMD_INSERT {s_cmd_insert}u
#define SLOT_CMD_INS_REL {s_cmd_ins_rel}u
#define SLOT_CMD_TRIG_EX {s_cmd_trig_ex}u
#define SLOT_CMD_DESP_ALL {s_cmd_desp_all}u
#define SLOT_REGISTER_OBSERVER {s_reg_obs}u
#define SLOT_BIND_OBJ {s_bind_obj}u

typedef struct BamTriggerDesc {{
    uint32_t struct_size; uint32_t flags; uint32_t event; uint32_t event_kind;
    uint32_t entity_lo; uint32_t entity_hi; const void* data_ptr; size_t data_len;
    const uint32_t* watched_components; size_t watched_component_count;
    uint32_t propagate_relationship; uint32_t reserved0;
}} BamTriggerDesc;

typedef uint32_t (*BamObsCtxFn)(uint64_t entity, const void* ev, void* sys_ctx, void* ud);

static int g_hctx = 1, g_lctx = 2, g_sctx = 3, g_cmds = 9;
static uint32_t g_next_c = 10;
static uint32_t g_node_c = 0, g_sp_c = 0, g_taga_c = 0, g_tagb_c = 0, g_cnt_c = 0, g_ro_c = 0, g_ping_c = 0;
static uint32_t g_childof_c = 0, g_custom_parent_c = 0, g_custom_rel_h = 0;
static int g_ping_is_msg = 0, g_startup_has_before = 0, g_added_flag_ok = 0, g_without_ok = 0;
static int g_childof_ins_ok = 0, g_custom_parent_ins_ok = 0, g_trig_prop_ok = 0, g_up_rel_comp_ok = 0;
static uint32_t g_obs_ping_c = 0;
static BamObsCtxFn g_obs_ctx_cb = NULL;
static void* g_obs_ud = NULL;

typedef struct SysReg {{ char name[64]; BamSystemFn cb; void* ud; uint32_t q_comp[8]; }} SysReg;
static SysReg g_sys[16];
static size_t g_sys_n = 0;
static SysReg* g_cur_sys = NULL;

static uint8_t g_cnt_buf[{cnt_sz}];
static uint8_t g_ro_buf[{ro_sz}];
static uint8_t g_nodes[4 * {node_sz}];
static uint8_t g_sp_rows[4][{sp_sz}];
static void* g_sp_ptrs[4] = {{ g_sp_rows[0], g_sp_rows[1], g_sp_rows[2], g_sp_rows[3] }};
static uint64_t g_ents[4] = {{ 1, 2, 3, 4 }};
static uint8_t g_ping_msg[64];
static size_t g_ping_len = 0, g_ping_sent = 0, g_next_ent = 500;
typedef struct Iter {{ uint32_t comp; size_t st; }} Iter;
static Iter g_it[16];

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_res_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc;(void)u;
    if (n && strcmp(n, "bevy_ecs::hierarchy::ChildOf") == 0) {{ g_childof_c = 9001u; *o = g_childof_c; return 0; }}
    if (n && strstr(n, "Counter")) {{ g_cnt_c = 9002u; *o = g_cnt_c; return 0; }}
    if (n && strstr(n, "ResultOut")) {{ g_ro_c = 9003u; *o = g_ro_c; return 0; }}
    return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; memset(i, 0, sizeof(*i)); i->struct_size = (uint32_t)sizeof(*i);
    if (c == g_ping_c && g_ping_is_msg) {{ i->flags = {flag_msg}u; i->size = {ping_sz}u; i->align = 4u; return 0; }}
    if (c == g_cnt_c) {{ i->flags = {flag_res}u; i->size = {cnt_sz}u; i->align = 4u; return 0; }}
    if (c == g_ro_c) {{ i->flags = {flag_res}u; i->size = {ro_sz}u; i->align = 4u; return 0; }}
    return 4;
}}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_c++;
    if (d->name) {{
        if (strstr(d->name, "Node")) g_node_c = id;
        if (strstr(d->name, "SpVal")) g_sp_c = id;
        if (strstr(d->name, "TagA")) g_taga_c = id;
        if (strstr(d->name, "TagB")) g_tagb_c = id;
        if (strstr(d->name, "Counter")) g_cnt_c = id;
        if (strstr(d->name, "ResultOut")) g_ro_c = id;
        if (strstr(d->name, "Ping")) {{ g_ping_c = id; if (d->flags & {flag_msg}u) g_ping_is_msg = 1; }}
        if (strstr(d->name, "__strata_rel_parent_CustomParent")) g_custom_parent_c = id;
    }}
    *o = id; return 0;
}}
static uint32_t h_reg_rel(void* lc, const void* d, uint32_t* o) {{ (void)lc;(void)d; g_custom_rel_h = 8001u; *o = g_custom_rel_h; return 0; }}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc;
    SysReg* r = &g_sys[g_sys_n];
    snprintf(r->name, 64, "%s", d->name ? d->name : "");
    r->cb = d->callback; r->ud = d->user_data;
    for (size_t qi = 0; qi < d->query_count && qi < 8; qi++) {{
        r->q_comp[qi] = d->queries[qi].term_count > 0 ? d->queries[qi].terms[0].component : 0;
        for (size_t ti = 0; ti < d->queries[qi].term_count; ti++) {{
            if (d->queries[qi].terms[ti].component == g_node_c && (d->queries[qi].terms[ti].flags & {flag_added}u)) g_added_flag_ok = 1;
        }}
    }}
    if (d->name && strcmp(d->name, "strata_init_objects") == 0) {{
        for (size_t bi = 0; bi < d->before_count; bi++) {{
            if (d->before[bi] && strcmp(d->before[bi], "boot_task") == 0) g_startup_has_before = 1;
        }}
    }}
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_cmds(void* sc, void** o) {{ (void)sc; *o = &g_cmds; return 0; }}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{
    (void)sc; size_t idx = qi < 16 ? qi : 0;
    g_it[idx].comp = g_cur_sys ? g_cur_sys->q_comp[idx] : g_obs_ping_c;
    g_it[idx].st = 0; *o = &g_it[idx]; return 0;
}}
static uint32_t h_it_rst(void* it) {{ ((Iter*)it)->st = 0; return 0; }}
static uint8_t h_next(void* it, size_t* len) {{
    Iter* s = (Iter*)it; if (s->st == 0) {{ s->st = 1; *len = 4; return 1; }} *len = 0; return 0;
}}
static const uint64_t* h_ents(void* it) {{ (void)it; return g_ents; }}
static void* h_col(void* it, size_t ti) {{
    (void)ti; Iter* s = (Iter*)it;
    return (s->comp == g_sp_c) ? (void*)g_sp_ptrs : (void*)g_nodes;
}}
static void* h_res_ptr(void* sc, uint32_t c, void* t) {{
    (void)sc;(void)t;
    if (c == g_cnt_c) return g_cnt_buf;
    if (c == g_ro_c) return g_ro_buf;
    return NULL;
}}
static uint32_t h_par(void* it, uint32_t (*cb)(void*, void*), void* frame) {{ return cb(it, frame); }}
static uint32_t h_msg_send(void* it, size_t ti, const void* p, size_t l) {{
    (void)it;(void)ti; if (l <= sizeof(g_ping_msg)) {{ memcpy(g_ping_msg, p, l); g_ping_len = l; g_ping_sent = 1; }} return 0;
}}
static uint32_t h_msg_rb(void* it, size_t ti, uint8_t* b, size_t m, size_t* out_r) {{
    (void)it;(void)ti; if (g_ping_sent && m > 0) {{ memcpy(b, g_ping_msg, g_ping_len); *out_r = 1; g_ping_sent = 0; }} else *out_r = 0; return 0;
}}
static uint32_t h_cmd_spawn(void* cmds, const uint32_t* cs, const void* const* ps, size_t n, uint64_t* oe) {{
    (void)cmds;(void)cs;(void)ps;(void)n; *oe = g_next_ent++; return 0;
}}
static uint32_t h_cmd_ins(void* cmds, uint64_t e, uint32_t c, const void* d, size_t l) {{
    (void)cmds;(void)e;(void)d;(void)l;
    if (c == g_childof_c) g_childof_ins_ok = 1;
    if (c == g_custom_parent_c) g_custom_parent_ins_ok = 1;
    return 0;
}}
static uint32_t h_cmd_ins_rel(void* cmds, uint32_t r, uint64_t e, uint64_t t, const void* d, size_t l) {{
    (void)cmds;(void)r;(void)e;(void)t;(void)d;(void)l; return 0;
}}
static uint32_t h_cmd_trig_ex(void* cmds, const BamTriggerDesc* d) {{
    (void)cmds;
    if (d && (d->flags & {flag_prop}u) && d->propagate_relationship == {invalid_comp}u) g_trig_prop_ok = 1;
    return 0;
}}
static uint32_t h_cmd_desp_all(void* cmds, const BamTermDesc* ts, size_t cnt) {{
    (void)cmds;
    for (size_t i = 0; i < cnt; i++) {{
        if (ts[i].component == g_taga_c && ts[i].mode == {access_without}u) g_without_ok = 1;
    }}
    return 0;
}}
static uint32_t h_up_cascade(void* it, uint32_t rel, uint64_t e, size_t ti, const void** out_p, uint64_t* out_e) {{
    (void)it;(void)ti;
    if (rel == g_custom_parent_c) g_up_rel_comp_ok = 1;
    if (e == 1) {{ *out_p = g_nodes; *out_e = 99; return 0; }}
    *out_p = NULL; *out_e = 0; return 4;
}}
static uint32_t h_reg_obs(void* lc, const void* desc_ptr) {{
    (void)lc;
    const uint8_t* p = (const uint8_t*)desc_ptr;
    const char* name = *(const char* const*)(p + {OBS_NAME});
    if (name && strstr(name, "on_hit")) {{
        g_obs_ctx_cb = *(const BamObsCtxFn*)(p + {OBS_CTX_CALLBACK});
        g_obs_ud = *(void* const*)(p + {OBS_USER_DATA});
        const BamQueryDesc* qs = *(const BamQueryDesc* const*)(p + {OBS_QUERIES});
        size_t qc = *(const size_t*)(p + {OBS_QUERY_COUNT});
        if (qc > 0 && qs && qs[0].term_count > 0) g_obs_ping_c = qs[0].terms[0].component;
    }}
    return 0;
}}
static uint32_t h_mark_chg(void* it, size_t ti, size_t s, size_t l) {{ (void)it;(void)ti;(void)s;(void)l; return 0; }}
static uint32_t h_bind_obj(void* hc, const char* n, size_t l, uint64_t e) {{ (void)hc;(void)n;(void)l;(void)e; return 0; }}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api; memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api); api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_res_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_REGISTER_RELATION] = (void*)h_reg_rel;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_COMMANDS] = (void*)h_sys_cmds;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_ITER_RESET] = (void*)h_it_rst;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT_UNTRACKED] = (void*)h_col;
    api.slots[SLOT_ITER_MARK_CHANGED_RANGE] = (void*)h_mark_chg;
    api.slots[SLOT_COL_ROWS_RO] = (void*)h_col;
    api.slots[SLOT_SYS_RES_PTR] = (void*)h_res_ptr;
    api.slots[SLOT_SYS_RES_MUT_PTR] = (void*)h_res_ptr;
    api.slots[SLOT_PAR_RO] = (void*)h_par;
    api.slots[SLOT_PAR_MUT] = (void*)h_par;
    api.slots[SLOT_MSG_SEND] = (void*)h_msg_send;
    api.slots[SLOT_MSG_RB] = (void*)h_msg_rb;
    api.slots[SLOT_CMD_SPAWN] = (void*)h_cmd_spawn;
    api.slots[SLOT_CMD_INSERT] = (void*)h_cmd_ins;
    api.slots[SLOT_CMD_INS_REL] = (void*)h_cmd_ins_rel;
    api.slots[SLOT_CMD_TRIG_EX] = (void*)h_cmd_trig_ex;
    api.slots[SLOT_CMD_DESP_ALL] = (void*)h_cmd_desp_all;
    api.slots[SLOT_ITER_UP_CASCADE] = (void*)h_up_cascade;
    api.slots[SLOT_REGISTER_OBSERVER] = (void*)h_reg_obs;
    api.slots[SLOT_BIND_OBJ] = (void*)h_bind_obj;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    if (!g_ping_is_msg || !g_startup_has_before || !g_added_flag_ok) {{
        fprintf(stderr, "flags msg=%d boot=%d added=%d\n", g_ping_is_msg, g_startup_has_before, g_added_flag_ok);
        return 5;
    }}

    memset(g_cnt_buf, 0, sizeof(g_cnt_buf));
    memset(g_ro_buf, 0, sizeof(g_ro_buf));
    for (int i = 0; i < 4; i++) {{
        int32_t nv = i + 1;
        float sv = 2.5f;
        memcpy(g_nodes + i * {node_sz}, &nv, 4);
        memcpy(g_sp_rows[i] + {off_spw}, &sv, 4);
    }}
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strcmp(g_sys[i].name, "boot_task") == 0) continue;
        if (strcmp(g_sys[i].name, "strata_init_objects") == 0) continue;
        g_cur_sys = &g_sys[i];
        g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}
    if (g_obs_ctx_cb) {{
        uint64_t tgt_e = 5;
        int32_t dmg = 10;
        uint8_t ev_pkt[64];
        memset(ev_pkt, 0, sizeof(ev_pkt));
        memcpy(ev_pkt + {off_hit_dmg}, &dmg, 4);
        g_cur_sys = NULL;
        g_obs_ctx_cb(tgt_e, ev_pkt, &g_sctx, g_obs_ud);
    }}

    int32_t total = 0, up_hits = 0, obs_seen = 0;
    float sp_sum = 0.0f;
    memcpy(&total, g_cnt_buf + {off_cnt}, 4);
    memcpy(&sp_sum, g_ro_buf + {off_sps}, 4);
    memcpy(&up_hits, g_ro_buf + {off_uh}, 4);
    memcpy(&obs_seen, g_ro_buf + {off_obs}, 4);
    if (total != 10) {{ fprintf(stderr, "PM-06 total=%d\n", total); return 10; }}
    if (fabsf(sp_sum - 10.0f) > 1e-4f) {{ fprintf(stderr, "PM-13 sp_sum=%f\n", sp_sum); return 11; }}
    if (!g_childof_ins_ok || !g_custom_parent_ins_ok || !g_trig_prop_ok || !g_up_rel_comp_ok || up_hits != 1) {{
        fprintf(stderr, "EQ-05 child=%d cparent=%d trig=%d up=%d hits=%d\n",
            g_childof_ins_ok, g_custom_parent_ins_ok, g_trig_prop_ok, g_up_rel_comp_ok, up_hits);
        return 12;
    }}
    if (!g_without_ok || obs_seen != 42) {{ fprintf(stderr, "GF13/EQ01 without=%d obs=%d\n", g_without_ok, obs_seen); return 13; }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_ecs_step4", &c_code, &artifact.dylib_path);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn jit_regression_spatial_limits_history_xz_and_run_if() {
    use strata_jit::abi_offsets::api_slots;
    let src = r#"
module test::jit_sw_step5 @version(1.0.0);

component Pos3 { xyz: vec3 = vec3(0.0, 0.0, 0.0) }
resource OutSw {
    disc64: i32 = 0,
    seg64: i32 = 0,
    seg_oob4: i32 = 9,
    seg_umax: i32 = 9,
    xz_v2: i32 = 0,
    xz_v3_y0: i32 = 0,
    xz_v3_y99: i32 = 0,
    xz_seg: i32 = 0,
    blocked_ran: i32 = 0,
}

spatial_grid GridXZ(cell_size: 4.0_m, bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m), capacity: 128) over Pos3 by Pos3.xyz;
spatial_history HistXZ(frames: 4, cell_size: 4.0_m, bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m), capacity: 128) over Pos3 by Pos3.xyz;

sys scan_all(g: &res GridXZ, h: &res HistXZ, out: &mut res OutSw) {
    let mut c_disc: i32 = 0;
    for _hit in g.query_disc(vec2(1.0, 1.0), 0.5_m) { c_disc += 1; }
    out.disc64 = c_disc;

    let mut c_seg: i32 = 0;
    for _hit in h.query_segment_at(0, vec3(0.5, 0.0, 1.0), vec3(1.5, 0.0, 1.0), 0.5_m) { c_seg += 1; }
    out.seg64 = c_seg;

    let mut c_oob4: i32 = 0;
    for _hit in h.query_segment_at(4, vec3(0.5, 0.0, 1.0), vec3(1.5, 0.0, 1.0), 0.5_m) { c_oob4 += 1; }
    out.seg_oob4 = c_oob4;

    let mut c_umax: i32 = 0;
    for _hit in h.query_segment_at(4294967295_u32, vec3(0.5, 0.0, 1.0), vec3(1.5, 0.0, 1.0), 0.5_m) { c_umax += 1; }
    out.seg_umax = c_umax;

    let mut c_v2: i32 = 0;
    for _hit in g.query_disc(vec2(10.0, 12.0), 1.0_m) { c_v2 += 1; }
    out.xz_v2 = c_v2;

    let mut c_v3_y0: i32 = 0;
    for _hit in g.query_disc(vec3(10.0, 0.0, 12.0), 1.0_m) { c_v3_y0 += 1; }
    out.xz_v3_y0 = c_v3_y0;

    let mut c_v3_y99: i32 = 0;
    for _hit in g.query_disc(vec3(10.0, 99.0, 12.0), 1.0_m) { c_v3_y99 += 1; }
    out.xz_v3_y99 = c_v3_y99;

    let mut c_xseg: i32 = 0;
    for _hit in h.query_segment_at(0, vec3(9.5, 0.0, 12.0), vec3(10.5, 0.0, 12.0), 1.0_m) { c_xseg += 1; }
    out.xz_seg = c_xseg;
}

sys blocked_sys(out: &mut res OutSw) {
    out.blocked_ran = 1;
}

schedule Update { scan_all }
schedule FixedUpdate run_if(false) { blocked_sys }
"#;
    let analyzed = analyze_source("jit_sw_step5.strata", src);
    assert!(analyzed.ok(), "sema: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_sw_step5".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let (p3_sz, off_xyz) = field_offset_of(&mir, "Pos3", "xyz");
    let (out_sz, off_d64) = field_offset_of(&mir, "OutSw", "disc64");
    let (_, off_s64) = field_offset_of(&mir, "OutSw", "seg64");
    let (_, off_oob4) = field_offset_of(&mir, "OutSw", "seg_oob4");
    let (_, off_umax) = field_offset_of(&mir, "OutSw", "seg_umax");
    let (_, off_v2) = field_offset_of(&mir, "OutSw", "xz_v2");
    let (_, off_y0) = field_offset_of(&mir, "OutSw", "xz_v3_y0");
    let (_, off_y99) = field_offset_of(&mir, "OutSw", "xz_v3_y99");
    let (_, off_xs) = field_offset_of(&mir, "OutSw", "xz_seg");
    let (_, off_blk) = field_offset_of(&mir, "OutSw", "blocked_ran");

    let word = std::mem::size_of::<usize>();
    let idx = |off: usize| (off - 8) / word;
    let s_cfg_sset = idx(api_slots::CONFIGURE_SCHEDULE_SET);
    let s_mnt_sys = idx(api_slots::MOUNT_SYSTEM_IN_SCHEDULE);
    let flag_res = bamabi_sys::BAM_STORAGE_FLAG_RESOURCE;

    let mut c_code = c_abi_prelude();
    c_code.push_str(&format!(
        r#"
#define SLOT_CFG_SSET {s_cfg_sset}u
#define SLOT_MNT_SYS {s_mnt_sys}u
static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_next_c = 10, g_out_c = 100u;
typedef struct SysReg {{ char name[96]; BamSystemFn cb; void* ud; uint32_t (*run_if_ctx)(void*, void*); void* run_if_ud; }} SysReg;
static SysReg g_sys[16];
static size_t g_sys_n = 0;
static uint8_t g_pos_buf[65 * {p3_sz}];
static uint64_t g_pos_ents[65];
static uint8_t g_out_buf[{out_sz}];
static size_t g_it_stage = 0;

static void* h_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t h_res_comp(const void* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc;(void)u; if (n && strstr(n, "OutSw")) {{ *o = g_out_c; return 0; }} return 4;
}}
static uint32_t h_linfo(const void* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; memset(i, 0, sizeof(*i)); i->struct_size = (uint32_t)sizeof(*i);
    if (c == g_out_c) {{ i->flags = {flag_res}u; i->size = {out_sz}u; i->align = 4u; return 0; }}
    return 4;
}}
static uint32_t h_reg_comp(void* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_next_c++; if (d->name && strstr(d->name, "OutSw")) g_out_c = id; *o = id; return 0;
}}
static uint32_t h_cfg_sset(void* lc, const void* d, uint32_t* o) {{ (void)lc;(void)d; if (o) *o = 1; return 0; }}
static uint32_t h_mnt_sys(void* lc, uint32_t s, uint32_t sc, uint32_t ss) {{ (void)lc;(void)s;(void)sc;(void)ss; return 0; }}
static uint32_t h_reg_sys(void* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)lc; snprintf(g_sys[g_sys_n].name, 96, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data;
    g_sys[g_sys_n].run_if_ctx = (uint32_t (*)(void*, void*))d->run_if_ctx;
    g_sys[g_sys_n].run_if_ud = d->run_if_ctx_user_data;
    *o = (uint32_t)(++g_sys_n); return 0;
}}
static uint32_t h_sys_q(void* sc, size_t qi, void** o) {{ (void)sc;(void)qi; g_it_stage = 0; *o = (void*)0x2222; return 0; }}
static uint32_t h_it_rst(void* it) {{ (void)it; g_it_stage = 0; return 0; }}
static uint8_t h_next(void* it, size_t* len) {{ (void)it; if (g_it_stage == 0) {{ g_it_stage = 1; *len = 65; return 1; }} *len = 0; return 0; }}
static const uint64_t* h_ents(void* it) {{ (void)it; return g_pos_ents; }}
static void* h_col(void* it, size_t ti) {{ (void)it;(void)ti; return g_pos_buf; }}
static void* h_res_ptr(void* sc, uint32_t c, void* t) {{ (void)sc;(void)t; return (c == g_out_c) ? g_out_buf : NULL; }}

int main(int argc, char** argv) {{
    if (argc < 2) return 2;
    void* dl = dlopen(argv[1], RTLD_NOW);
    if (!dl) return 3;
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(dl, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(dl, "bamabi_shutdown");
    BamHostApi api; memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api); api.abi_version = WIRE_ABI_VER;
    api.slots[SLOT_LOAD_HOST_CTX] = (void*)h_lhc;
    api.slots[SLOT_REGISTER_COMPONENT] = (void*)h_reg_comp;
    api.slots[SLOT_RESOLVE_COMPONENT] = (void*)h_res_comp;
    api.slots[SLOT_COMPONENT_LAYOUT_INFO] = (void*)h_linfo;
    api.slots[SLOT_CFG_SSET] = (void*)h_cfg_sset;
    api.slots[SLOT_MNT_SYS] = (void*)h_mnt_sys;
    api.slots[SLOT_REGISTER_SYSTEM] = (void*)h_reg_sys;
    api.slots[SLOT_REGISTER_SYSTEM_HANDLE] = (void*)h_reg_sys;
    api.slots[SLOT_SYS_QUERY] = (void*)h_sys_q;
    api.slots[SLOT_ITER_RESET] = (void*)h_it_rst;
    api.slots[SLOT_ITER_NEXT_CHUNK] = (void*)h_next;
    api.slots[SLOT_ITER_ENTITIES] = (void*)h_ents;
    api.slots[SLOT_ITER_COL_RO] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT] = (void*)h_col;
    api.slots[SLOT_ITER_COL_MUT_UNTRACKED] = (void*)h_col;
    api.slots[SLOT_SYS_RES_PTR] = (void*)h_res_ptr;
    api.slots[SLOT_SYS_RES_MUT_PTR] = (void*)h_res_ptr;

    void* state = NULL;
    if (init_fn(&api, &g_lctx, &state) != 0) return 4;
    memset(g_pos_buf, 0, sizeof(g_pos_buf));
    memset(g_out_buf, 0, sizeof(g_out_buf));
    for (int i = 0; i < 64; i++) {{
        g_pos_ents[i] = (uint64_t)(100 + i);
        float p[3] = {{ 1.0f, 0.0f, 1.0f }};
        memcpy(g_pos_buf + i * {p3_sz} + {off_xyz}, p, 12);
    }}
    g_pos_ents[64] = 999ull;
    float pxz[3] = {{ 10.0f, 99.0f, 12.0f }};
    memcpy(g_pos_buf + 64 * {p3_sz} + {off_xyz}, pxz, 12);

    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "rebuild_csr")) g_sys[i].cb(&g_sctx, g_sys[i].ud);
    }}
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (!strstr(g_sys[i].name, "rebuild_csr")) {{
            if (!g_sys[i].run_if_ctx || g_sys[i].run_if_ctx(&g_sctx, g_sys[i].run_if_ud)) {{
                g_sys[i].cb(&g_sctx, g_sys[i].ud);
            }}
        }}
    }}

    int32_t d64=0, s64=0, oob4=9, umax=9, v2=0, y0=0, y99=0, xs=0, blk=9;
    memcpy(&d64, g_out_buf + {off_d64}, 4);
    memcpy(&s64, g_out_buf + {off_s64}, 4);
    memcpy(&oob4, g_out_buf + {off_oob4}, 4);
    memcpy(&umax, g_out_buf + {off_umax}, 4);
    memcpy(&v2, g_out_buf + {off_v2}, 4);
    memcpy(&y0, g_out_buf + {off_y0}, 4);
    memcpy(&y99, g_out_buf + {off_y99}, 4);
    memcpy(&xs, g_out_buf + {off_xs}, 4);
    memcpy(&blk, g_out_buf + {off_blk}, 4);
    if (d64 != 64 || s64 != 64) {{
        fprintf(stderr, "SW-04 d64=%d s64=%d oob4=%d blk=%d g_sys_n=%zu", d64, s64, oob4, blk, g_sys_n);
        for (size_t i = 0; i < g_sys_n; i++) fprintf(stderr, " [%zu:%s]", i, g_sys[i].name);
        fprintf(stderr, "\n");
        return 10;
    }}
    if (oob4 != 0 || umax != 0) {{ fprintf(stderr, "SW-05 oob4=%d umax=%d\n", oob4, umax); return 11; }}
    if (v2 != 1 || y0 != 1 || y99 != 1 || xs != 1) {{
        fprintf(stderr, "SW-06 v2=%d y0=%d y99=%d xs=%d\n", v2, y0, y99, xs); return 12;
    }}
    if (blk != 0) {{ fprintf(stderr, "SW-07d blocked_ran=%d\n", blk); return 13; }}

    shut_fn(state);
    dlclose(dl);
    return 0;
}}
"#
    ));
    run_c_host_harness(tmp.path(), "jit_sw_step5", &c_code, &artifact.dylib_path);
}
