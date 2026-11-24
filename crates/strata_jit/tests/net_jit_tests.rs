use std::fs;
use std::process::Command;
use strata_codegen::net::{
    STRATA_NET_MAX_PAYLOAD_BYTES, STRATA_NET_PACKET_CANONICAL_NAME, STRATA_NET_PACKET_MAGIC,
    STRATA_NET_PACKET_SCHEMA_FINGERPRINT, STRATA_NET_PACKET_SIZE, STRATA_NET_WIRE_VERSION,
    dequantize_scalar_f64, pack_bits_le, quantize_scalar_f64, unpack_bits_le,
};
use strata_jit::abi_offsets::{
    ACCESS_MODE_CHANGED, HOST_API_SLOTS, all_exposed_api_slots, api_slots,
};
use strata_jit::emitter::emit_pic_object;
use strata_jit::{JitCompileOptions, JitOptLevel, compile_module_to_dylib};
use strata_mir::{MirNetComponent, MirRpc, lower_to_mir};
use strata_sema::analyze_source;
use strata_sema::hir::{AuthorityKind, NetDirection, NetReliability};
use tempfile::TempDir;

const NET_FIXTURE: &str = r#"
module game::jit_mp @version(1.0.0);

@net(reliable, rate = 20Hz, channel = 0)
@authority(server)
component FighterPose {
    @quantize(min = -100.0, max = 100.0, bits = 12)
    yaw: f32 = 0.0,
    @quantize(min = 0.0, max = 1.0, bits = 1)
    grounded: f32 = 0.0,
    @quantize(min = -1000000.0, max = 1000000.0, bits = 32)
    precise: f32 = 0.0,
    @quantize(min = -50.0, max = 50.0, bits = 16)
    pos: vec3 = vec3(0.0, 0.0, 0.0),
    seq: u32 = 0,
    alive: bool = true,
}

@net(unreliable, channel = 1)
@predicted
@authority(predicted)
component PredictedInput {
    @quantize(min = -1.0, max = 1.0, bits = 8)
    throttle: f32 = 0.0,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc MoveCmd {
    @quantize(min = -1.0, max = 1.0, bits = 8)
    dx: f32,
    seq: u32,
}

stream Hit {
    dmg: f32,
}

@authority(server)
sys emit_on_change() {
    for e in query(p: &FighterPose).changed() {
        emit(Hit { dmg: e.p.yaw });
    }
}

sys consume_hits(hits: stream_in<Hit>) {
    let _ = hits.dmg;
}

@authority(server)
sys selective_pose_update() {
    for e in query(p: &mut? FighterPose) {
        if e.p.alive && e.p.seq == 9999 {
            e.p.yaw += 1.0;
        }
    }
}

schedule FixedUpdate {
    emit_on_change,
    consume_hits,
    selective_pose_update,
}
"#;

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

#[test]
fn abi_offsets_expose_slots_30_32_and_changed_within_wire_slots() {
    assert_eq!(HOST_API_SLOTS, bamabi_sys::BAM_HOST_API_SLOT_COUNT);
    const {
        assert!(HOST_API_SLOTS >= 68);
    }
    let slots = all_exposed_api_slots();
    assert!(slots.len() <= HOST_API_SLOTS);
    assert!(slots.contains(&api_slots::MSG_READ_BATCH));
    assert!(slots.contains(&api_slots::MSG_SEND));
    assert!(slots.contains(&api_slots::MSG_WRITE_BATCH));
    assert_eq!(ACCESS_MODE_CHANGED, bamabi_sys::AccessMode::CHANGED.0);
    assert_eq!(ACCESS_MODE_CHANGED, 6);
    assert_eq!(
        bamabi_sys::BAM_TERM_KNOWN_FLAGS,
        bamabi_sys::BAM_TERM_FLAG_CHANGED | bamabi_sys::BAM_TERM_FLAG_ADDED
    );
}

#[test]
fn jit_rejects_oversized_net_payload_and_skips_net_symbols_for_plain_modules() {
    let plain_src = r#"
module game::plain_jit @version(1.0.0);
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
sys step() {
    for e in query(p: &mut Pos) {
        e.p.x += 1.0;
    }
}
schedule FixedUpdate { step }
"#;
    let plain_analyzed = analyze_source("plain_jit.strata", plain_src);
    assert!(plain_analyzed.ok(), "{:?}", plain_analyzed.diagnostics);
    let plain_mir = lower_to_mir(&plain_analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let plain_obj = emit_pic_object(
        &plain_mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "plain_jit".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("plain emit_pic_object");
    let obj_path = tmp.path().join("plain_jit.o");
    fs::write(&obj_path, &plain_obj.object_bytes).expect("write plain .o");
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let nm = Command::new("nm").arg(&obj_path).output().expect("nm");
        assert!(nm.status.success());
        let syms = String::from_utf8_lossy(&nm.stdout);
        assert!(
            !syms.contains("strata_sys_net_rx") && !syms.contains("strata_sys_net_tx"),
            "non-net module must not emit net TX/RX systems:\n{syms}"
        );
    }

    // Oversized component (>128 bytes) must fail cleanly.
    let net_analyzed = analyze_source("jit_mp.strata", NET_FIXTURE);
    assert!(net_analyzed.ok(), "{:?}", net_analyzed.diagnostics);
    let mut bad_comp_mir = lower_to_mir(&net_analyzed);
    bad_comp_mir.net_components.push(MirNetComponent {
        name: "Oversized".to_owned(),
        canonical_name: "game::jit_mp::Oversized".to_owned(),
        is_resource: false,
        is_replicated: true,
        reliability: NetReliability::Reliable,
        rate_hz: None,
        interval_ticks: None,
        channel: 0,
        authority: AuthorityKind::Server,
        is_predicted: false,
        schema_fingerprint: 1,
        uuid_bytes: [0; 16],
        quantize_specs: Vec::new(),
        wire_fields: Vec::new(),
        packed_bits: (STRATA_NET_MAX_PAYLOAD_BYTES as u32 + 1) * 8,
        packed_bytes: STRATA_NET_MAX_PAYLOAD_BYTES as u32 + 1,
    });
    let err = compile_module_to_dylib(
        &bad_comp_mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "oversized_comp".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect_err("oversized component must be rejected");
    assert!(err.to_string().contains("exceeds StrataNetPacket capacity"));

    // Oversized RPC (>128 bytes) must fail cleanly.
    let mut bad_rpc_mir = lower_to_mir(&net_analyzed);
    bad_rpc_mir.rpcs.push(MirRpc {
        name: "OversizedRpc".to_owned(),
        canonical_name: "game::jit_mp::OversizedRpc".to_owned(),
        direction: NetDirection::ClientToServer,
        reliability: NetReliability::Reliable,
        channel: 0,
        authority: AuthorityKind::Client,
        rpc_id: 1,
        schema_fingerprint: 1,
        fields: Vec::new(),
        quantize_specs: Vec::new(),
        wire_fields: Vec::new(),
        packed_bits: (STRATA_NET_MAX_PAYLOAD_BYTES as u32 + 2) * 8,
        packed_bytes: STRATA_NET_MAX_PAYLOAD_BYTES as u32 + 2,
        payload_bytes: STRATA_NET_MAX_PAYLOAD_BYTES as u32 + 2,
    });
    let rpc_err = match emit_pic_object(
        &bad_rpc_mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "oversized_rpc".to_owned(),
            opt_level: JitOptLevel::FastCompile,
        },
    ) {
        Err(e) => e,
        Ok(_) => panic!("oversized RPC must be rejected"),
    };
    assert!(
        rpc_err
            .to_string()
            .contains("exceeds StrataNetPacket capacity")
    );
}

#[test]
fn jit_networking_compiles_pic_dylib_and_executes_tx_rx_changed_and_handshake_via_vtable() {
    let analyzed = analyze_source("jit_mp.strata", NET_FIXTURE);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "strata_net_mp".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib for networking module");

    assert!(artifact.object_path.exists());
    assert!(artifact.dylib_path.exists());

    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let out_obj = Command::new("nm")
            .arg(&artifact.object_path)
            .output()
            .expect("nm .o");
        assert!(out_obj.status.success());
        let obj_syms = String::from_utf8_lossy(&out_obj.stdout);
        assert!(
            !obj_syms.contains("strata_jit_state"),
            "unexpected BSS global `strata_jit_state`:\n{obj_syms}"
        );
        assert!(obj_syms.contains("calloc") && obj_syms.contains("free"));
        assert!(obj_syms.contains("strata_sys_net_rx_0"));
        assert!(obj_syms.contains("strata_sys_net_tx_0"));
        assert!(obj_syms.contains("strata_net_quantize_scalar_f64"));

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
                "missing `{required}` in:\n{dyn_syms}"
            );
        }
    }

    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }

    // Extract layout and wire constants directly from MIR for the C99 host vtable harness.
    let fp_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == "game::jit_mp::FighterPose")
        .expect("FighterPose layout");
    let fp_nc = mir
        .net_components
        .iter()
        .find(|nc| nc.canonical_name == "game::jit_mp::FighterPose")
        .expect("FighterPose net_component");
    let pred_nc = mir
        .net_components
        .iter()
        .find(|nc| nc.canonical_name == "game::jit_mp::PredictedInput")
        .expect("PredictedInput net_component");

    let field_off = |name: &str| -> usize {
        fp_layout
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("missing field {name}"))
            .offset
    };

    let yaw_off = field_off("yaw");
    let grounded_off = field_off("grounded");
    let precise_off = field_off("precise");
    let pos_off = field_off("pos");
    let seq_off = field_off("seq");
    let alive_off = field_off("alive");

    // Precompute expected wire packet bytes using `strata_codegen::net` as ground truth.
    let mut expected_payload = [0u8; STRATA_NET_MAX_PAYLOAD_BYTES];
    let mut alt_payload = [0u8; STRATA_NET_MAX_PAYLOAD_BYTES];
    for wf in &fp_nc.wire_fields {
        match wf.field_name.as_str() {
            "yaw" => {
                let q = wf.quantize.as_ref().unwrap();
                pack_bits_le(
                    &mut expected_payload,
                    wf.bit_offset,
                    q.bits,
                    quantize_scalar_f64(37.25, q.min, q.max, q.bits, q.step),
                );
                pack_bits_le(
                    &mut alt_payload,
                    wf.bit_offset,
                    q.bits,
                    quantize_scalar_f64(-50.0, q.min, q.max, q.bits, q.step),
                );
            }
            "grounded" => {
                let q = wf.quantize.as_ref().unwrap();
                pack_bits_le(
                    &mut expected_payload,
                    wf.bit_offset,
                    q.bits,
                    quantize_scalar_f64(1.0, q.min, q.max, q.bits, q.step),
                );
                pack_bits_le(
                    &mut alt_payload,
                    wf.bit_offset,
                    q.bits,
                    quantize_scalar_f64(0.0, q.min, q.max, q.bits, q.step),
                );
            }
            "precise" => {
                let q = wf.quantize.as_ref().unwrap();
                pack_bits_le(
                    &mut expected_payload,
                    wf.bit_offset,
                    q.bits,
                    quantize_scalar_f64(1234.5, q.min, q.max, q.bits, q.step),
                );
                pack_bits_le(
                    &mut alt_payload,
                    wf.bit_offset,
                    q.bits,
                    quantize_scalar_f64(-999.25, q.min, q.max, q.bits, q.step),
                );
            }
            "pos" => {
                let q = wf.quantize.as_ref().unwrap();
                for (li, &v) in [12.5_f64, -25.0, 49.0].iter().enumerate() {
                    pack_bits_le(
                        &mut expected_payload,
                        wf.bit_offset + (li as u32) * u32::from(q.bits),
                        q.bits,
                        quantize_scalar_f64(v, q.min, q.max, q.bits, q.step),
                    );
                }
                for (li, &v) in [-10.0_f64, 5.0, 0.0].iter().enumerate() {
                    pack_bits_le(
                        &mut alt_payload,
                        wf.bit_offset + (li as u32) * u32::from(q.bits),
                        q.bits,
                        quantize_scalar_f64(v, q.min, q.max, q.bits, q.step),
                    );
                }
            }
            "seq" => {
                pack_bits_le(&mut expected_payload, wf.bit_offset, 32, 42);
                pack_bits_le(&mut alt_payload, wf.bit_offset, 32, 99);
            }
            "alive" => {
                pack_bits_le(&mut expected_payload, wf.bit_offset, 8, 1);
                pack_bits_le(&mut alt_payload, wf.bit_offset, 8, 0);
            }
            other => panic!("unexpected wire field {other}"),
        }
    }

    // Verify expected dequantized yaw for alt_payload matches [-50.0].
    let yaw_wf = fp_nc
        .wire_fields
        .iter()
        .find(|w| w.field_name == "yaw")
        .unwrap();
    let yaw_q = yaw_wf.quantize.as_ref().unwrap();
    let alt_yaw_deq = dequantize_scalar_f64(
        unpack_bits_le(&alt_payload, yaw_wf.bit_offset, yaw_q.bits),
        yaw_q.min,
        yaw_q.max,
        yaw_q.bits,
        yaw_q.step,
    ) as f32;

    let alt_payload_hex: String = alt_payload
        .iter()
        .map(|b| format!("0x{b:02X}u"))
        .collect::<Vec<_>>()
        .join(", ");
    let exp_payload_hex: String = expected_payload
        .iter()
        .map(|b| format!("0x{b:02X}u"))
        .collect::<Vec<_>>()
        .join(", ");

    let fp_target_id = bamabi_sys::fnv1a_64_str(&fp_nc.canonical_name);
    let mod_net_fp = mir.net_handshake.module_net_fingerprint;
    let host_api_slots = HOST_API_SLOTS;

    let c_src = format!(
        r#"
#include <dlfcn.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct BamStrView {{ const char* ptr; size_t len; }} BamStrView;
typedef struct BamComponentUuid {{ uint8_t bytes[16]; }} BamComponentUuid;
typedef struct BamFieldDesc {{
    uint32_t struct_size;
    uint32_t kind;
    BamStrView name;
    BamStrView type_tag;
    size_t offset;
    size_t size;
    size_t align;
}} BamFieldDesc;

typedef struct BamRequiredComponent {{
    uint32_t struct_size;
    uint32_t flags;
    uint32_t component;
    uint32_t _pad;
    const uint8_t* init_bytes;
    size_t init_size;
}} BamRequiredComponent;

typedef struct BamComponentDesc {{
    uint32_t struct_size;
    uint32_t flags;
    const char* name;
    BamComponentUuid uuid;
    size_t size;
    size_t align;
    const uint32_t* required_components;
    size_t required_component_count;
    uint64_t schema_fingerprint;
    const BamFieldDesc* fields;
    size_t field_count;
    const BamRequiredComponent* required_init_descs;
    size_t required_init_desc_count;
}} BamComponentDesc;

typedef struct BamLayoutInfo {{
    uint32_t struct_size;
    uint32_t flags;
    BamComponentUuid uuid;
    uint64_t schema_fingerprint;
    size_t size;
    size_t align;
    const BamFieldDesc* fields;
    size_t field_count;
}} BamLayoutInfo;

typedef struct BamTermDesc {{
    uint32_t component;
    uint32_t mode;
    uint16_t flags;
    uint8_t or_group;
    uint8_t reserved0;
}} BamTermDesc;

typedef struct BamQueryDesc {{
    uint32_t struct_size;
    uint32_t flags;
    const BamTermDesc* terms;
    size_t term_count;
    uint32_t param_set_group;
    uint32_t reserved0;
}} BamQueryDesc;

typedef uint32_t (*BamSystemFn)(void* sys_ctx, void* user_data);

typedef struct BamSystemDesc {{
    uint32_t struct_size;
    uint32_t flags;
    const char* name;
    const BamQueryDesc* queries;
    size_t query_count;
    BamSystemFn callback;
    void* user_data;
    uint32_t schedule;
    uint32_t reserved0;
    const char* const* after;
    size_t after_count;
    const char* const* before;
    size_t before_count;
    void* run_if;
    void* run_if_user_data;
    const char* const* in_sets;
    size_t in_set_count;
    const char* const* after_weak;
    size_t after_weak_count;
    const char* const* before_weak;
    size_t before_weak_count;
    const char* const* ambiguous_with;
    size_t ambiguous_with_count;
    void* run_if_ctx;
    const BamQueryDesc* run_if_query;
    void* run_if_ctx_user_data;
}} BamSystemDesc;

typedef struct BamHostApi {{
    uint32_t struct_size;
    uint32_t abi_version;
    void* slots[{host_api_slots}];
}} BamHostApi;

typedef struct StrataNetPacket {{
    uint64_t module_net_fingerprint;
    uint64_t item_schema_fingerprint;
    uint64_t target_id;
    uint64_t entity_bits;
    uint32_t magic;
    uint32_t tick_or_seq;
    uint16_t version;
    uint16_t payload_bits;
    uint16_t flags;
    uint8_t kind;
    uint8_t channel;
    uint8_t payload_bytes;
    uint8_t client_id;
    uint8_t _pad[6];
    uint8_t payload[128];
}} StrataNetPacket;

static int g_host_ctx_sentinel = 1;
static int g_load_ctx_sentinel = 2;
static int g_sys_ctx_sentinel = 3;

static bool g_provide_net_pkt = false;
static bool g_corrupt_net_pkt_fp = false;
static uint32_t g_next_comp = 10;
static uint32_t g_fighter_comp = 0;
static uint32_t g_pred_comp = 0;
static uint32_t g_hit_comp = 0;
static uint32_t g_net_pkt_comp = 99;

typedef struct RegSys {{
    char name[64];
    BamSystemFn cb;
    void* user_data;
    uint32_t schedule;
    uint32_t query_count;
    BamTermDesc q0_terms[16];
    size_t q0_term_count;
    BamTermDesc q1_terms[16];
    size_t q1_term_count;
}} RegSys;

static RegSys g_systems[32];
static size_t g_sys_count = 0;

static uint8_t g_pose_buf[{pose_sz}];
static uint64_t g_entity_id = 0x000000010000002Aull;
static size_t g_iter_stage = 0;
static size_t g_active_qi = 0;
static uint32_t g_mark_changed_calls = 0;
static uint32_t g_msg_read_calls = 0;

static StrataNetPacket g_tx_pkts[16];
static size_t g_tx_pkt_count = 0;
static StrataNetPacket g_rx_pkts[16];
static size_t g_rx_pkt_count = 0;
static size_t g_rx_cursor = 0;

static void* mock_load_host_ctx(const void* lctx) {{
    (void)lctx;
    return &g_host_ctx_sentinel;
}}

static uint32_t mock_register_component(void* lctx, const BamComponentDesc* desc, uint32_t* out) {{
    (void)lctx;
    uint32_t id = g_next_comp++;
    if (strcmp(desc->name, "game::jit_mp::FighterPose") == 0) g_fighter_comp = id;
    if (strcmp(desc->name, "game::jit_mp::PredictedInput") == 0) g_pred_comp = id;
    if (strcmp(desc->name, "game::jit_mp::Hit") == 0) g_hit_comp = id;
    *out = id;
    return 0;
}}

static uint32_t mock_resolve_component(const void* hctx, const char* name, const BamComponentUuid* uuid, uint32_t* out) {{
    (void)hctx; (void)uuid;
    if (strcmp(name, "{pkt_canon}") == 0) {{
        if (!g_provide_net_pkt) return 4; /* NOT_FOUND */
        *out = g_net_pkt_comp;
        return 0;
    }}
    if (strcmp(name, "game::jit_mp::Hit") == 0 && g_hit_comp != 0) {{
        *out = g_hit_comp;
        return 0;
    }}
    return 4;
}}

static uint32_t mock_component_layout_info(const void* hctx, uint32_t comp, BamLayoutInfo* info) {{
    (void)hctx;
    if (comp == g_net_pkt_comp) {{
        info->flags = {flag_msg}u;
        info->size = {pkt_sz}u;
        info->align = 8u;
        info->schema_fingerprint = g_corrupt_net_pkt_fp ? (0x{pkt_fp:016X}ull ^ 1ull) : 0x{pkt_fp:016X}ull;
        return 0;
    }}
    if (comp == g_fighter_comp) {{
        info->flags = 0u;
        info->size = {pose_sz}u;
        info->schema_fingerprint = 0x{fp_schema:016X}ull;
        return 0;
    }}
    if (comp == g_pred_comp) {{
        info->flags = 0u;
        info->size = {pred_sz}u;
        info->schema_fingerprint = 0x{pred_schema:016X}ull;
        return 0;
    }}
    if (comp == g_hit_comp) {{
        info->flags = {flag_msg}u;
        info->size = 4u;
        info->schema_fingerprint = 0ull;
        return 0;
    }}
    return 4;
}}

static uint32_t mock_register_system_handle(void* lctx, const BamSystemDesc* desc, uint32_t* out) {{
    (void)lctx;
    RegSys* r = &g_systems[g_sys_count];
    memset(r, 0, sizeof(*r));
    snprintf(r->name, sizeof(r->name), "%s", desc->name);
    r->cb = desc->callback;
    r->user_data = desc->user_data;
    r->schedule = desc->schedule;
    r->query_count = (uint32_t)desc->query_count;
    if (desc->query_count > 0 && desc->queries[0].term_count > 0) {{
        r->q0_term_count = desc->queries[0].term_count;
        memcpy(r->q0_terms, desc->queries[0].terms, r->q0_term_count * sizeof(BamTermDesc));
    }}
    if (desc->query_count > 1 && desc->queries[1].term_count > 0) {{
        r->q1_term_count = desc->queries[1].term_count;
        memcpy(r->q1_terms, desc->queries[1].terms, r->q1_term_count * sizeof(BamTermDesc));
    }}
    *out = (uint32_t)(g_sys_count + 1);
    g_sys_count++;
    return 0;
}}

static uint32_t mock_sys_query(void* sctx, size_t qi, void** out_it) {{
    (void)sctx;
    g_active_qi = qi;
    g_iter_stage = 0;
    *out_it = (void*)(uintptr_t)(0x1000u + qi);
    return 0;
}}

static uint32_t mock_iter_reset(void* it) {{ (void)it; g_iter_stage = 0; return 0; }}
static uint8_t mock_iter_next_chunk(void* it, size_t* out_len) {{
    (void)it;
    if (g_active_qi == 1u && g_iter_stage == 0u) {{
        g_iter_stage = 1u;
        *out_len = 1u;
        return 1u;
    }}
    *out_len = 0u;
    return 0u;
}}
static const uint64_t* mock_iter_entities(const void* it) {{ (void)it; return &g_entity_id; }}
static const uint8_t* mock_iter_col_ro(const void* it, size_t ti) {{ (void)it; (void)ti; return g_pose_buf; }}
static uint8_t* mock_iter_col_mut_untracked(void* it, size_t ti) {{ (void)it; (void)ti; return g_pose_buf; }}
static uint32_t mock_iter_mark_changed_range(void* it, size_t ti, size_t start, size_t count) {{
    (void)it; (void)ti; (void)start; (void)count;
    g_mark_changed_calls++;
    return 0;
}}

static uint32_t mock_msg_read_batch(void* it, size_t ti, uint8_t* out_buf, size_t max_count, size_t* out_read) {{
    (void)it; (void)ti;
    g_msg_read_calls++;
    size_t avail = (g_rx_pkt_count > g_rx_cursor) ? (g_rx_pkt_count - g_rx_cursor) : 0u;
    size_t n = (avail < max_count) ? avail : max_count;
    if (n > 0u) {{
        memcpy(out_buf, &g_rx_pkts[g_rx_cursor], n * sizeof(StrataNetPacket));
        g_rx_cursor += n;
    }}
    *out_read = n;
    return 0;
}}

static uint32_t mock_msg_write_batch(void* it, size_t ti, const uint8_t* in_buf, size_t count) {{
    (void)it; (void)ti;
    for (size_t i = 0; i < count && g_tx_pkt_count < 16u; ++i) {{
        memcpy(&g_tx_pkts[g_tx_pkt_count++], in_buf + i * sizeof(StrataNetPacket), sizeof(StrataNetPacket));
    }}
    return 0;
}}

static void fill_api(BamHostApi* api) {{
    memset(api, 0, sizeof(*api));
    api->struct_size = (uint32_t)sizeof(BamHostApi);
    api->abi_version = 0x00030000u;
    api->slots[2] = (void*)mock_load_host_ctx;
    api->slots[3] = (void*)mock_register_component;
    api->slots[4] = (void*)mock_resolve_component;
    api->slots[9] = (void*)mock_iter_next_chunk;
    api->slots[10] = (void*)mock_iter_reset;
    api->slots[11] = (void*)mock_iter_entities;
    api->slots[12] = (void*)mock_iter_col_ro;
    api->slots[14] = (void*)mock_iter_col_mut_untracked;
    api->slots[15] = (void*)mock_iter_mark_changed_range;
    api->slots[30] = (void*)mock_msg_read_batch;
    api->slots[32] = (void*)mock_msg_write_batch;
    api->slots[53] = (void*)mock_component_layout_info;
    api->slots[60] = (void*)mock_register_system_handle;
    api->slots[7] = (void*)mock_sys_query;
}}

static RegSys* find_sys(const char* name) {{
    for (size_t i = 0; i < g_sys_count; ++i) {{
        if (strcmp(g_systems[i].name, name) == 0) return &g_systems[i];
    }}
    return NULL;
}}

int main(void) {{
    void* lib = dlopen("{dylib_path}", RTLD_NOW);
    if (!lib) {{ fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }}

    typedef const void* (*ManifestFn)(void);
    typedef uint32_t (*InitFn)(const BamHostApi*, void*, void**);
    typedef void (*ShutdownFn)(void*);

    ManifestFn manifest_fn = (ManifestFn)dlsym(lib, "bamabi_manifest");
    InitFn init_fn = (InitFn)dlsym(lib, "bamabi_init");
    ShutdownFn shutdown_fn = (ShutdownFn)dlsym(lib, "bamabi_shutdown");
    if (!manifest_fn || !init_fn || !shutdown_fn || !manifest_fn()) return 2;

    BamHostApi api;
    fill_api(&api);

    // 1. Non-networked host (`StrataNetPacket` absent): init succeeds cleanly without TX/RX.
    void* inst1 = NULL;
    g_provide_net_pkt = false;
    g_sys_count = 0;
    if (init_fn(&api, &g_load_ctx_sentinel, &inst1) != 0u || !inst1) return 3;
    if (find_sys("__strata_net_rx_0") != NULL || find_sys("__strata_net_tx_0") != NULL) return 4;
    RegSys* emit_sys = find_sys("emit_on_change");
    if (!emit_sys || emit_sys->q0_term_count != 1u || emit_sys->q0_terms[0].mode != 6u || emit_sys->q0_terms[0].flags != 0u) return 5;
    shutdown_fn(inst1);

    // 2. Host with mismatched `StrataNetPacket` fingerprint: init fails with TYPE_MISMATCH (7).
    void* inst2 = NULL;
    g_provide_net_pkt = true;
    g_corrupt_net_pkt_fp = true;
    g_sys_count = 0;
    uint32_t mismatch_rc = init_fn(&api, &g_load_ctx_sentinel, &inst2);
    if (mismatch_rc != {ffi_type_mismatch}u || inst2 != NULL) return 6;

    // 3. Full networked host: init succeeds and registers RX before user systems and TX after.
    void* inst3 = NULL;
    g_corrupt_net_pkt_fp = false;
    g_sys_count = 0;
    if (init_fn(&api, &g_load_ctx_sentinel, &inst3) != 0u || !inst3) return 7;
    RegSys* rx = find_sys("__strata_net_rx_0");
    RegSys* tx = find_sys("__strata_net_tx_0");
    if (!rx || !tx) return 8;
    if (strcmp(g_systems[0].name, "__strata_net_rx_0") != 0) return 9;
    if (strcmp(g_systems[g_sys_count - 1].name, "__strata_net_tx_0") != 0) return 10;
    if (tx->q1_terms[0].mode != 6u || tx->q1_terms[0].flags != 0u) return 11;

    // Populate `FighterPose` row for TX test.
    memset(g_pose_buf, 0, sizeof(g_pose_buf));
    float yaw = 37.25f, grounded = 1.0f, precise = 1234.5f;
    float pos[3] = {{ 12.5f, -25.0f, 49.0f }};
    uint32_t seq = 42u;
    uint8_t alive = 1u;
    memcpy(g_pose_buf + {yaw_off}, &yaw, 4);
    memcpy(g_pose_buf + {grounded_off}, &grounded, 4);
    memcpy(g_pose_buf + {precise_off}, &precise, 4);
    memcpy(g_pose_buf + {pos_off}, pos, 12);
    memcpy(g_pose_buf + {seq_off}, &seq, 4);
    memcpy(g_pose_buf + {alive_off}, &alive, 1);

    g_tx_pkt_count = 0;
    if (tx->cb(&g_sys_ctx_sentinel, tx->user_data) != 0u) return 12;
    if (g_tx_pkt_count != 1u) return 13;

    const StrataNetPacket* pkt = &g_tx_pkts[0];
    if (pkt->magic != 0x{magic:08X}u || pkt->version != {ver}u) return 14;
    if (pkt->module_net_fingerprint != 0x{mod_net_fp:016X}ull) return 15;
    if (pkt->item_schema_fingerprint != 0x{fp_schema:016X}ull) return 16;
    if (pkt->target_id != 0x{fp_target_id:016X}ull) return 17;
    if (pkt->entity_bits != g_entity_id || pkt->kind != 1u || pkt->channel != 0u) return 18;
    if (pkt->payload_bits != {pbits}u || pkt->payload_bytes != {pbytes}u) return 19;

    const uint8_t exp_payload[128] = {{ {exp_payload_hex} }};
    if (memcmp(pkt->payload, exp_payload, {pbytes}u) != 0) {{
        fprintf(stderr, "TX quantized payload mismatch\n");
        return 20;
    }}

    // 4. RX Handshake rejection (corrupt module_net_fingerprint & item_schema_fingerprint).
    g_rx_pkts[0] = *pkt;
    g_rx_pkts[0].module_net_fingerprint ^= 1ull;
    g_rx_pkts[1] = *pkt;
    g_rx_pkts[1].item_schema_fingerprint ^= 1ull;
    g_rx_pkt_count = 2u;
    g_rx_cursor = 0u;
    g_mark_changed_calls = 0u;
    g_msg_read_calls = 0u;
    if (rx->cb(&g_sys_ctx_sentinel, rx->user_data) != 0u) return 21;
    if (g_msg_read_calls == 0u || g_mark_changed_calls != 0u) return 22;

    // 5. RX `&mut?` no-op gating: packet matching existing bytes must NOT mark changed.
    // First apply exact decoded bytes via one round, then re-apply same packet and assert 0 marks.
    g_rx_pkts[0] = *pkt;
    g_rx_pkt_count = 1u;
    g_rx_cursor = 0u;
    g_mark_changed_calls = 0u;
    if (rx->cb(&g_sys_ctx_sentinel, rx->user_data) != 0u) return 23;
    g_rx_cursor = 0u;
    g_mark_changed_calls = 0u;
    if (rx->cb(&g_sys_ctx_sentinel, rx->user_data) != 0u) return 24;
    if (g_mark_changed_calls != 0u) return 25;

    // 6. RX valid delta packet with new values updates memory and marks changed range (Slot 15).
    StrataNetPacket alt_pkt = *pkt;
    const uint8_t alt_payload_bytes[128] = {{ {alt_payload_hex} }};
    memcpy(alt_pkt.payload, alt_payload_bytes, 128u);
    g_rx_pkts[0] = alt_pkt;
    g_rx_pkt_count = 1u;
    g_rx_cursor = 0u;
    g_mark_changed_calls = 0u;
    if (rx->cb(&g_sys_ctx_sentinel, rx->user_data) != 0u) return 26;
    if (g_mark_changed_calls != 1u) return 27;

    float got_yaw = 0.0f;
    uint32_t got_seq = 0u;
    uint8_t got_alive = 1u;
    memcpy(&got_yaw, g_pose_buf + {yaw_off}, 4);
    memcpy(&got_seq, g_pose_buf + {seq_off}, 4);
    memcpy(&got_alive, g_pose_buf + {alive_off}, 1);
    if (fabsf(got_yaw - {alt_yaw_deq:.6}f) > 1e-3f || got_seq != 99u || got_alive != 0u) return 28;

    // 7. `consume_hits(stream_in<Hit>)` executes cleanly (`MSG_READ_BATCH` Slot 30).
    RegSys* ch_sys = find_sys("consume_hits");
    if (!ch_sys) return 29;
    g_rx_pkt_count = 0u;
    g_rx_cursor = 0u;
    if (ch_sys->cb(&g_sys_ctx_sentinel, ch_sys->user_data) != 0u) return 30;

    shutdown_fn(inst3);
    dlclose(lib);
    return 0;
}}
"#,
        pose_sz = fp_layout.size,
        pred_sz = mir
            .layouts
            .iter()
            .find(|l| l.canonical_name == "game::jit_mp::PredictedInput")
            .unwrap()
            .size,
        pkt_canon = STRATA_NET_PACKET_CANONICAL_NAME,
        flag_msg = bamabi_sys::BAM_STORAGE_FLAG_MESSAGE,
        pkt_sz = STRATA_NET_PACKET_SIZE,
        pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
        fp_schema = fp_nc.schema_fingerprint,
        pred_schema = pred_nc.schema_fingerprint,
        dylib_path = artifact.dylib_path.display(),
        ffi_type_mismatch = bamabi_sys::FfiResult::TYPE_MISMATCH.0,
        magic = STRATA_NET_PACKET_MAGIC,
        ver = STRATA_NET_WIRE_VERSION,
        mod_net_fp = mod_net_fp,
        fp_target_id = fp_target_id,
        pbits = fp_nc.packed_bits,
        pbytes = fp_nc.packed_bytes,
        exp_payload_hex = exp_payload_hex,
        alt_payload_hex = alt_payload_hex,
        yaw_off = yaw_off,
        grounded_off = grounded_off,
        precise_off = precise_off,
        pos_off = pos_off,
        seq_off = seq_off,
        alive_off = alive_off,
        alt_yaw_deq = alt_yaw_deq,
    );

    let c_path = tmp.path().join("jit_vtable_harness.c");
    let bin_path = tmp.path().join("jit_vtable_harness");
    fs::write(&c_path, c_src).expect("write harness .c");

    let cc = find_c_compiler();
    let mut cmd = Command::new(cc);
    cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
        .arg(&c_path)
        .arg("-o")
        .arg(&bin_path)
        .arg("-lm");
    if cfg!(target_os = "linux") {
        cmd.arg("-ldl");
    }
    let compile_out = cmd.output().expect("compile harness");
    assert!(
        compile_out.status.success(),
        "C harness compile failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compile_out.stdout),
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let run_out = Command::new(&bin_path).output().expect("run harness");
    assert!(
        run_out.status.success(),
        "JIT vtable harness failed with {:?}:\nstdout:\n{}\nstderr:\n{}",
        run_out.status.code(),
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr)
    );
}

#[test]
fn jit_mutable_changed_query_replicated_resource_and_component_fingerprint_mismatch() {
    let src = r#"
module game::jit_res_mut @version(1.0.0);

@net(reliable, channel = 2)
@authority(server)
resource MatchClock {
    round: u32 = 1,
}

@net(reliable, channel = 0)
@authority(server)
component Counter {
    val: u32 = 0,
}

@authority(server)
sys bump_changed(clk: &res MatchClock) {
    let _ = clk.round;
    for e in query(c: &mut Counter).changed() {
        e.c.val += 1;
    }
}

schedule FixedUpdate { bump_changed }
"#;
    let analyzed = analyze_source("jit_res_mut.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "strata_res_mut".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }

    let clk_nc = mir
        .net_components
        .iter()
        .find(|nc| nc.canonical_name == "game::jit_res_mut::MatchClock")
        .expect("MatchClock net_component");
    let cnt_nc = mir
        .net_components
        .iter()
        .find(|nc| nc.canonical_name == "game::jit_res_mut::Counter")
        .expect("Counter net_component");
    let host_api_slots = HOST_API_SLOTS;

    let c_src = format!(
        r#"
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct BamStrView {{ const char* ptr; size_t len; }} BamStrView;
typedef struct BamComponentUuid {{ uint8_t bytes[16]; }} BamComponentUuid;
typedef struct BamFieldDesc {{
    uint32_t struct_size; uint32_t kind; BamStrView name; BamStrView type_tag;
    size_t offset; size_t size; size_t align;
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
typedef struct BamChangeTicks {{
    uint32_t added; uint32_t changed; uint32_t last_run; uint32_t this_run;
}} BamChangeTicks;
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
    uint32_t struct_size; uint32_t abi_version; void* slots[{host_api_slots}];
}} BamHostApi;
typedef struct StrataNetPacket {{
    uint64_t module_net_fingerprint; uint64_t item_schema_fingerprint;
    uint64_t target_id; uint64_t entity_bits;
    uint32_t magic; uint32_t tick_or_seq;
    uint16_t version; uint16_t payload_bits; uint16_t flags;
    uint8_t kind; uint8_t channel; uint8_t payload_bytes; uint8_t client_id;
    uint8_t _pad[6]; uint8_t payload[128];
}} StrataNetPacket;

static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static uint32_t g_clk_comp = 10, g_cnt_comp = 11, g_pkt_comp = 12;
static bool g_corrupt_cnt_fp = false;
static uint32_t g_clock_round = 7u;
static StrataNetPacket g_pkts[4];
static size_t g_pkt_n = 0, g_pkt_cur = 0;

typedef struct RegSys {{
    char name[64]; BamSystemFn cb; void* ud;
    BamTermDesc q0[16]; size_t q0_n;
}} RegSys;
static RegSys g_sys[16];
static size_t g_sys_n = 0;

static void* m_lhc(const void* p) {{ (void)p; return &g_hctx; }}
static uint32_t m_reg_c(void* l, const BamComponentDesc* d, uint32_t* o) {{
    (void)l; (void)d; *o = g_cnt_comp; return 0;
}}
static uint32_t m_res_c(const void* h, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)h; (void)u;
    if (strcmp(n, "{pkt_canon}") == 0) {{ *o = g_pkt_comp; return 0; }}
    if (strcmp(n, "game::jit_res_mut::MatchClock") == 0) {{ *o = g_clk_comp; return 0; }}
    return 4;
}}
static uint32_t m_linfo(const void* h, uint32_t c, BamLayoutInfo* i) {{
    (void)h;
    if (c == g_pkt_comp) {{
        i->flags = {flag_msg}u; i->size = 184u; i->align = 8u;
        i->schema_fingerprint = 0x{pkt_fp:016X}ull; return 0;
    }}
    if (c == g_clk_comp) {{
        i->flags = {flag_res}u; i->size = 4u; i->align = 4u;
        i->schema_fingerprint = 0x{clk_fp:016X}ull; return 0;
    }}
    if (c == g_cnt_comp) {{
        i->flags = 0u; i->size = 4u; i->align = 4u;
        i->schema_fingerprint = g_corrupt_cnt_fp ? (0x{cnt_fp:016X}ull ^ 1ull) : 0x{cnt_fp:016X}ull;
        return 0;
    }}
    return 4;
}}
static uint32_t m_reg_s(void* l, const BamSystemDesc* d, uint32_t* o) {{
    (void)l;
    RegSys* r = &g_sys[g_sys_n];
    memset(r, 0, sizeof(*r));
    snprintf(r->name, sizeof(r->name), "%s", d->name);
    r->cb = d->callback; r->ud = d->user_data;
    if (d->query_count > 0 && d->queries[0].term_count > 0) {{
        r->q0_n = d->queries[0].term_count;
        memcpy(r->q0, d->queries[0].terms, r->q0_n * sizeof(BamTermDesc));
    }}
    *o = (uint32_t)(++g_sys_n);
    return 0;
}}
static uint32_t m_sq(void* s, size_t qi, void** o) {{ (void)s; *o = (void*)(uintptr_t)(0x2000u + qi); return 0; }}
static uint32_t m_ireset(void* i) {{ (void)i; return 0; }}
static uint8_t m_inext(void* i, size_t* l) {{ (void)i; *l = 0; return 0; }}
static const uint8_t* m_res_ptr(const void* s, uint32_t c, BamChangeTicks* t) {{
    (void)s;
    if (c != g_clk_comp) return NULL;
    if (t) {{ t->added = 1u; t->changed = 5u; t->last_run = 3u; t->this_run = 6u; }}
    return (const uint8_t*)&g_clock_round;
}}
static uint8_t* m_res_mut_ptr(void* s, uint32_t c, BamChangeTicks* t) {{
    (void)s; (void)t;
    return (c == g_clk_comp) ? (uint8_t*)&g_clock_round : NULL;
}}
static uint32_t m_mrb(void* it, size_t ti, uint8_t* out, size_t max_c, size_t* got) {{
    (void)it; (void)ti;
    size_t av = (g_pkt_n > g_pkt_cur) ? (g_pkt_n - g_pkt_cur) : 0u;
    size_t n = (av < max_c) ? av : max_c;
    if (n > 0u) {{ memcpy(out, &g_pkts[g_pkt_cur], n * sizeof(StrataNetPacket)); g_pkt_cur += n; }}
    *got = n;
    return 0;
}}
static uint32_t m_mwb(void* it, size_t ti, const uint8_t* inp, size_t c) {{
    (void)it; (void)ti;
    for (size_t i = 0; i < c && g_pkt_n < 4u; ++i) {{
        memcpy(&g_pkts[g_pkt_n++], inp + i * sizeof(StrataNetPacket), sizeof(StrataNetPacket));
    }}
    return 0;
}}
static RegSys* fsys(const char* n) {{
    for (size_t i = 0; i < g_sys_n; ++i) if (strcmp(g_sys[i].name, n) == 0) return &g_sys[i];
    return NULL;
}}

int main(void) {{
    void* lib = dlopen("{dylib_path}", RTLD_NOW);
    if (!lib) return 1;
    uint32_t (*init_fn)(const BamHostApi*, void*, void**) = (uint32_t (*)(const BamHostApi*, void*, void**))dlsym(lib, "bamabi_init");
    void (*shut_fn)(void*) = (void (*)(void*))dlsym(lib, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = 0x00030000u;
    api.slots[2] = (void*)m_lhc;
    api.slots[3] = (void*)m_reg_c;
    api.slots[4] = (void*)m_res_c;
    api.slots[7] = (void*)m_sq;
    api.slots[9] = (void*)m_inext;
    api.slots[10] = (void*)m_ireset;
    api.slots[30] = (void*)m_mrb;
    api.slots[32] = (void*)m_mwb;
    api.slots[34] = (void*)m_res_ptr;
    api.slots[35] = (void*)m_res_mut_ptr;
    api.slots[53] = (void*)m_linfo;
    api.slots[60] = (void*)m_reg_s;

    // 1. Component schema fingerprint mismatch via Slot 53 returns TYPE_MISMATCH.
    void* bad_inst = NULL;
    g_corrupt_cnt_fp = true;
    g_sys_n = 0;
    if (init_fn(&api, &g_lctx, &bad_inst) != {ffi_type_mismatch}u || bad_inst != NULL) return 2;

    // 2. Valid init registers mutable + `.changed()` query as (WRITE, CHANGED) with flags == 0.
    void* inst = NULL;
    g_corrupt_cnt_fp = false;
    g_sys_n = 0;
    if (init_fn(&api, &g_lctx, &inst) != 0u || !inst) return 3;
    RegSys* bump = fsys("bump_changed");
    if (!bump || bump->q0_n != 2u) return 4;
    if (bump->q0[0].mode != 1u || bump->q0[0].flags != 0u) return 5;
    if (bump->q0[1].mode != 6u || bump->q0[1].flags != 0u) return 6;

    // 3. Replicated resource TX -> RX roundtrip (`PACKET_KIND_RESOURCE_DELTA == 2`).
    RegSys* tx = fsys("__strata_net_tx_0");
    RegSys* rx = fsys("__strata_net_rx_0");
    if (!tx || !rx) return 7;
    g_pkt_n = 0;
    if (tx->cb(&g_sctx, tx->ud) != 0u || g_pkt_n != 1u) return 8;
    if (g_pkts[0].kind != 2u || g_pkts[0].channel != 2u || (g_pkts[0].flags & 0x10u) == 0u) return 9;
    g_clock_round = 1u;
    g_pkt_cur = 0;
    if (rx->cb(&g_sctx, rx->ud) != 0u) return 10;
    if (g_clock_round != 7u) return 11;

    shut_fn(inst);
    dlclose(lib);
    return 0;
}}
"#,
        pkt_canon = STRATA_NET_PACKET_CANONICAL_NAME,
        flag_msg = bamabi_sys::BAM_STORAGE_FLAG_MESSAGE,
        flag_res = bamabi_sys::BAM_STORAGE_FLAG_RESOURCE,
        pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
        clk_fp = clk_nc.schema_fingerprint,
        cnt_fp = cnt_nc.schema_fingerprint,
        dylib_path = artifact.dylib_path.display(),
        ffi_type_mismatch = bamabi_sys::FfiResult::TYPE_MISMATCH.0,
    );

    let c_path = tmp.path().join("jit_res_mut_harness.c");
    let bin_path = tmp.path().join("jit_res_mut_harness");
    fs::write(&c_path, c_src).expect("write res/mut harness .c");

    let cc = find_c_compiler();
    let mut cmd = Command::new(cc);
    cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
        .arg(&c_path)
        .arg("-o")
        .arg(&bin_path);
    if cfg!(target_os = "linux") {
        cmd.arg("-ldl");
    }
    let compile_out = cmd.output().expect("compile res/mut harness");
    assert!(
        compile_out.status.success(),
        "C res/mut harness compile failed:\n{}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let run_out = Command::new(&bin_path)
        .output()
        .expect("run res/mut harness");
    assert!(
        run_out.status.success(),
        "JIT res/mut harness failed with {:?}",
        run_out.status.code()
    );
}

#[test]
fn jit_rejects_missing_wire_field_and_rounds_quantized_integer_decode() {
    let src = r#"
module game::jit_quant_int @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
component QuantInt {
    @quantize(min = -10.0, max = 10.0, bits = 8)
    qi: i32 = 0,
}

schedule FixedUpdate {}
"#;
    let analyzed = analyze_source("jit_quant_int.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");

    // 1. Missing wire field must return an explicit error instead of silently dropping.
    let mut bad_mir = mir.clone();
    bad_mir.net_components[0].wire_fields[0].field_name = "missing_cold_field".to_owned();
    let err = match emit_pic_object(
        &bad_mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "bad_field".to_owned(),
            opt_level: JitOptLevel::FastCompile,
        },
    ) {
        Err(e) => e,
        Ok(_) => panic!("missing wire field must fail explicitly"),
    };
    assert!(
        err.to_string().contains("missing from solved layout"),
        "unexpected err: {err}"
    );

    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }

    // 2. Compile valid QuantInt dylib and verify qi = 1 round-trips to 1 via libm round() -> fcvt_to_sint_sat.
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_quant_int".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile QuantInt dylib");
    let qi_nc = &mir.net_components[0];
    let host_api_slots = HOST_API_SLOTS;

    let c_src = format!(
        r#"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>

typedef uint32_t BamResult;
typedef uint32_t BamComponent;
typedef uint32_t BamSystem;
typedef struct BamHostCtx BamHostCtx;
typedef struct BamLoadCtx BamLoadCtx;
typedef struct BamSystemCtx BamSystemCtx;
typedef struct BamIter BamIter;
typedef struct BamLayoutInfo {{
    uint32_t struct_size, flags;
    uint8_t uuid[16];
    uint64_t schema_fingerprint;
    size_t size, align;
    const void* fields;
    size_t field_count;
}} BamLayoutInfo;
typedef struct BamSystemDesc {{
    uint32_t struct_size, flags;
    const char* name;
    const void* queries; size_t query_count;
    BamResult (*callback)(BamSystemCtx*, void*);
    void* user_data;
    uint32_t schedule;
    uint32_t reserved0;
    const char* const* after; size_t after_count;
    const char* const* before; size_t before_count;
    void* run_if; void* run_if_user_data;
    const char* const* in_sets; size_t in_set_count;
    const char* const* after_weak; size_t after_weak_count;
    const char* const* before_weak; size_t before_weak_count;
}} BamSystemDesc;
typedef struct BamHostApi {{
    uint32_t struct_size;
    uint32_t abi_version;
    void* slots[{host_api_slots}];
}} BamHostApi;

static BamSystemDesc g_rx_sys, g_tx_sys;
static int g_has_rx = 0, g_has_tx = 0;
static uint8_t g_pkts[4][184];
static size_t g_pkt_n = 0, g_pkt_cur = 0;
static int32_t g_qi = 1;
static uint64_t g_ent = 42ull;
static int g_msg_it = 0, g_q_it = 0, g_q_step = 0;

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_res(const BamHostCtx* h, const char* n, const void* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "{pkt_canon}") == 0) {{ *o = 9u; return 0u; }}
    return 10u;
}}
static BamResult m_reg_c(BamLoadCtx* l, const void* d, BamComponent* o) {{ (void)l; (void)d; *o = 1u; return 0u; }}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h;
    memset(o, 0, sizeof(*o));
    o->struct_size = (uint32_t)sizeof(*o);
    if (c == 9u) {{ o->flags = {flag_msg}u; o->size = 184u; o->align = 8u; o->schema_fingerprint = 0x{pkt_fp:016X}ull; return 0u; }}
    if (c == 1u) {{ o->size = 4u; o->align = 4u; o->schema_fingerprint = 0x{qi_fp:016X}ull; return 0u; }}
    return 10u;
}}
static BamResult m_reg_s(BamLoadCtx* l, const BamSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "__strata_net_rx_0") == 0) {{ g_rx_sys = *d; g_has_rx = 1; }}
    if (strcmp(d->name, "__strata_net_tx_0") == 0) {{ g_tx_sys = *d; g_has_tx = 1; }}
    if (o) *o = 1u;
    return 0u;
}}
static BamResult m_mnt(BamLoadCtx* l, BamSystem s, uint32_t sc, uint32_t ss) {{ (void)l; (void)s; (void)sc; (void)ss; return 0u; }}
static BamResult m_sq(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc;
    if (qi == 0u) {{ *o = (BamIter*)&g_msg_it; return 0u; }}
    if (qi == 1u) {{ g_q_step = 0; *o = (BamIter*)&g_q_it; return 0u; }}
    *o = NULL; return 10u;
}}
static BamResult m_it_rst(BamIter* i) {{ (void)i; g_q_step = 0; return 0u; }}
static uint8_t m_it_next(BamIter* i, size_t* l) {{
    if (i == (BamIter*)&g_q_it && g_q_step == 0) {{ g_q_step = 1; *l = 1u; return 1u; }}
    *l = 0u; return 0u;
}}
static const uint64_t* m_it_ents(const BamIter* i) {{ (void)i; return &g_ent; }}
static const uint8_t* m_it_ro(const BamIter* i, size_t ti) {{ (void)i; (void)ti; return (const uint8_t*)&g_qi; }}
static uint8_t* m_it_mut(BamIter* i, size_t ti) {{ (void)i; (void)ti; return (uint8_t*)&g_qi; }}
static BamResult m_it_mark(BamIter* i, size_t ti, size_t s, size_t c) {{ (void)i; (void)ti; (void)s; (void)c; return 0u; }}
static BamResult m_msg_rb(BamIter* i, size_t ti, uint8_t* b, size_t m, size_t* r) {{
    (void)i; (void)ti;
    size_t av = (g_pkt_n > g_pkt_cur) ? (g_pkt_n - g_pkt_cur) : 0u;
    size_t tk = (av < m) ? av : m;
    if (tk > 0u) {{ memcpy(b, g_pkts[g_pkt_cur], tk * 184u); g_pkt_cur += tk; }}
    *r = tk; return 0u;
}}
static BamResult m_msg_wb(BamIter* i, size_t ti, const uint8_t* b, size_t c) {{
    (void)i; (void)ti;
    if (c > 0u && g_pkt_n + c <= 4u) {{ memcpy(g_pkts[g_pkt_n], b, c * 184u); g_pkt_n += c; }}
    return 0u;
}}

int main(void) {{
    void* lib = dlopen("{dylib_path}", RTLD_NOW);
    if (!lib) return 1;
    typedef BamResult (*InitFn)(const BamHostApi*, BamLoadCtx*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(lib, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(lib, "bamabi_shutdown");
    if (!init_fn || !shut_fn) return 2;

    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = 0x00030000u;
    api.slots[2] = (void*)m_hc;
    api.slots[3] = (void*)m_reg_c;
    api.slots[4] = (void*)m_res;
    api.slots[7] = (void*)m_sq;
    api.slots[9] = (void*)m_it_next;
    api.slots[10] = (void*)m_it_rst;
    api.slots[11] = (void*)m_it_ents;
    api.slots[12] = (void*)m_it_ro;
    api.slots[14] = (void*)m_it_mut;
    api.slots[15] = (void*)m_it_mark;
    api.slots[30] = (void*)m_msg_rb;
    api.slots[32] = (void*)m_msg_wb;
    api.slots[53] = (void*)m_linfo;
    api.slots[60] = (void*)m_reg_s;
    api.slots[62] = (void*)m_mnt;

    int lctx = 1, sctx = 1;
    void* inst = NULL;
    if (init_fn(&api, (BamLoadCtx*)&lctx, &inst) != 0u || !inst) return 3;
    if (!g_has_rx || !g_has_tx) return 4;

    g_qi = 1;
    g_pkt_n = 0u;
    if (g_tx_sys.callback((BamSystemCtx*)&sctx, g_tx_sys.user_data) != 0u || g_pkt_n != 1u) return 5;

    g_qi = -99;
    g_pkt_cur = 0u;
    if (g_rx_sys.callback((BamSystemCtx*)&sctx, g_rx_sys.user_data) != 0u) return 6;
    if (g_qi != 1) {{
        fprintf(stderr, "expected g_qi == 1, got %d\n", g_qi);
        return 7;
    }}

    shut_fn(inst);
    dlclose(lib);
    return 0;
}}
"#,
        pkt_canon = STRATA_NET_PACKET_CANONICAL_NAME,
        flag_msg = bamabi_sys::BAM_STORAGE_FLAG_MESSAGE,
        pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
        qi_fp = qi_nc.schema_fingerprint,
        dylib_path = artifact.dylib_path.display(),
    );
    let c_path = tmp.path().join("jit_quant_int_harness.c");
    let bin_path = tmp.path().join("jit_quant_int_harness");
    fs::write(&c_path, c_src).unwrap();
    let cc = find_c_compiler();
    let mut cmd = Command::new(cc);
    cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror"])
        .arg(&c_path)
        .arg("-o")
        .arg(&bin_path);
    if cfg!(target_os = "linux") {
        cmd.arg("-ldl");
    }
    let comp = cmd.output().unwrap();
    assert!(
        comp.status.success(),
        "compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&bin_path).output().unwrap();
    assert!(
        run.status.success(),
        "JIT QuantInt harness failed with code {:?}:\n{}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
}

static GENERATED_CARGO_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn is_valid_git_rev_jit(s: &str) -> bool {
    !s.is_empty() && s.len() >= 7 && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn resolve_wire_rev_jit(ws_root: &std::path::Path) -> String {
    let abi_lock = ws_root.join("abi-lock.toml");
    if abi_lock.is_file() {
        let content = fs::read_to_string(&abi_lock)
            .unwrap_or_else(|e| panic!("failed reading `{}`: {e}", abi_lock.display()));
        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if let Some((key, val)) = line.split_once('=')
                && key.trim() == "wire_rev"
            {
                let rev = val.trim().trim_matches('"').trim_matches('\'').trim();
                if is_valid_git_rev_jit(rev) {
                    return rev.to_owned();
                }
                panic!("invalid `wire_rev` in `{}`: `{rev}`", abi_lock.display());
            }
        }
    }

    let cargo_lock = ws_root.join("Cargo.lock");
    if cargo_lock.is_file() {
        let content = fs::read_to_string(&cargo_lock)
            .unwrap_or_else(|e| panic!("failed reading `{}`: {e}", cargo_lock.display()));
        let mut in_pkg = false;
        let mut pkg_name: Option<String> = None;
        let mut pkg_source: Option<String> = None;
        let mut fallback: Option<String> = None;

        let flush_pkg = |name: Option<&str>,
                         source: Option<&str>,
                         fallback: &mut Option<String>|
         -> Option<String> {
            let src = source?;
            if !src.contains("bamabi-wire.git") {
                return None;
            }
            let rev = src.split_once('#')?.1.split(['"', '&', ' ']).next()?;
            if !is_valid_git_rev_jit(rev) {
                return None;
            }
            if name == Some("bamabi_sys") {
                return Some(rev.to_owned());
            }
            if fallback.is_none() {
                *fallback = Some(rev.to_owned());
            }
            None
        };

        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line == "[[package]]" {
                if in_pkg
                    && let Some(found) =
                        flush_pkg(pkg_name.as_deref(), pkg_source.as_deref(), &mut fallback)
                {
                    return found;
                }
                in_pkg = true;
                pkg_name = None;
                pkg_source = None;
                continue;
            }
            if in_pkg && let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"');
                if k == "name" {
                    pkg_name = Some(v.to_owned());
                } else if k == "source" {
                    pkg_source = Some(v.to_owned());
                }
            }
        }
        if in_pkg
            && let Some(found) =
                flush_pkg(pkg_name.as_deref(), pkg_source.as_deref(), &mut fallback)
        {
            return found;
        }
        if let Some(rev) = fallback {
            return rev;
        }
    }

    if let Ok(wire_dir) = fs::canonicalize(ws_root.join("..").join("bamabi-wire"))
        && let Ok(out) = Command::new("git")
            .arg("-C")
            .arg(&wire_dir)
            .args(["rev-parse", "HEAD"])
            .output()
        && out.status.success()
    {
        let rev = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if is_valid_git_rev_jit(&rev) {
            return rev;
        }
    }

    panic!(
        "unable to resolve bamabi-wire revision from `{}`, `{}`, or sibling `../bamabi-wire`",
        abi_lock.display(),
        cargo_lock.display()
    );
}

fn cargo_lock_has_git_wire_source_jit(ws_root: &std::path::Path) -> bool {
    let lock = ws_root.join("Cargo.lock");
    let Ok(content) = fs::read_to_string(lock) else {
        return false;
    };
    content
        .lines()
        .any(|l| l.contains("source = \"") && l.contains("bamabi-wire.git#"))
}

fn write_offline_patch_config_jit(ws_root: &std::path::Path, crate_dir: &std::path::Path) {
    let lock = ws_root.join("Cargo.lock");
    if lock.exists() {
        fs::copy(&lock, crate_dir.join("Cargo.lock")).expect("copy Cargo.lock");
    }
    let mut cfg = String::new();
    if let Ok(wire) = fs::canonicalize(ws_root.join("..").join("bamabi-wire")) {
        let w = wire.display();
        if cargo_lock_has_git_wire_source_jit(ws_root) {
            let wire_rev = resolve_wire_rev_jit(ws_root);
            cfg.push_str(&format!(
                "[patch.\"https://github.com/yaga-simha/bamabi-wire.git\"]\n\
                 bamabi_sys = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_macros = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_sdk_gen = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_guest_sys = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_guest = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n"
            ));
        } else {
            cfg.push_str(&format!(
                "[patch.\"https://github.com/yaga-simha/bamabi-wire.git\"]\n\
                 bamabi_sys = {{ path = \"{w}/crates/bamabi_sys\" }}\n\
                 bamabi_macros = {{ path = \"{w}/crates/bamabi_macros\" }}\n\
                 bamabi_sdk_gen = {{ path = \"{w}/crates/bamabi_sdk_gen\" }}\n\
                 bamabi_guest_sys = {{ path = \"{w}/crates/bamabi_guest_sys\" }}\n\
                 bamabi_guest = {{ path = \"{w}/crates/bamabi_guest\" }}\n"
            ));
        }
    }
    if let Ok(tools) = fs::canonicalize(ws_root.join("..").join("bamabi-tools")) {
        let t = tools.display();
        cfg.push_str(&format!(
            "\n[patch.\"https://github.com/yaga-simha/bamabi-tools.git\"]\n\
             bamabi_manifest = {{ path = \"{t}/crates/bamabi_manifest\" }}\n\
             bamabi_trust = {{ path = \"{t}/crates/bamabi_trust\" }}\n"
        ));
    }
    if let Ok(core) = fs::canonicalize(ws_root.join("..").join("bamabi-core")) {
        let c = core.display();
        cfg.push_str(&format!(
            "\n[patch.\"https://github.com/yaga-simha/bamabi-core.git\"]\n\
             bamabi_host_sys = {{ path = \"{c}/crates/bamabi_host_sys\" }}\n\
             bamabi_host = {{ path = \"{c}/crates/bamabi_host\" }}\n"
        ));
    }
    if !cfg.is_empty() {
        let cargo_dir = crate_dir.join(".cargo");
        fs::create_dir_all(&cargo_dir).expect("mkdir .cargo");
        fs::write(cargo_dir.join("config.toml"), cfg).expect("write .cargo/config.toml");
    }
}

fn cargo_offline_flag_jit() -> Option<&'static str> {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)?;
    ws_root
        .join("..")
        .join("bamabi-wire")
        .is_dir()
        .then_some("--offline")
}

fn sanitized_cargo_cmd_jit() -> Command {
    let cargo = std::env::var_os("CARGO")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    for var in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "LLVM_PROFILE_FILE",
        "CARGO_LLVM_COV",
        "CARGO_LLVM_COV_TARGET_DIR",
        "CARGO_LLVM_COV_BUILD_DIR",
        "RUSTC_WRAPPER",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

#[test]
fn jit_quantized_ivec_uvec_and_i64_u64_bit_exact_with_c99_rust_guest_bevy_native_and_oracle() {
    use std::path::PathBuf;
    use strata_codegen::{
        BevyNativeOptions, RustGuestOptions, emit_bevy_native, emit_c99, emit_rust_guest_with,
    };

    let src = r#"
module game::jit_ivec_parity @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
component IntVecQuantNet {
    @quantize(min = -50.0, max = 50.0, bits = 10)
    iv2: ivec2 = ivec2(0, 0),
    @quantize(min = -20.0, max = 20.0, bits = 8)
    iv3: ivec3 = ivec3(0, 0, 0),
    @quantize(min = 0.0, max = 100.0, bits = 8)
    uv2: uvec2 = uvec2(0, 0),
    @quantize(min = -1.5, max = 1.5, bits = 2)
    iv2_tie: ivec2 = ivec2(0, 0),
    @quantize(min = -20.0, max = 20.0, bits = 8)
    qi64: i64 = 0,
    @quantize(min = 0.0, max = 100.0, bits = 8)
    qu64: u64 = 0,
}

schedule FixedUpdate {}
"#;
    let analyzed = analyze_source("jit_ivec_parity.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let nc = &mir.net_components[0];
    let layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == nc.canonical_name)
        .expect("IntVecQuantNet layout");

    let field_off = |name: &str| -> usize {
        layout
            .fields
            .iter()
            .find(|f| f.name == name)
            .expect(name)
            .offset
    };
    let iv2_off = field_off("iv2");
    let iv3_off = field_off("iv3");
    let uv2_off = field_off("uv2");
    let iv2_tie_off = field_off("iv2_tie");
    let qi64_off = field_off("qi64");
    let qu64_off = field_off("qu64");

    // Oracle payload + tie payload
    let mut oracle_payload = [0u8; 128];
    let mut oracle_tie_payload = [0u8; 128];
    let iv2_in = [-3i32, 1i32];
    let iv3_in = [-7i32, 0i32, 9i32];
    let uv2_in = [5u32, 99u32];
    let iv2_tie_in = [-1i32, 0i32];
    let qi64_in = -7i64;
    let qu64_in = 42u64;

    for wf in &nc.wire_fields {
        let q = wf.quantize.as_ref().expect("quantize spec");
        match wf.field_name.as_str() {
            "iv2" => {
                for (li, &v) in iv2_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    let boff = wf.bit_offset + (li as u32) * u32::from(q.bits);
                    pack_bits_le(&mut oracle_payload, boff, q.bits, qv);
                    pack_bits_le(&mut oracle_tie_payload, boff, q.bits, qv);
                }
            }
            "iv3" => {
                for (li, &v) in iv3_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    let boff = wf.bit_offset + (li as u32) * u32::from(q.bits);
                    pack_bits_le(&mut oracle_payload, boff, q.bits, qv);
                    pack_bits_le(&mut oracle_tie_payload, boff, q.bits, qv);
                }
            }
            "uv2" => {
                for (li, &v) in uv2_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    let boff = wf.bit_offset + (li as u32) * u32::from(q.bits);
                    pack_bits_le(&mut oracle_payload, boff, q.bits, qv);
                    pack_bits_le(&mut oracle_tie_payload, boff, q.bits, qv);
                }
            }
            "iv2_tie" => {
                for (li, &v) in iv2_tie_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    let boff = wf.bit_offset + (li as u32) * u32::from(q.bits);
                    pack_bits_le(&mut oracle_payload, boff, q.bits, qv);
                }
                pack_bits_le(&mut oracle_tie_payload, wf.bit_offset, q.bits, 1);
                pack_bits_le(
                    &mut oracle_tie_payload,
                    wf.bit_offset + u32::from(q.bits),
                    q.bits,
                    2,
                );
            }
            "qi64" => {
                let qv = quantize_scalar_f64(qi64_in as f64, q.min, q.max, q.bits, q.step);
                pack_bits_le(&mut oracle_payload, wf.bit_offset, q.bits, qv);
                pack_bits_le(&mut oracle_tie_payload, wf.bit_offset, q.bits, qv);
            }
            "qu64" => {
                let qv = quantize_scalar_f64(qu64_in as f64, q.min, q.max, q.bits, q.step);
                pack_bits_le(&mut oracle_payload, wf.bit_offset, q.bits, qv);
                pack_bits_le(&mut oracle_tie_payload, wf.bit_offset, q.bits, qv);
            }
            other => panic!("unexpected field {other}"),
        }
    }
    let oracle_hex: String = oracle_payload[..nc.packed_bytes as usize]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let oracle_c_arr: String = oracle_payload[..nc.packed_bytes as usize]
        .iter()
        .map(|b| format!("0x{b:02X}u"))
        .collect::<Vec<_>>()
        .join(", ");
    let tie_c_arr: String = oracle_tie_payload
        .iter()
        .map(|b| format!("0x{b:02X}u"))
        .collect::<Vec<_>>()
        .join(", ");
    let tie_rs_arr: String = oracle_tie_payload
        .iter()
        .map(|b| format!("0x{b:02X}"))
        .collect::<Vec<_>>()
        .join(", ");

    let tmp = TempDir::new().expect("tempdir");

    // 1. JIT (`dlopen`) TX + RX + C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`) bit-for-bit comparison
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let artifact = compile_module_to_dylib(
            &mir,
            &JitCompileOptions {
                out_dir: tmp.path().to_path_buf(),
                module_stem: "jit_ivec_parity".to_owned(),
                opt_level: JitOptLevel::Speed,
            },
        )
        .expect("compile jit_ivec_parity dylib");

        let c_art = emit_c99(&mir).expect("emit_c99 jit_ivec_parity");
        for f in &c_art.files {
            fs::write(tmp.path().join(&f.path), &f.content).unwrap();
        }
        let c_main = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
        let c_type = c_main
            .content
            .split("strata_net_encode_IntVecQuantNet(\n    const ")
            .nth(1)
            .and_then(|s| s.split('*').next())
            .unwrap()
            .trim()
            .to_owned();
        let host_api_slots = HOST_API_SLOTS;

        let harness = format!(
            r#"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include "{c_file}"

typedef struct HostShimSystemDesc {{
    uint32_t struct_size, flags;
    const char* name;
    const void* queries; size_t query_count;
    BamResult (*callback)(BamSystemCtx*, void*);
    void* user_data;
    uint32_t schedule;
    uint32_t reserved0;
    const char* const* after; size_t after_count;
    const char* const* before; size_t before_count;
    void* run_if; void* run_if_user_data;
    const char* const* in_sets; size_t in_set_count;
    const char* const* after_weak; size_t after_weak_count;
    const char* const* before_weak; size_t before_weak_count;
}} HostShimSystemDesc;

typedef struct HostShimApi {{
    uint32_t struct_size;
    uint32_t abi_version;
    void* slots[{host_api_slots}];
}} HostShimApi;

static HostShimSystemDesc g_rx_sys, g_tx_sys;
static int g_has_rx = 0, g_has_tx = 0;
static StrataNetPacket g_pkts[4];
static size_t g_pkt_n = 0, g_pkt_cur = 0;
static uint8_t g_comp_buf[{comp_sz}];
static uint64_t g_ent = 42ull;
static int g_msg_it = 0, g_q_it = 0, g_q_step = 0;

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_res(const BamHostCtx* h, const char* n, const BamComponentUuid* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "{pkt_canon}") == 0) {{ *o = 9u; return 0u; }}
    return 10u;
}}
static BamResult m_reg_c(BamLoadCtx* l, const BamComponentDesc* d, BamComponent* o) {{ (void)l; (void)d; *o = 1u; return 0u; }}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h;
    memset(o, 0, sizeof(*o));
    o->struct_size = (uint32_t)sizeof(*o);
    if (c == 9u) {{ o->flags = {flag_msg}u; o->size = 184u; o->align = 8u; o->schema_fingerprint = 0x{pkt_fp:016X}ull; return 0u; }}
    if (c == 1u) {{ o->size = {comp_sz}u; o->align = {comp_al}u; o->schema_fingerprint = 0x{comp_fp:016X}ull; return 0u; }}
    return 10u;
}}
static BamResult m_reg_s(BamLoadCtx* l, const HostShimSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "__strata_net_rx_0") == 0) {{ g_rx_sys = *d; g_has_rx = 1; }}
    if (strcmp(d->name, "__strata_net_tx_0") == 0) {{ g_tx_sys = *d; g_has_tx = 1; }}
    if (o) *o = 1u;
    return 0u;
}}
static BamResult m_mnt(BamLoadCtx* l, BamSystem s, BamScheduleId sc, BamSystemSet ss) {{ (void)l; (void)s; (void)sc; (void)ss; return 0u; }}
static BamResult m_sq(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc;
    if (qi == 0u) {{ *o = (BamIter*)&g_msg_it; return 0u; }}
    if (qi == 1u) {{ g_q_step = 0; *o = (BamIter*)&g_q_it; return 0u; }}
    *o = NULL; return 10u;
}}
static BamResult m_it_rst(BamIter* i) {{ (void)i; g_q_step = 0; return 0u; }}
static BamBool m_it_next(BamIter* i, size_t* l) {{
    if (i == (BamIter*)&g_q_it && g_q_step == 0) {{ g_q_step = 1; *l = 1u; return BAM_TRUE; }}
    *l = 0u; return BAM_FALSE;
}}
static const BamEntity* m_it_ents(const BamIter* i) {{ (void)i; return (const BamEntity*)&g_ent; }}
static const uint8_t* m_it_ro(const BamIter* i, size_t ti) {{ (void)i; (void)ti; return g_comp_buf; }}
static uint8_t* m_it_mut(BamIter* i, size_t ti) {{ (void)i; (void)ti; return g_comp_buf; }}
static BamResult m_it_mark(BamIter* i, size_t ti, size_t s, size_t c) {{ (void)i; (void)ti; (void)s; (void)c; return 0u; }}
static BamResult m_msg_rb(BamIter* i, size_t ti, uint8_t* b, size_t m, size_t* r) {{
    (void)i; (void)ti;
    size_t av = (g_pkt_n > g_pkt_cur) ? (g_pkt_n - g_pkt_cur) : 0u;
    size_t tk = (av < m) ? av : m;
    if (tk > 0u) {{ memcpy(b, &g_pkts[g_pkt_cur], tk * sizeof(StrataNetPacket)); g_pkt_cur += tk; }}
    *r = tk; return 0u;
}}
static BamResult m_msg_wb(BamIter* i, size_t ti, const uint8_t* b, size_t c) {{
    (void)i; (void)ti;
    if (c > 0u && g_pkt_n + c <= 4u) {{ memcpy(&g_pkts[g_pkt_n], b, c * sizeof(StrataNetPacket)); g_pkt_n += c; }}
    return 0u;
}}

int main(void) {{
    void* lib = dlopen("{dylib}", RTLD_NOW);
    if (!lib) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }}
    typedef BamResult (*InitFn)(const HostShimApi*, BamLoadCtx*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(lib, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(lib, "bamabi_shutdown");
    if (!init_fn || !shut_fn) return 2;

    HostShimApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = 0x00030000u;
    api.slots[2] = (void*)m_hc;
    api.slots[3] = (void*)m_reg_c;
    api.slots[4] = (void*)m_res;
    api.slots[7] = (void*)m_sq;
    api.slots[9] = (void*)m_it_next;
    api.slots[10] = (void*)m_it_rst;
    api.slots[11] = (void*)m_it_ents;
    api.slots[12] = (void*)m_it_ro;
    api.slots[14] = (void*)m_it_mut;
    api.slots[15] = (void*)m_it_mark;
    api.slots[30] = (void*)m_msg_rb;
    api.slots[32] = (void*)m_msg_wb;
    api.slots[53] = (void*)m_linfo;
    api.slots[60] = (void*)m_reg_s;
    api.slots[62] = (void*)m_mnt;

    int lctx = 1, sctx = 1;
    void* inst = NULL;
    if (init_fn(&api, (BamLoadCtx*)&lctx, &inst) != 0u || !inst) return 3;
    if (!g_has_rx || !g_has_tx) return 4;

    /* Populate input component bytes */
    {c_type} c_src;
    memset(&c_src, 0, sizeof(c_src));
    c_src.iv2 = strata_ivec2(-3, 1);
    c_src.iv3 = strata_ivec3(-7, 0, 9);
    c_src.uv2 = strata_uvec2(5u, 99u);
    c_src.iv2_tie = strata_ivec2(-1, 0);
    c_src.qi64 = -7;
    c_src.qu64 = 42ull;
    memcpy(g_comp_buf + {iv2_off}, &c_src.iv2, 8u);
    memcpy(g_comp_buf + {iv3_off}, &c_src.iv3, 12u);
    memcpy(g_comp_buf + {uv2_off}, &c_src.uv2, 8u);
    memcpy(g_comp_buf + {iv2_tie_off}, &c_src.iv2_tie, 8u);
    memcpy(g_comp_buf + {qi64_off}, &c_src.qi64, 8u);
    memcpy(g_comp_buf + {qu64_off}, &c_src.qu64, 8u);

    g_pkt_n = 0u;
    if (g_tx_sys.callback((BamSystemCtx*)&sctx, g_tx_sys.user_data) != 0u || g_pkt_n != 1u) return 5;

    const uint8_t oracle_bytes[{pbytes}] = {{ {oracle_c_arr} }};
    if (memcmp(g_pkts[0].payload, oracle_bytes, {pbytes}u) != 0) {{
        fprintf(stderr, "JIT TX payload mismatch vs oracle\n");
        return 6;
    }}
    StrataNetPacket c_pkt;
    strata_net_encode_IntVecQuantNet(&c_src, g_ent, 0u, 0u, &c_pkt);
    if (memcmp(g_pkts[0].payload, c_pkt.payload, {pbytes}u) != 0) {{
        fprintf(stderr, "JIT TX payload mismatch vs C99\n");
        return 7;
    }}

    /* JIT RX decode back into zeroed buffer */
    memset(g_comp_buf, 0x5A, sizeof(g_comp_buf));
    g_pkt_cur = 0u;
    if (g_rx_sys.callback((BamSystemCtx*)&sctx, g_rx_sys.user_data) != 0u) return 8;
    {c_type} c_dst;
    memset(&c_dst, 0x5A, sizeof(c_dst));
    if (!strata_net_decode_IntVecQuantNet(&c_pkt, &c_dst)) return 9;
    if (memcmp(g_comp_buf + {iv2_off}, &c_dst.iv2, 8u) != 0 ||
        memcmp(g_comp_buf + {iv3_off}, &c_dst.iv3, 12u) != 0 ||
        memcmp(g_comp_buf + {uv2_off}, &c_dst.uv2, 8u) != 0 ||
        memcmp(g_comp_buf + {qi64_off}, &c_dst.qi64, 8u) != 0 ||
        memcmp(g_comp_buf + {qu64_off}, &c_dst.qu64, 8u) != 0) {{
        fprintf(stderr, "JIT RX decoded bytes mismatch vs C99\n");
        return 10;
    }}

    /* Tie-rounding probe (-0.5 -> -1, +0.5 -> +1) on both JIT and C99 */
    const uint8_t tie_bytes[128] = {{ {tie_c_arr} }};
    memcpy(g_pkts[0].payload, tie_bytes, 128u);
    memset(g_comp_buf, 0, sizeof(g_comp_buf));
    g_pkt_cur = 0u;
    if (g_rx_sys.callback((BamSystemCtx*)&sctx, g_rx_sys.user_data) != 0u) return 11;
    int32_t jit_tie[2] = {{0, 0}};
    memcpy(jit_tie, g_comp_buf + {iv2_tie_off}, 8u);
    if (jit_tie[0] != -1 || jit_tie[1] != 1) {{
        fprintf(stderr, "JIT tie=(%d,%d) expected (-1,1)\n", jit_tie[0], jit_tie[1]);
        return 12;
    }}
    memcpy(c_pkt.payload, tie_bytes, 128u);
    {c_type} c_tie;
    memset(&c_tie, 0, sizeof(c_tie));
    if (!strata_net_decode_IntVecQuantNet(&c_pkt, &c_tie)) return 13;
    if (c_tie.iv2_tie.x != -1 || c_tie.iv2_tie.y != 1) {{
        fprintf(stderr, "C99 tie=(%d,%d) expected (-1,1)\n", c_tie.iv2_tie.x, c_tie.iv2_tie.y);
        return 14;
    }}

    shut_fn(inst);
    dlclose(lib);
    return 0;
}}
"#,
            c_file = c_main.path,
            comp_sz = layout.size,
            comp_al = layout.align.max(1),
            pkt_canon = STRATA_NET_PACKET_CANONICAL_NAME,
            flag_msg = bamabi_sys::BAM_STORAGE_FLAG_MESSAGE,
            pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
            comp_fp = nc.schema_fingerprint,
            dylib = artifact.dylib_path.display(),
            pbytes = nc.packed_bytes,
        );
        let c_path = tmp.path().join("jit_ivec_parity_harness.c");
        let bin_path = tmp.path().join("jit_ivec_parity_harness");
        fs::write(&c_path, harness).unwrap();
        let cc = find_c_compiler();
        let mut cmd = Command::new(cc);
        cmd.args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&c_path)
        .arg("-o")
        .arg(&bin_path)
        .arg("-lm");
        if cfg!(target_os = "linux") {
            cmd.arg("-ldl");
        }
        let comp = cmd.output().unwrap();
        assert!(
            comp.status.success(),
            "JIT/C99 ivec parity compile failed:\n{}",
            String::from_utf8_lossy(&comp.stderr)
        );
        let run = Command::new(&bin_path).output().unwrap();
        assert!(
            run.status.success(),
            "JIT/C99 ivec parity failed ({:?}):\n{}",
            run.status.code(),
            String::from_utf8_lossy(&run.stderr)
        );
    }

    // 2. Verify Rust Guest & Bevy Native match the exact same oracle payload & tie-rounding
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_jit_ivec_test".to_owned(),
        },
    )
    .expect("emit_rust_guest");
    let rg_lib = &rg_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let rg_struct = rg_lib
        .split("strata_net_encode_IntVecQuantNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_dir = tmp.path().join("rg_jit_ivec");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let rg_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use guest_jit_ivec_test::*;

#[test]
fn rg_matches_jit_ivec_oracle() {{
    let mut src = {rg_struct}::default();
    src.iv2 = [-3, 1];
    src.iv3 = [-7, 0, 9];
    src.uv2 = [5, 99];
    src.iv2_tie = [-1, 0];
    src.qi64 = -7;
    src.qu64 = 42;
    let pkt = strata_net_encode_IntVecQuantNet(&src, 42, 0, 0);
    let hex: String = pkt.payload[..{pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(hex, "{oracle_hex}");
    let mut tie_pkt = pkt;
    tie_pkt.payload = [{tie_rs_arr}];
    let mut tie_dst = {rg_struct}::default();
    assert!(strata_net_decode_IntVecQuantNet(&tie_pkt, &mut tie_dst));
    assert_eq!(tie_dst.iv2, [-3, 1]);
    assert_eq!(tie_dst.iv3, [-7, 0, 9]);
    assert_eq!(tie_dst.uv2, [5, 99]);
    assert_eq!(tie_dst.iv2_tie, [-1, 1]);
    assert_eq!(tie_dst.qi64, -7);
    assert_eq!(tie_dst.qu64, 42);
}}
"#,
        pbytes = nc.packed_bytes,
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/rg_ivec.rs"), rg_test).unwrap();
    write_offline_patch_config_jit(&ws_root, &rg_dir);
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd_jit()
            .current_dir(&rg_dir)
            .arg("test")
            .args(cargo_offline_flag_jit())
            .args(["--test", "rg_ivec", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        rg_out.status.success(),
        "RustGuest ivec test failed:\n{}",
        String::from_utf8_lossy(&rg_out.stderr)
    );

    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt")).unwrap();
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_jit_ivec_test".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native");
    let bn_lib = &bn_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let bn_struct = bn_lib
        .split("strata_net_encode_IntVecQuantNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_dir = tmp.path().join("bn_jit_ivec");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use native_jit_ivec_test::*;

#[test]
fn bn_matches_jit_ivec_oracle() {{
    let mut src = {bn_struct}::default();
    src.iv2 = [-3, 1];
    src.iv3 = [-7, 0, 9];
    src.uv2 = [5, 99];
    src.iv2_tie = [-1, 0];
    src.qi64 = -7;
    src.qu64 = 42;
    let pkt = strata_net_encode_IntVecQuantNet(&src, 42, 0, 0);
    let hex: String = pkt.payload[..{pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(hex, "{oracle_hex}");
    let mut tie_pkt = pkt;
    tie_pkt.payload = [{tie_rs_arr}];
    let mut tie_dst = {bn_struct}::default();
    assert!(strata_net_decode_IntVecQuantNet(&tie_pkt, &mut tie_dst));
    assert_eq!(tie_dst.iv2, [-3, 1]);
    assert_eq!(tie_dst.iv3, [-7, 0, 9]);
    assert_eq!(tie_dst.uv2, [5, 99]);
    assert_eq!(tie_dst.iv2_tie, [-1, 1]);
    assert_eq!(tie_dst.qi64, -7);
    assert_eq!(tie_dst.qu64, 42);
}}
"#,
        pbytes = nc.packed_bytes,
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/bn_ivec.rs"), bn_test).unwrap();
    write_offline_patch_config_jit(&ws_root, &bn_dir);
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd_jit()
            .current_dir(&bn_dir)
            .arg("test")
            .args(cargo_offline_flag_jit())
            .args(["--test", "bn_ivec", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        bn_out.status.success(),
        "BevyNative ivec test failed:\n{}",
        String::from_utf8_lossy(&bn_out.stderr)
    );
}

#[test]
fn jit_fix32_fix64_and_array_defaults_and_const_int_match_backends_and_roundtrip_wire() {
    use std::path::PathBuf;
    use strata_codegen::{
        BevyNativeOptions, RustGuestOptions, emit_bevy_native, emit_c99, emit_rust_guest_with,
    };

    let src_parity = r#"
module game::jit_fixed_defaults @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
component FixedDefaultsNet {
    f32_frac: fix32 = 1.5,
    f32_neg: fix32 = -3,
    f64_frac: fix64 = -2.25,
    f64_int: fix64 = 42,
    arr32: [fix32; 2] = [1.5, -3],
    arr64: [fix64; 2] = [-2.25, 42],
    f32_min: fix32 = -32768,
    f64_min: fix64 = -2147483648,
}

@net(reliable, channel = 1)
@authority(server)
resource FixedNetRes {
    r32: fix32 = 1.5,
    r64: fix64 = -2.25,
    r32_int: fix32 = -3,
    r64_int: fix64 = 42,
}

schedule FixedUpdate {}
"#;
    let src_jit_exec = r#"
module game::jit_fixed_defaults @version(1.0.0);

struct NestedFixed {
    n32: fix32 = -3,
    n64: fix64 = 42,
}

@net(reliable, channel = 0)
@authority(server)
component FixedDefaultsNet {
    f32_frac: fix32 = 1.5,
    f32_neg: fix32 = -3,
    f64_frac: fix64 = -2.25,
    f64_int: fix64 = 42,
    arr32: [fix32; 2] = [1.5, -3],
    arr64: [fix64; 2] = [-2.25, 42],
    f32_min: fix32 = -32768,
    f64_min: fix64 = -2147483648,
}

component NestedFixedComp {
    inner: NestedFixed = NestedFixed { n32: 1.5, n64: -2.25 },
    arr_inner: [NestedFixed; 2] = [
        NestedFixed { n32: 1.5, n64: -2.25 },
        NestedFixed { n32: -3, n64: 42 },
    ],
}

component ResProbe {
    r32: fix32 = 0,
    r64: fix64 = 0,
    r32_int: fix32 = 0,
    r64_int: fix64 = 0,
}

@net(reliable, channel = 1)
@authority(server)
resource FixedNetRes {
    r32: fix32 = 1.5,
    r64: fix64 = -2.25,
    r32_int: fix32 = -3,
    r64_int: fix64 = 42,
}

@authority(server)
sys spawn_fixed_defaults() {
    let _e1 = spawn { FixedDefaultsNet {} };
    let _e2 = spawn { NestedFixedComp {} };
}

@authority(server)
sys read_mod_local_res(r: &res FixedNetRes) {
    for e in query(p: &mut ResProbe) {
        e.p.r32 = r.r32;
        e.p.r64 = r.r64;
        e.p.r32_int = r.r32_int;
        e.p.r64_int = r.r64_int;
    }
}

schedule FixedUpdate {
    spawn_fixed_defaults,
    read_mod_local_res,
}
"#;
    let src_const_inst = r#"
module game::jit_fixed_const_inst @version(1.0.0);

const C_F32_FRAC: fix32 = 1.5;
const C_F32_NEG: fix32 = -3;
const C_F64_FRAC: fix64 = -2.25;
const C_F64_INT: fix64 = 42;
const C_F32_MIN: fix32 = -32768;
const C_F64_MIN: fix64 = -2147483648;

component FixedConstTarget {
    f32_frac: fix32 = 0,
    f32_neg: fix32 = 0,
    f64_frac: fix64 = 0,
    f64_int: fix64 = 0,
    f32_min: fix32 = 0,
    f64_min: fix64 = 0,
}

sys assign_const_fixed() {
    for e in query(p: &mut FixedConstTarget) {
        e.p.f32_frac = C_F32_FRAC;
        e.p.f32_neg = C_F32_NEG;
        e.p.f64_frac = C_F64_FRAC;
        e.p.f64_int = C_F64_INT;
        e.p.f32_min = C_F32_MIN;
        e.p.f64_min = C_F64_MIN;
    }
}

schedule FixedUpdate {
    assign_const_fixed,
}
"#;
    let parity_analyzed = analyze_source("jit_fixed_parity.strata", src_parity);
    assert!(parity_analyzed.ok(), "{:?}", parity_analyzed.diagnostics);
    let parity_mir = lower_to_mir(&parity_analyzed);

    let analyzed = analyze_source("jit_fixed_defaults.strata", src_jit_exec);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let nc = mir
        .net_components
        .iter()
        .find(|c| c.canonical_name == "game::jit_fixed_defaults::FixedDefaultsNet")
        .expect("FixedDefaultsNet net_component");
    let res_nc = mir
        .net_components
        .iter()
        .find(|c| c.canonical_name == "game::jit_fixed_defaults::FixedNetRes")
        .expect("FixedNetRes net_component");
    let fixed_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == "game::jit_fixed_defaults::FixedDefaultsNet")
        .expect("FixedDefaultsNet layout");
    let nested_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == "game::jit_fixed_defaults::NestedFixedComp")
        .expect("NestedFixedComp layout");
    let nested_inner_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == "game::jit_fixed_defaults::NestedFixed")
        .expect("NestedFixed layout");
    let probe_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == "game::jit_fixed_defaults::ResProbe")
        .expect("ResProbe layout");

    let field_off = |layout: &strata_sema::layout::SolvedLayout, name: &str| -> usize {
        layout
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("missing field {name}"))
            .offset
    };

    let exp_f32_frac: i32 = 98_304;
    let exp_f32_neg: i32 = -196_608;
    let exp_f64_frac: i64 = -9_663_676_416;
    let exp_f64_int: i64 = 42i64 << 32;
    let exp_f32_min: i32 = i32::MIN;
    let exp_f64_min: i64 = i64::MIN;

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    // 1. C99 ground truth (`-std=c99 -Wall -Wextra -Wpedantic -Werror`) + JIT `dlopen` execution
    let c_art = emit_c99(&mir).expect("emit_c99 jit_fixed_defaults");
    for f in &c_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).unwrap();
    }
    let c_main = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let comp_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::jit_fixed_defaults::FixedDefaultsNet")
        .unwrap();
    let c_type = format!("StrataType_{comp_idx}_FixedDefaultsNet");
    let c_def_fn = format!("strata_default_{comp_idx}_FixedDefaultsNet");

    let pbytes = nc.packed_bytes as usize;
    let mut c99_hex = String::new();

    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let artifact = compile_module_to_dylib(
            &mir,
            &JitCompileOptions {
                out_dir: tmp.path().to_path_buf(),
                module_stem: "jit_fixed_defaults".to_owned(),
                opt_level: JitOptLevel::Speed,
            },
        )
        .expect("compile jit_fixed_defaults dylib");

        let nested_stride = nested_layout
            .fields
            .iter()
            .find(|f| f.name == "arr_inner")
            .unwrap()
            .size
            / 2;
        let host_api_slots = HOST_API_SLOTS;

        let harness = format!(
            r#"
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "{c_file}"

typedef struct HostShimSystemDesc {{
    uint32_t struct_size, flags;
    const char* name;
    const void* queries; size_t query_count;
    BamResult (*callback)(BamSystemCtx*, void*);
    void* user_data;
    uint32_t schedule;
    uint32_t reserved0;
    const char* const* after; size_t after_count;
    const char* const* before; size_t before_count;
    void* run_if; void* run_if_user_data;
    const char* const* in_sets; size_t in_set_count;
    const char* const* after_weak; size_t after_weak_count;
    const char* const* before_weak; size_t before_weak_count;
}} HostShimSystemDesc;

typedef struct HostShimApi {{
    uint32_t struct_size;
    uint32_t abi_version;
    void* slots[{host_api_slots}];
}} HostShimApi;

enum ActiveSys {{
    ACT_NONE = 0,
    ACT_SPAWN = 1,
    ACT_RES_PROBE = 2,
    ACT_TX = 3,
    ACT_RX = 4,
}};

static int g_cmds_sentinel = 1;
static int g_active_sys = ACT_NONE;
static uint32_t g_next_comp = 10u;
static uint32_t g_fixed_comp = 0u;
static uint32_t g_nested_comp = 0u;
static uint32_t g_probe_comp = 0u;

static HostShimSystemDesc g_spawn_sys, g_probe_sys, g_rx_sys, g_tx_sys;
static int g_has_spawn = 0, g_has_probe = 0, g_has_rx = 0, g_has_tx = 0;

static uint8_t g_spawn_fixed_buf[{fixed_sz}];
static uint8_t g_spawn_nested_buf[{nested_sz}];
static uint8_t g_probe_buf[{probe_sz}];
static uint8_t g_rx_fixed_buf[{fixed_sz}];
static int g_saw_spawn_fixed = 0;
static int g_saw_spawn_nested = 0;

static StrataNetPacket g_pkts[4];
static size_t g_pkt_n = 0, g_pkt_cur = 0;
static uint64_t g_ent = 77ull;
static uint32_t g_mark_calls = 0u;
static int g_msg_it = 0, g_q_it = 0, g_q_step = 0;

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_res(const BamHostCtx* h, const char* n, const BamComponentUuid* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "{pkt_canon}") == 0) {{ *o = 99u; return 0u; }}
    return 4u;
}}
static BamResult m_reg_c(BamLoadCtx* l, const BamComponentDesc* d, BamComponent* o) {{
    (void)l;
    uint32_t id = g_next_comp++;
    if (strcmp(d->name, "game::jit_fixed_defaults::FixedDefaultsNet") == 0) g_fixed_comp = id;
    if (strcmp(d->name, "game::jit_fixed_defaults::NestedFixedComp") == 0) g_nested_comp = id;
    if (strcmp(d->name, "game::jit_fixed_defaults::ResProbe") == 0) g_probe_comp = id;
    *o = id;
    return 0u;
}}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h;
    memset(o, 0, sizeof(*o));
    o->struct_size = (uint32_t)sizeof(*o);
    if (c == 99u) {{ o->flags = {flag_msg}u; o->size = 184u; o->align = 8u; o->schema_fingerprint = 0x{pkt_fp:016X}ull; return 0u; }}
    if (c == g_fixed_comp) {{ o->size = {fixed_sz}u; o->align = {fixed_al}u; o->schema_fingerprint = 0x{fixed_fp:016X}ull; return 0u; }}
    if (c == g_nested_comp) {{ o->size = {nested_sz}u; o->align = {nested_al}u; o->schema_fingerprint = 0x{nested_fp:016X}ull; return 0u; }}
    if (c == g_probe_comp) {{ o->size = {probe_sz}u; o->align = {probe_al}u; o->schema_fingerprint = 0x{probe_fp:016X}ull; return 0u; }}
    return 4u;
}}
static BamResult m_reg_s(BamLoadCtx* l, const HostShimSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "spawn_fixed_defaults") == 0) {{ g_spawn_sys = *d; g_has_spawn = 1; }}
    if (strcmp(d->name, "read_mod_local_res") == 0) {{ g_probe_sys = *d; g_has_probe = 1; }}
    if (strcmp(d->name, "__strata_net_rx_0") == 0) {{ g_rx_sys = *d; g_has_rx = 1; }}
    if (strcmp(d->name, "__strata_net_tx_0") == 0) {{ g_tx_sys = *d; g_has_tx = 1; }}
    if (o) *o = 1u;
    return 0u;
}}
static BamResult m_mnt(BamLoadCtx* l, BamSystem s, BamScheduleId sc, BamSystemSet ss) {{ (void)l; (void)s; (void)sc; (void)ss; return 0u; }}
static BamResult m_sys_cmds(BamSystemCtx* sc, void** out_cmds) {{ (void)sc; *out_cmds = &g_cmds_sentinel; return 0u; }}
static BamResult m_cmd_spawn(void* cmds, const uint32_t* comps, const uint8_t* const* data_ptrs, size_t count, uint64_t* out_ent) {{
    (void)cmds;
    for (size_t i = 0u; i < count; ++i) {{
        if (comps[i] == g_fixed_comp && data_ptrs[i] != NULL) {{
            memcpy(g_spawn_fixed_buf, data_ptrs[i], {fixed_sz}u);
            g_saw_spawn_fixed = 1;
        }}
        if (comps[i] == g_nested_comp && data_ptrs[i] != NULL) {{
            memcpy(g_spawn_nested_buf, data_ptrs[i], {nested_sz}u);
            g_saw_spawn_nested = 1;
        }}
    }}
    if (out_ent) *out_ent = g_ent;
    return 0u;
}}
static BamResult m_sq(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc;
    if (g_active_sys == ACT_TX || g_active_sys == ACT_RX) {{
        if (qi == 0u) {{ *o = (BamIter*)&g_msg_it; return 0u; }}
        if (qi == 1u) {{ g_q_step = 0; *o = (BamIter*)&g_q_it; return 0u; }}
        *o = NULL; return 4u;
    }}
    if (qi == 0u) {{ g_q_step = 0; *o = (BamIter*)&g_q_it; return 0u; }}
    *o = NULL; return 4u;
}}
static BamResult m_it_rst(BamIter* i) {{ (void)i; g_q_step = 0; return 0u; }}
static BamBool m_it_next(BamIter* i, size_t* l) {{
    if (i == (BamIter*)&g_q_it && g_q_step == 0) {{ g_q_step = 1; *l = 1u; return BAM_TRUE; }}
    *l = 0u; return BAM_FALSE;
}}
static const BamEntity* m_it_ents(const BamIter* i) {{ (void)i; return (const BamEntity*)&g_ent; }}
static const uint8_t* m_it_ro(const BamIter* i, size_t ti) {{
    (void)i; (void)ti;
    if (g_active_sys == ACT_TX) return g_spawn_fixed_buf;
    return g_spawn_fixed_buf;
}}
static uint8_t* m_it_mut(BamIter* i, size_t ti) {{
    (void)i; (void)ti;
    if (g_active_sys == ACT_RES_PROBE) return g_probe_buf;
    if (g_active_sys == ACT_RX) return g_rx_fixed_buf;
    return g_probe_buf;
}}
static BamResult m_it_mark(BamIter* i, size_t ti, size_t s, size_t c) {{ (void)i; (void)ti; (void)s; (void)c; g_mark_calls++; return 0u; }}
static BamResult m_msg_rb(BamIter* i, size_t ti, uint8_t* b, size_t m, size_t* r) {{
    (void)i; (void)ti;
    size_t av = (g_pkt_n > g_pkt_cur) ? (g_pkt_n - g_pkt_cur) : 0u;
    size_t tk = (av < m) ? av : m;
    if (tk > 0u) {{ memcpy(b, &g_pkts[g_pkt_cur], tk * sizeof(StrataNetPacket)); g_pkt_cur += tk; }}
    *r = tk; return 0u;
}}
static BamResult m_msg_wb(BamIter* i, size_t ti, const uint8_t* b, size_t c) {{
    (void)i; (void)ti;
    if (c > 0u && g_pkt_n + c <= 4u) {{ memcpy(&g_pkts[g_pkt_n], b, c * sizeof(StrataNetPacket)); g_pkt_n += c; }}
    return 0u;
}}

static int check_fixed_buf(const uint8_t* buf, const char* label) {{
    int32_t f32_frac = 0, f32_neg = 0, f32_min = 0, arr32[2] = {{0, 0}};
    int64_t f64_frac = 0, f64_int = 0, f64_min = 0, arr64[2] = {{0, 0}};
    memcpy(&f32_frac, buf + {f32_frac_off}, 4u);
    memcpy(&f32_neg, buf + {f32_neg_off}, 4u);
    memcpy(&f64_frac, buf + {f64_frac_off}, 8u);
    memcpy(&f64_int, buf + {f64_int_off}, 8u);
    memcpy(arr32, buf + {arr32_off}, 8u);
    memcpy(arr64, buf + {arr64_off}, 16u);
    memcpy(&f32_min, buf + {f32_min_off}, 4u);
    memcpy(&f64_min, buf + {f64_min_off}, 8u);
    if (f32_frac != 98304 || f32_neg != -196608) {{
        fprintf(stderr, "%s f32 mismatch: %d %d\n", label, f32_frac, f32_neg);
        return 1;
    }}
    if (f64_frac != -9663676416ll || f64_int != (42ll << 32)) {{
        fprintf(stderr, "%s f64 mismatch: %lld %lld\n", label, (long long)f64_frac, (long long)f64_int);
        return 2;
    }}
    if (arr32[0] != 98304 || arr32[1] != -196608) {{
        fprintf(stderr, "%s arr32 mismatch: %d %d\n", label, arr32[0], arr32[1]);
        return 3;
    }}
    if (arr64[0] != -9663676416ll || arr64[1] != (42ll << 32)) {{
        fprintf(stderr, "%s arr64 mismatch: %lld %lld\n", label, (long long)arr64[0], (long long)arr64[1]);
        return 4;
    }}
    if (f32_min != INT32_MIN || f64_min != INT64_MIN) {{
        fprintf(stderr, "%s min mismatch: %d %lld\n", label, f32_min, (long long)f64_min);
        return 5;
    }}
    return 0;
}}

int main(void) {{
    void* lib = dlopen("{dylib}", RTLD_NOW);
    if (!lib) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }}
    typedef BamResult (*InitFn)(const HostShimApi*, BamLoadCtx*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(lib, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(lib, "bamabi_shutdown");
    if (!init_fn || !shut_fn) return 2;

    HostShimApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = 0x00030000u;
    api.slots[2] = (void*)m_hc;
    api.slots[3] = (void*)m_reg_c;
    api.slots[4] = (void*)m_res;
    api.slots[7] = (void*)m_sq;
    api.slots[8] = (void*)m_sys_cmds;
    api.slots[9] = (void*)m_it_next;
    api.slots[10] = (void*)m_it_rst;
    api.slots[11] = (void*)m_it_ents;
    api.slots[12] = (void*)m_it_ro;
    api.slots[13] = (void*)m_it_mut;
    api.slots[14] = (void*)m_it_mut;
    api.slots[15] = (void*)m_it_mark;
    api.slots[22] = (void*)m_cmd_spawn;
    api.slots[30] = (void*)m_msg_rb;
    api.slots[32] = (void*)m_msg_wb;
    api.slots[53] = (void*)m_linfo;
    api.slots[60] = (void*)m_reg_s;
    api.slots[62] = (void*)m_mnt;

    int lctx = 1, sctx = 1;
    void* inst = NULL;
    if (init_fn(&api, (BamLoadCtx*)&lctx, &inst) != 0u || !inst) return 3;
    if (!g_has_spawn || !g_has_probe || !g_has_rx || !g_has_tx) return 4;

    /* A. Spawn defaults (`default_blob_id` via `lower_struct_init` -> `CMD_SPAWN`) */
    memset(g_spawn_fixed_buf, 0, sizeof(g_spawn_fixed_buf));
    memset(g_spawn_nested_buf, 0, sizeof(g_spawn_nested_buf));
    g_active_sys = ACT_SPAWN;
    if (g_spawn_sys.callback((BamSystemCtx*)&sctx, g_spawn_sys.user_data) != 0u) return 5;
    if (!g_saw_spawn_fixed || !g_saw_spawn_nested) {{
        fprintf(stderr, "spawn flags: fixed=%d (%u) nested=%d (%u)\n", g_saw_spawn_fixed, g_fixed_comp, g_saw_spawn_nested, g_nested_comp);
        return 6;
    }}
    if (check_fixed_buf(g_spawn_fixed_buf, "JIT spawn_fixed") != 0) return 7;

    /* Verify nested struct + nested struct array defaults */
    int32_t in32 = 0, a0_32 = 0, a1_32 = 0;
    int64_t in64 = 0, a0_64 = 0, a1_64 = 0;
    memcpy(&in32, g_spawn_nested_buf + {inner_off} + {n32_off}, 4u);
    memcpy(&in64, g_spawn_nested_buf + {inner_off} + {n64_off}, 8u);
    memcpy(&a0_32, g_spawn_nested_buf + {arr_inner_off} + {n32_off}, 4u);
    memcpy(&a0_64, g_spawn_nested_buf + {arr_inner_off} + {n64_off}, 8u);
    memcpy(&a1_32, g_spawn_nested_buf + {arr_inner_off} + {nested_stride} + {n32_off}, 4u);
    memcpy(&a1_64, g_spawn_nested_buf + {arr_inner_off} + {nested_stride} + {n64_off}, 8u);
    if (in32 != 98304 || in64 != -9663676416ll || a0_32 != 98304 || a0_64 != -9663676416ll || a1_32 != -196608 || a1_64 != (42ll << 32)) {{
        fprintf(stderr, "JIT nested struct/array defaults mismatch\n");
        return 8;
    }}

    /* B. Mod-local `@net resource FixedNetRes` initialized from `default_blob_id` inside `StrataJitState` */
    memset(g_probe_buf, 0, sizeof(g_probe_buf));
    g_active_sys = ACT_RES_PROBE;
    if (g_probe_sys.callback((BamSystemCtx*)&sctx, g_probe_sys.user_data) != 0u) return 9;
    int32_t r32 = 0, r32_int = 0;
    int64_t r64 = 0, r64_int = 0;
    memcpy(&r32, g_probe_buf + {probe_r32_off}, 4u);
    memcpy(&r64, g_probe_buf + {probe_r64_off}, 8u);
    memcpy(&r32_int, g_probe_buf + {probe_r32_int_off}, 4u);
    memcpy(&r64_int, g_probe_buf + {probe_r64_int_off}, 8u);
    if (r32 != 98304 || r64 != -9663676416ll || r32_int != -196608 || r64_int != (42ll << 32)) {{
        fprintf(stderr, "JIT FixedNetRes defaults mismatch: %d %lld %d %lld\n", r32, (long long)r64, r32_int, (long long)r64_int);
        return 10;
    }}

    /* C. C99 default struct comparison + TX/RX `StrataNetPacket` wire round-trip parity */
    {c_type} c_def = {c_def_fn}();
    StrataNetPacket c_pkt;
    strata_net_encode_FixedDefaultsNet(&c_def, g_ent, 0u, 0u, &c_pkt);

    g_pkt_n = 0u;
    g_active_sys = ACT_TX;
    if (g_tx_sys.callback((BamSystemCtx*)&sctx, g_tx_sys.user_data) != 0u || g_pkt_n != 1u) return 13;
    if (memcmp(g_pkts[0].payload, c_pkt.payload, {pbytes}u) != 0) {{
        fprintf(stderr, "JIT vs C99 TX FixedDefaultsNet payload mismatch\n");
        return 14;
    }}

    memset(g_rx_fixed_buf, 0, sizeof(g_rx_fixed_buf));
    g_pkt_cur = 0u;
    g_mark_calls = 0u;
    g_active_sys = ACT_RX;
    if (g_rx_sys.callback((BamSystemCtx*)&sctx, g_rx_sys.user_data) != 0u) return 15;
    if (g_mark_calls != 1u) return 16;
    if (check_fixed_buf(g_rx_fixed_buf, "JIT RX_decoded") != 0) return 17;

    for (size_t i = 0u; i < {pbytes}u; ++i) {{
        printf("%02x", c_pkt.payload[i]);
    }}
    printf("\n");

    shut_fn(inst);
    dlclose(lib);
    return 0;
}}
"#,
            c_file = c_main.path,
            fixed_sz = fixed_layout.size,
            fixed_al = fixed_layout.align.max(1),
            fixed_fp = nc.schema_fingerprint,
            nested_sz = nested_layout.size,
            nested_al = nested_layout.align.max(1),
            nested_fp = nested_layout.schema_fingerprint,
            probe_sz = probe_layout.size,
            probe_al = probe_layout.align.max(1),
            probe_fp = probe_layout.schema_fingerprint,
            pkt_canon = STRATA_NET_PACKET_CANONICAL_NAME,
            flag_msg = bamabi_sys::BAM_STORAGE_FLAG_MESSAGE,
            pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
            dylib = artifact.dylib_path.display(),
            f32_frac_off = field_off(fixed_layout, "f32_frac"),
            f32_neg_off = field_off(fixed_layout, "f32_neg"),
            f64_frac_off = field_off(fixed_layout, "f64_frac"),
            f64_int_off = field_off(fixed_layout, "f64_int"),
            arr32_off = field_off(fixed_layout, "arr32"),
            arr64_off = field_off(fixed_layout, "arr64"),
            f32_min_off = field_off(fixed_layout, "f32_min"),
            f64_min_off = field_off(fixed_layout, "f64_min"),
            inner_off = field_off(nested_layout, "inner"),
            arr_inner_off = field_off(nested_layout, "arr_inner"),
            n32_off = field_off(nested_inner_layout, "n32"),
            n64_off = field_off(nested_inner_layout, "n64"),
            nested_stride = nested_stride,
            probe_r32_off = field_off(probe_layout, "r32"),
            probe_r64_off = field_off(probe_layout, "r64"),
            probe_r32_int_off = field_off(probe_layout, "r32_int"),
            probe_r64_int_off = field_off(probe_layout, "r64_int"),
            pbytes = pbytes,
        );
        let c_path = tmp.path().join("jit_fixed_defaults_harness.c");
        let bin_path = tmp.path().join("jit_fixed_defaults_harness");
        fs::write(&c_path, harness).unwrap();
        let cc = find_c_compiler();
        let mut cmd = Command::new(cc);
        cmd.args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&c_path)
        .arg("-o")
        .arg(&bin_path)
        .arg("-lm");
        if cfg!(target_os = "linux") {
            cmd.arg("-ldl");
        }
        let comp = cmd.output().unwrap();
        assert!(
            comp.status.success(),
            "JIT/C99 fixed defaults compile failed:\n{}",
            String::from_utf8_lossy(&comp.stderr)
        );
        let run = Command::new(&bin_path).output().unwrap();
        assert!(
            run.status.success(),
            "JIT/C99 fixed defaults harness failed ({:?}):\nstdout:\n{}\nstderr:\n{}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        c99_hex = String::from_utf8_lossy(&run.stdout).trim().to_owned();
        assert_eq!(c99_hex.len(), pbytes * 2);

        // 1b. JIT `dlopen` execution check for `Inst::ConstInt` / `Inst::ConstFloat` on `Fix32`/`Fix64`
        let ci_analyzed = analyze_source("jit_fixed_const_inst.strata", src_const_inst);
        assert!(ci_analyzed.ok(), "{:?}", ci_analyzed.diagnostics);
        let ci_mir = lower_to_mir(&ci_analyzed);
        let ci_layout = ci_mir
            .layouts
            .iter()
            .find(|l| l.canonical_name == "game::jit_fixed_const_inst::FixedConstTarget")
            .unwrap();
        let ci_art = compile_module_to_dylib(
            &ci_mir,
            &JitCompileOptions {
                out_dir: tmp.path().to_path_buf(),
                module_stem: "jit_fixed_const_inst".to_owned(),
                opt_level: JitOptLevel::Speed,
            },
        )
        .expect("compile jit_fixed_const_inst dylib");
        let host_api_slots = HOST_API_SLOTS;
        let ci_c = format!(
            r#"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct BamComponentDesc {{ uint32_t struct_size, flags; const char* name; uint8_t uuid[16]; size_t size, align; const uint32_t* req; size_t req_n; uint64_t fp; const void* fields; size_t f_n; const void* req_init; size_t ri_n; }} BamComponentDesc;
typedef struct BamSystemDesc {{
    uint32_t struct_size, flags; const char* name; const void* queries; size_t query_count;
    uint32_t (*callback)(void*, void*); void* user_data; uint32_t schedule; uint32_t reserved0;
    const char* const* after; size_t after_count; const char* const* before; size_t before_count;
    void* run_if; void* run_if_user_data; const char* const* in_sets; size_t in_set_count;
    const char* const* after_weak; size_t after_weak_count; const char* const* before_weak; size_t before_weak_count;
}} BamSystemDesc;
typedef struct BamHostApi {{ uint32_t struct_size, abi_version; void* slots[{host_api_slots}]; }} BamHostApi;

static uint8_t g_buf[{sz}];
static uint64_t g_ent = 1ull;
static int g_it = 0, g_step = 0;
static BamSystemDesc g_sys;
static int g_has_sys = 0;

static const void* m_hc(const void* l) {{ return l; }}
static uint32_t m_reg_c(void* l, const BamComponentDesc* d, uint32_t* o) {{ (void)l; (void)d; *o = 1u; return 0u; }}
static uint32_t m_reg_s(void* l, const BamSystemDesc* d, uint32_t* o) {{
    (void)l;
    if (strcmp(d->name, "assign_const_fixed") == 0) {{ g_sys = *d; g_has_sys = 1; }}
    if (o) *o = 1u;
    return 0u;
}}
static uint32_t m_mnt(void* l, uint32_t s, uint32_t sc, uint32_t ss) {{ (void)l; (void)s; (void)sc; (void)ss; return 0u; }}
static uint32_t m_sq(void* s, size_t qi, void** o) {{ (void)s; (void)qi; g_step = 0; *o = &g_it; return 0u; }}
static uint32_t m_rst(void* i) {{ (void)i; g_step = 0; return 0u; }}
static uint8_t m_nxt(void* i, size_t* l) {{ (void)i; if (g_step == 0) {{ g_step = 1; *l = 1u; return 1u; }} *l = 0u; return 0u; }}
static const uint64_t* m_ents(const void* i) {{ (void)i; return &g_ent; }}
static uint8_t* m_mut(void* i, size_t ti) {{ (void)i; (void)ti; return g_buf; }}

int main(void) {{
    void* lib = dlopen("{dylib}", RTLD_NOW);
    if (!lib) return 1;
    uint32_t (*init_fn)(const BamHostApi*, void*, void**) = (uint32_t (*)(const BamHostApi*, void*, void**))dlsym(lib, "bamabi_init");
    void (*shut_fn)(void*) = (void (*)(void*))dlsym(lib, "bamabi_shutdown");
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = 0x00030000u;
    api.slots[2] = (void*)m_hc;
    api.slots[3] = (void*)m_reg_c;
    api.slots[7] = (void*)m_sq;
    api.slots[9] = (void*)m_nxt;
    api.slots[10] = (void*)m_rst;
    api.slots[11] = (void*)m_ents;
    api.slots[13] = (void*)m_mut;
    api.slots[60] = (void*)m_reg_s;
    api.slots[62] = (void*)m_mnt;
    int lctx = 1, sctx = 1;
    void* inst = NULL;
    if (init_fn(&api, &lctx, &inst) != 0u || !inst || !g_has_sys) return 2;
    memset(g_buf, 0, sizeof(g_buf));
    if (g_sys.callback(&sctx, g_sys.user_data) != 0u) return 3;
    int32_t f32_frac = 0, f32_neg = 0, f32_min = 0;
    int64_t f64_frac = 0, f64_int = 0, f64_min = 0;
    memcpy(&f32_frac, g_buf + {f32_frac_off}, 4u);
    memcpy(&f32_neg, g_buf + {f32_neg_off}, 4u);
    memcpy(&f64_frac, g_buf + {f64_frac_off}, 8u);
    memcpy(&f64_int, g_buf + {f64_int_off}, 8u);
    memcpy(&f32_min, g_buf + {f32_min_off}, 4u);
    memcpy(&f64_min, g_buf + {f64_min_off}, 8u);
    if (f32_frac != 98304 || f32_neg != -196608 || f64_frac != -9663676416ll || f64_int != (42ll << 32) || f32_min != INT32_MIN || f64_min != INT64_MIN) {{
        fprintf(stderr, "JIT ConstInt/ConstFloat mismatch: %d %d %lld %lld %d %lld\n", f32_frac, f32_neg, (long long)f64_frac, (long long)f64_int, f32_min, (long long)f64_min);
        return 4;
    }}
    shut_fn(inst);
    dlclose(lib);
    return 0;
}}
"#,
            sz = ci_layout.size,
            dylib = ci_art.dylib_path.display(),
            f32_frac_off = field_off(ci_layout, "f32_frac"),
            f32_neg_off = field_off(ci_layout, "f32_neg"),
            f64_frac_off = field_off(ci_layout, "f64_frac"),
            f64_int_off = field_off(ci_layout, "f64_int"),
            f32_min_off = field_off(ci_layout, "f32_min"),
            f64_min_off = field_off(ci_layout, "f64_min"),
        );
        let ci_c_path = tmp.path().join("jit_fixed_const_inst.c");
        let ci_bin_path = tmp.path().join("jit_fixed_const_inst_bin");
        fs::write(&ci_c_path, ci_c).unwrap();
        let mut ci_cmd = Command::new(cc);
        ci_cmd
            .args(["-std=c99", "-Wall", "-Wextra", "-Wpedantic", "-Werror"])
            .arg(&ci_c_path)
            .arg("-o")
            .arg(&ci_bin_path);
        if cfg!(target_os = "linux") {
            ci_cmd.arg("-ldl");
        }
        let ci_comp = ci_cmd.output().unwrap();
        assert!(
            ci_comp.status.success(),
            "JIT ConstInt harness compile failed:\n{}",
            String::from_utf8_lossy(&ci_comp.stderr)
        );
        let ci_run = Command::new(&ci_bin_path).output().unwrap();
        assert!(
            ci_run.status.success(),
            "JIT ConstInt harness failed ({:?}):\n{}",
            ci_run.status.code(),
            String::from_utf8_lossy(&ci_run.stderr)
        );
    }

    // 2. Verify Rust Guest & Bevy Native match the exact same defaults & wire payload
    let _ = res_nc;
    let rg_art = emit_rust_guest_with(
        &parity_mir,
        &RustGuestOptions {
            crate_name: "guest_jit_fixed_defaults".to_owned(),
        },
    )
    .expect("emit_rust_guest");
    let rg_lib = &rg_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let rg_struct = rg_lib
        .split("strata_net_encode_FixedDefaultsNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_res_struct = rg_lib
        .split("strata_net_encode_FixedNetRes(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_dir = tmp.path().join("rg_jit_fixed");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let rg_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use guest_jit_fixed_defaults::*;

#[test]
fn rg_matches_jit_fixed_defaults() {{
    let def = {rg_struct}::default();
    assert_eq!(def.f32_frac, {exp_f32_frac});
    assert_eq!(def.f32_neg, {exp_f32_neg});
    assert_eq!(def.f64_frac, {exp_f64_frac});
    assert_eq!(def.f64_int, {exp_f64_int});
    assert_eq!(def.arr32, [{exp_f32_frac}, {exp_f32_neg}]);
    assert_eq!(def.arr64, [{exp_f64_frac}, {exp_f64_int}]);
    assert_eq!(def.f32_min, {exp_f32_min});
    assert_eq!(def.f64_min, {exp_f64_min});

    let rdef = {rg_res_struct}::default();
    assert_eq!(rdef.r32, {exp_f32_frac});
    assert_eq!(rdef.r64, {exp_f64_frac});
    assert_eq!(rdef.r32_int, {exp_f32_neg});
    assert_eq!(rdef.r64_int, {exp_f64_int});

    let pkt = strata_net_encode_FixedDefaultsNet(&def, 77, 0, 0);
    let hex: String = pkt.payload[..{pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    if !"{c99_hex}".is_empty() {{
        assert_eq!(hex, "{c99_hex}");
    }}
    let mut dec = {rg_struct}::default();
    dec.f32_frac = 0;
    dec.f32_neg = 0;
    dec.f64_frac = 0;
    dec.f64_int = 0;
    dec.arr32 = [0, 0];
    dec.arr64 = [0, 0];
    dec.f32_min = 0;
    dec.f64_min = 0;
    assert!(strata_net_decode_FixedDefaultsNet(&pkt, &mut dec));
    assert_eq!(dec, def);
}}
"#
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/rg_fixed.rs"), rg_test).unwrap();
    write_offline_patch_config_jit(&ws_root, &rg_dir);
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd_jit()
            .current_dir(&rg_dir)
            .arg("test")
            .args(cargo_offline_flag_jit())
            .args(["--test", "rg_fixed", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        rg_out.status.success(),
        "RustGuest fixed defaults test failed:\n{}",
        String::from_utf8_lossy(&rg_out.stderr)
    );

    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt")).unwrap();
    let bn_art = emit_bevy_native(
        &parity_mir,
        &BevyNativeOptions {
            crate_name: "native_jit_fixed_defaults".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native");
    let bn_lib = &bn_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let bn_struct = bn_lib
        .split("strata_net_encode_FixedDefaultsNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_res_struct = bn_lib
        .split("strata_net_encode_FixedNetRes(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_dir = tmp.path().join("bn_jit_fixed");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use native_jit_fixed_defaults::*;

#[test]
fn bn_matches_jit_fixed_defaults() {{
    let def = {bn_struct}::default();
    assert_eq!(def.f32_frac, {exp_f32_frac});
    assert_eq!(def.f32_neg, {exp_f32_neg});
    assert_eq!(def.f64_frac, {exp_f64_frac});
    assert_eq!(def.f64_int, {exp_f64_int});
    assert_eq!(def.arr32, [{exp_f32_frac}, {exp_f32_neg}]);
    assert_eq!(def.arr64, [{exp_f64_frac}, {exp_f64_int}]);
    assert_eq!(def.f32_min, {exp_f32_min});
    assert_eq!(def.f64_min, {exp_f64_min});

    let rdef = {bn_res_struct}::default();
    assert_eq!(rdef.r32, {exp_f32_frac});
    assert_eq!(rdef.r64, {exp_f64_frac});
    assert_eq!(rdef.r32_int, {exp_f32_neg});
    assert_eq!(rdef.r64_int, {exp_f64_int});

    let pkt = strata_net_encode_FixedDefaultsNet(&def, 77, 0, 0);
    let hex: String = pkt.payload[..{pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    if !"{c99_hex}".is_empty() {{
        assert_eq!(hex, "{c99_hex}");
    }}
    let mut dec = {bn_struct}::default();
    dec.f32_frac = 0;
    dec.f32_neg = 0;
    dec.f64_frac = 0;
    dec.f64_int = 0;
    dec.arr32 = [0, 0];
    dec.arr64 = [0, 0];
    dec.f32_min = 0;
    dec.f64_min = 0;
    assert!(strata_net_decode_FixedDefaultsNet(&pkt, &mut dec));
    assert_eq!(dec, def);
}}
"#
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/bn_fixed.rs"), bn_test).unwrap();
    write_offline_patch_config_jit(&ws_root, &bn_dir);
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd_jit()
            .current_dir(&bn_dir)
            .arg("test")
            .args(cargo_offline_flag_jit())
            .args(["--test", "bn_fixed", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        bn_out.status.success(),
        "BevyNative fixed defaults test failed:\n{}",
        String::from_utf8_lossy(&bn_out.stderr)
    );
}

#[test]
fn jit_and_four_backend_iteration5_fix32_fix64_arrays_nested_structs_spawns_and_wire_parity() {
    use std::path::PathBuf;
    use strata_codegen::{
        BevyNativeOptions, RustGuestOptions, emit_bevy_native, emit_c99, emit_rust_guest_with,
    };

    let src = r#"
module game::iter5_jit_4backend @version(1.0.0);

struct InnerFix {
    a: fix32 = 1.5,
    flag: bool = true,
}

@net(reliable, channel = 0)
@authority(server)
component FixedDefaultsNet {
    f32_frac: fix32 = 1.5,
    f32_neg: fix32 = -3,
    f64_frac: fix64 = -2.25,
    f64_int: fix64 = 42,
    arr32: [fix32; 2] = [1.5, -3],
    arr64: [fix64; 2] = [-2.25, 42],
    f32_min: fix32 = -32768,
    f64_min: fix64 = -2147483648,
}

@net(reliable, channel = 1)
@authority(server)
component AdvComp {
    f32_frac: fix32 = 0.0,
    f32_neg: fix32 = 0,
    f64_frac: fix64 = 0.0,
    f64_int: fix64 = 0,
    arr32: [fix32; 2],
    arr64: [fix64; 2],
    arr2d_32: [[fix32; 2]; 2],
    arr2d_64: [[fix64; 2]; 2],
    arr_inner: [InnerFix; 2],
}

component ExtraTag {
    batch_idx: i32 = 0,
}

fn helper_fix32_to_fix64(v: fix32) -> fix64 {
    let x: fix32 = -5;
    let y: fix64 = -0.3;
    let arr: [fix64; 2] = [-1.25, 7];
    if v > x && arr[0] < arr[1] {
        return (v as fix64) + y;
    }
    return y;
}

@authority(server)
sys spawn_all_cases() {
    let e_def = spawn { FixedDefaultsNet {} };
    let _e_adv = spawn {
        AdvComp {
            f32_frac: 0.3,
            f32_neg: -99,
            f64_frac: -0.3,
            f64_int: 123,
            arr32: [2.5, -4],
            arr64: [-1.25, 7],
            arr2d_32: [[2.5, -4], [0.3, -0.3]],
            arr2d_64: [[-1.25, 7], [0.3, -0.3]],
            arr_inner: [InnerFix { a: 2.5 }, InnerFix {}],
        }
    };
    insert(e_def, FixedDefaultsNet { f32_frac: 0.3, f64_frac: -0.3 });
    spawn_batch(2) |i| {
        let mut sx: fix32 = 0.3;
        if i == 1 {
            sx = -5;
        }
        {
            AdvComp {
                f32_frac: sx,
                f64_frac: helper_fix32_to_fix64(sx),
                f64_int: helper_fix32_to_fix64(-10),
            },
            ExtraTag { batch_idx: i },
        }
    };
}

@authority(server)
sys mutate_adv_fields() {
    for e in query(c: &mut AdvComp).without<ExtraTag>() {
        e.c.f32_neg = -99;
        e.c.f32_frac = 0.3;
        e.c.f64_frac = -0.3;
        e.c.f64_int = 123;
        e.c.arr32 = [2.5, -4];
        e.c.arr64 = [-1.25, 7];
        e.c.f32_frac += 0.5;
        e.c.f32_neg += 2;
        e.c.f64_frac += -0.3;
    }
}

schedule Startup { spawn_all_cases }
schedule FixedUpdate { mutate_adv_fields }
"#;

    let analyzed = analyze_source("iter5_jit_4backend.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    strata_mir::verify_mir(&mir).expect("MIR verify");

    let def_nc = mir
        .net_components
        .iter()
        .find(|c| c.name == "FixedDefaultsNet")
        .expect("FixedDefaultsNet");
    let adv_nc = mir
        .net_components
        .iter()
        .find(|c| c.name == "AdvComp")
        .expect("AdvComp");
    let def_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == def_nc.canonical_name)
        .expect("FixedDefaultsNet layout");
    let adv_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == adv_nc.canonical_name)
        .expect("AdvComp layout");
    let inner_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == "game::iter5_jit_4backend::InnerFix")
        .expect("InnerFix layout");
    let tag_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == "game::iter5_jit_4backend::ExtraTag")
        .expect("ExtraTag layout");

    let foff = |layout: &strata_sema::layout::SolvedLayout, name: &str| -> usize {
        layout
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("missing field {name}"))
            .offset
    };

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    // 1. Emit C99 + compile JIT PIC dylib
    let c_art = emit_c99(&mir).expect("emit_c99 iter5_jit_4backend");
    for f in &c_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).unwrap();
    }
    let c_main = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let def_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == def_nc.canonical_name)
        .unwrap();
    let adv_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == adv_nc.canonical_name)
        .unwrap();
    let c_def_ty = format!("StrataType_{def_idx}_FixedDefaultsNet");
    let c_def_fn = format!("strata_default_{def_idx}_FixedDefaultsNet");
    let c_adv_ty = format!("StrataType_{adv_idx}_AdvComp");
    let adv_pbytes = adv_nc.packed_bytes as usize;
    let def_pbytes = def_nc.packed_bytes as usize;

    let mut adv_hex_from_c99 = String::new();
    let mut def_hex_from_c99 = String::new();

    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let artifact = compile_module_to_dylib(
            &mir,
            &JitCompileOptions {
                out_dir: tmp.path().to_path_buf(),
                module_stem: "iter5_jit_4backend".to_owned(),
                opt_level: JitOptLevel::Speed,
            },
        )
        .expect("compile iter5_jit_4backend dylib");

        let arr_inner_stride = adv_layout
            .fields
            .iter()
            .find(|f| f.name == "arr_inner")
            .unwrap()
            .size
            / 2;
        let host_api_slots = HOST_API_SLOTS;

        let c_src = format!(
            r#"
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "{c_file}"

typedef struct HostShimSystemDesc {{
    uint32_t struct_size, flags;
    const char* name;
    const void* queries; size_t query_count;
    BamResult (*callback)(BamSystemCtx*, void*);
    void* user_data;
    uint32_t schedule;
    uint32_t reserved0;
    const char* const* after; size_t after_count;
    const char* const* before; size_t before_count;
    void* run_if; void* run_if_user_data;
    const char* const* in_sets; size_t in_set_count;
    const char* const* after_weak; size_t after_weak_count;
    const char* const* before_weak; size_t before_weak_count;
}} HostShimSystemDesc;

typedef struct HostShimApi {{
    uint32_t struct_size;
    uint32_t abi_version;
    void* slots[{host_api_slots}];
}} HostShimApi;

enum ActiveSys {{
    ACT_NONE = 0,
    ACT_SPAWN = 1,
    ACT_MUTATE = 2,
    ACT_TX = 3,
    ACT_RX = 4,
}};

static int g_cmds_sentinel = 1;
static int g_active_sys = ACT_NONE;
static uint32_t g_next_comp = 10u;
static uint32_t g_def_comp = 0u, g_adv_comp = 0u, g_tag_comp = 0u;

static HostShimSystemDesc g_spawn_sys, g_mut_sys, g_rx_sys, g_tx_sys;
static int g_has_spawn = 0, g_has_mut = 0, g_has_rx = 0, g_has_tx = 0;

static uint8_t g_spawn_def_buf[{def_sz}];
static uint8_t g_spawn_adv_buf[{adv_sz}];
static uint8_t g_insert_def_buf[{def_sz}];
static uint8_t g_batch_adv_buf[2][{adv_sz}];
static uint8_t g_mut_adv_buf[{adv_sz}];
static uint8_t g_rx_def_buf[{def_sz}];
static uint8_t g_rx_adv_buf[{adv_sz}];
static int g_saw_spawn_def = 0, g_saw_spawn_adv = 0, g_saw_insert_def = 0, g_saw_batch = 0;

static StrataNetPacket g_pkts[8];
static size_t g_pkt_n = 0, g_pkt_cur = 0;
static uint64_t g_ent_def = 101ull, g_ent_adv = 202ull;
static uint32_t g_mark_calls = 0u;
static int g_msg_it = 0, g_q_step = 0;

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_res(const BamHostCtx* h, const char* n, const BamComponentUuid* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "{pkt_canon}") == 0) {{ *o = 99u; return 0u; }}
    return 4u;
}}
static BamResult m_reg_c(BamLoadCtx* l, const BamComponentDesc* d, BamComponent* o) {{
    (void)l;
    uint32_t id = g_next_comp++;
    if (strcmp(d->name, "game::iter5_jit_4backend::FixedDefaultsNet") == 0) g_def_comp = id;
    if (strcmp(d->name, "game::iter5_jit_4backend::AdvComp") == 0) g_adv_comp = id;
    if (strcmp(d->name, "game::iter5_jit_4backend::ExtraTag") == 0) g_tag_comp = id;
    *o = id;
    return 0u;
}}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h;
    memset(o, 0, sizeof(*o));
    o->struct_size = (uint32_t)sizeof(*o);
    if (c == 99u) {{ o->flags = {flag_msg}u; o->size = 184u; o->align = 8u; o->schema_fingerprint = 0x{pkt_fp:016X}ull; return 0u; }}
    if (c == g_def_comp) {{ o->size = {def_sz}u; o->align = {def_al}u; o->schema_fingerprint = 0x{def_fp:016X}ull; return 0u; }}
    if (c == g_adv_comp) {{ o->size = {adv_sz}u; o->align = {adv_al}u; o->schema_fingerprint = 0x{adv_fp:016X}ull; return 0u; }}
    if (c == g_tag_comp) {{ o->size = {tag_sz}u; o->align = {tag_al}u; o->schema_fingerprint = 0x{tag_fp:016X}ull; return 0u; }}
    return 4u;
}}
static BamResult m_reg_s(BamLoadCtx* l, const HostShimSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "spawn_all_cases") == 0) {{ g_spawn_sys = *d; g_has_spawn = 1; }}
    if (strcmp(d->name, "mutate_adv_fields") == 0) {{ g_mut_sys = *d; g_has_mut = 1; }}
    if (strcmp(d->name, "__strata_net_rx_0") == 0) {{ g_rx_sys = *d; g_has_rx = 1; }}
    if (strcmp(d->name, "__strata_net_tx_0") == 0) {{ g_tx_sys = *d; g_has_tx = 1; }}
    if (o) *o = 1u;
    return 0u;
}}
static BamResult m_mnt(BamLoadCtx* l, BamSystem s, BamScheduleId sc, BamSystemSet ss) {{ (void)l; (void)s; (void)sc; (void)ss; return 0u; }}
static BamResult m_sys_cmds(BamSystemCtx* sc, void** out_cmds) {{ (void)sc; *out_cmds = &g_cmds_sentinel; return 0u; }}
static BamResult m_cmd_spawn(void* cmds, const uint32_t* comps, const uint8_t* const* data_ptrs, size_t count, uint64_t* out_ent) {{
    (void)cmds;
    uint64_t ent = 0ull;
    for (size_t i = 0u; i < count; ++i) {{
        if (comps[i] == g_def_comp && data_ptrs[i] != NULL) {{
            memcpy(g_spawn_def_buf, data_ptrs[i], {def_sz}u);
            g_saw_spawn_def = 1;
            ent = g_ent_def;
        }}
        if (comps[i] == g_adv_comp && data_ptrs[i] != NULL) {{
            memcpy(g_spawn_adv_buf, data_ptrs[i], {adv_sz}u);
            g_saw_spawn_adv = 1;
            ent = g_ent_adv;
        }}
    }}
    if (out_ent) *out_ent = ent;
    return 0u;
}}
static BamResult m_cmd_insert(void* cmds, uint64_t ent, uint32_t comp, const uint8_t* data_ptr, size_t data_len) {{
    (void)cmds;
    if (ent == g_ent_def && comp == g_def_comp && data_ptr != NULL && data_len == {def_sz}u) {{
        memcpy(g_insert_def_buf, data_ptr, {def_sz}u);
        g_saw_insert_def = 1;
    }}
    return 0u;
}}
static BamResult m_cmd_spawn_batch(void* cmds, const uint32_t* comps, const uint8_t* const* col_bufs, size_t comp_cnt, size_t ent_cnt, uint64_t* out_ents) {{
    (void)cmds; (void)out_ents;
    if (ent_cnt == 2u) {{
        for (size_t i = 0u; i < comp_cnt; ++i) {{
            if (comps[i] == g_adv_comp && col_bufs[i] != NULL) {{
                memcpy(g_batch_adv_buf[0], col_bufs[i], {adv_sz}u);
                memcpy(g_batch_adv_buf[1], col_bufs[i] + {adv_sz}u, {adv_sz}u);
                g_saw_batch = 1;
            }}
        }}
    }}
    return 0u;
}}
static BamResult m_sq(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc;
    if (g_active_sys == ACT_TX || g_active_sys == ACT_RX) {{
        if (qi == 0u) {{ *o = (BamIter*)&g_msg_it; return 0u; }}
        if (qi == 1u || qi == 2u) {{ g_q_step = 0; *o = (BamIter*)(uintptr_t)(0x1000u + qi); return 0u; }}
        *o = NULL; return 4u;
    }}
    if (qi == 0u) {{ g_q_step = 0; *o = (BamIter*)(uintptr_t)0x2000u; return 0u; }}
    *o = NULL; return 4u;
}}
static BamResult m_it_rst(BamIter* i) {{ (void)i; g_q_step = 0; return 0u; }}
static BamBool m_it_next(BamIter* i, size_t* l) {{
    if ((uintptr_t)i >= 0x1001u && g_q_step == 0) {{ g_q_step = 1; *l = 1u; return BAM_TRUE; }}
    *l = 0u; return BAM_FALSE;
}}
static const BamEntity* m_it_ents(const BamIter* i) {{
    return ((uintptr_t)i == 0x1001u) ? (const BamEntity*)&g_ent_def : (const BamEntity*)&g_ent_adv;
}}
static const uint8_t* m_it_ro(const BamIter* i, size_t ti) {{
    (void)ti;
    return ((uintptr_t)i == 0x1001u) ? g_spawn_def_buf : g_spawn_adv_buf;
}}
static uint8_t* m_it_mut(BamIter* i, size_t ti) {{
    (void)ti;
    if (g_active_sys == ACT_MUTATE) return g_mut_adv_buf;
    if (g_active_sys == ACT_RX) return ((uintptr_t)i == 0x1001u) ? g_rx_def_buf : g_rx_adv_buf;
    return g_mut_adv_buf;
}}
static BamResult m_it_mark(BamIter* i, size_t ti, size_t s, size_t c) {{ (void)i; (void)ti; (void)s; (void)c; g_mark_calls++; return 0u; }}
static BamResult m_msg_rb(BamIter* i, size_t ti, uint8_t* b, size_t m, size_t* r) {{
    (void)i; (void)ti;
    size_t av = (g_pkt_n > g_pkt_cur) ? (g_pkt_n - g_pkt_cur) : 0u;
    size_t tk = (av < m) ? av : m;
    if (tk > 0u) {{ memcpy(b, &g_pkts[g_pkt_cur], tk * sizeof(StrataNetPacket)); g_pkt_cur += tk; }}
    *r = tk; return 0u;
}}
static BamResult m_msg_wb(BamIter* i, size_t ti, const uint8_t* b, size_t c) {{
    (void)i; (void)ti;
    for (size_t k = 0u; k < c && g_pkt_n < 8u; ++k) {{
        memcpy(&g_pkts[g_pkt_n++], b + k * sizeof(StrataNetPacket), sizeof(StrataNetPacket));
    }}
    return 0u;
}}

static int verify_adv_spawn_buf(const uint8_t* buf, const char* label) {{
    int32_t f32_frac = 0, f32_neg = 0, arr32[2] = {{0, 0}}, arr2d_32[2][2] = {{0}};
    int64_t f64_frac = 0, f64_int = 0, arr64[2] = {{0, 0}}, arr2d_64[2][2] = {{0}};
    memcpy(&f32_frac, buf + {adv_f32_frac_off}, 4u);
    memcpy(&f32_neg, buf + {adv_f32_neg_off}, 4u);
    memcpy(&f64_frac, buf + {adv_f64_frac_off}, 8u);
    memcpy(&f64_int, buf + {adv_f64_int_off}, 8u);
    memcpy(arr32, buf + {adv_arr32_off}, 8u);
    memcpy(arr64, buf + {adv_arr64_off}, 16u);
    memcpy(arr2d_32, buf + {adv_arr2d_32_off}, 16u);
    memcpy(arr2d_64, buf + {adv_arr2d_64_off}, 32u);

    if (f32_frac != 19661 || f32_neg != (-99 * 65536)) {{
        fprintf(stderr, "%s f32 mismatch: %d %d\n", label, f32_frac, f32_neg);
        return 1;
    }}
    if (f64_frac != -1288490189ll || f64_int != (123ll << 32)) {{
        fprintf(stderr, "%s f64 mismatch: %lld %lld\n", label, (long long)f64_frac, (long long)f64_int);
        return 2;
    }}
    if (arr32[0] != 163840 || arr32[1] != -262144) {{
        fprintf(stderr, "%s arr32 mismatch: %d %d\n", label, arr32[0], arr32[1]);
        return 3;
    }}
    if (arr64[0] != -5368709120ll || arr64[1] != (7ll << 32)) {{
        fprintf(stderr, "%s arr64 mismatch: %lld %lld\n", label, (long long)arr64[0], (long long)arr64[1]);
        return 4;
    }}
    if (arr2d_32[0][0] != 163840 || arr2d_32[0][1] != -262144 || arr2d_32[1][0] != 19661 || arr2d_32[1][1] != -19661) {{
        fprintf(stderr, "%s arr2d_32 mismatch: %d %d %d %d\n", label, arr2d_32[0][0], arr2d_32[0][1], arr2d_32[1][0], arr2d_32[1][1]);
        return 5;
    }}
    if (arr2d_64[0][0] != -5368709120ll || arr2d_64[0][1] != (7ll << 32) || arr2d_64[1][0] != 1288490189ll || arr2d_64[1][1] != -1288490189ll) {{
        fprintf(stderr, "%s arr2d_64 mismatch: %lld %lld %lld %lld\n", label, (long long)arr2d_64[0][0], (long long)arr2d_64[0][1], (long long)arr2d_64[1][0], (long long)arr2d_64[1][1]);
        return 6;
    }}

    int32_t in0_a = 0, in1_a = 0;
    uint8_t in0_flag = 0, in1_flag = 0;
    const uint8_t* p0 = buf + {adv_arr_inner_off};
    const uint8_t* p1 = buf + {adv_arr_inner_off} + {arr_inner_stride};
    memcpy(&in0_a, p0 + {in_a_off}, 4u);
    memcpy(&in0_flag, p0 + {in_flag_off}, 1u);
    memcpy(&in1_a, p1 + {in_a_off}, 4u);
    memcpy(&in1_flag, p1 + {in_flag_off}, 1u);
    if (in0_a != 163840 || in0_flag != 1u || in1_a != 98304 || in1_flag != 1u) {{
        fprintf(stderr, "%s arr_inner mismatch: (%d, %u) (%d, %u)\n",
                label, in0_a, in0_flag, in1_a, in1_flag);
        return 7;
    }}
    return 0;
}}

int main(void) {{
    void* lib = dlopen("{dylib}", RTLD_NOW);
    if (!lib) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }}
    typedef BamResult (*InitFn)(const HostShimApi*, BamLoadCtx*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(lib, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(lib, "bamabi_shutdown");
    if (!init_fn || !shut_fn) return 2;

    HostShimApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = 0x00030000u;
    api.slots[2] = (void*)m_hc;
    api.slots[3] = (void*)m_reg_c;
    api.slots[4] = (void*)m_res;
    api.slots[7] = (void*)m_sq;
    api.slots[8] = (void*)m_sys_cmds;
    api.slots[9] = (void*)m_it_next;
    api.slots[10] = (void*)m_it_rst;
    api.slots[11] = (void*)m_it_ents;
    api.slots[12] = (void*)m_it_ro;
    api.slots[13] = (void*)m_it_mut;
    api.slots[14] = (void*)m_it_mut;
    api.slots[15] = (void*)m_it_mark;
    api.slots[22] = (void*)m_cmd_spawn;
    api.slots[24] = (void*)m_cmd_insert;
    api.slots[30] = (void*)m_msg_rb;
    api.slots[32] = (void*)m_msg_wb;
    api.slots[39] = (void*)m_cmd_spawn_batch;
    api.slots[53] = (void*)m_linfo;
    api.slots[60] = (void*)m_reg_s;
    api.slots[62] = (void*)m_mnt;

    int lctx = 1, sctx = 1;
    void* inst = NULL;
    if (init_fn(&api, (BamLoadCtx*)&lctx, &inst) != 0u || !inst) return 3;
    if (!g_has_spawn || !g_has_mut || !g_has_rx || !g_has_tx) return 4;

    /* 1. Startup: spawn FixedDefaultsNet, spawn AdvComp, insert FixedDefaultsNet, spawn_batch(2) */
    g_active_sys = ACT_SPAWN;
    if (g_spawn_sys.callback((BamSystemCtx*)&sctx, g_spawn_sys.user_data) != 0u) return 5;
    if (!g_saw_spawn_def || !g_saw_spawn_adv || !g_saw_insert_def || !g_saw_batch) return 6;

    /* Verify FixedDefaultsNet defaults including -32768 / -2147483648 */
    int32_t d_f32_min = 0, d_f32_frac = 0, d_f32_neg = 0;
    int64_t d_f64_min = 0, d_f64_frac = 0, d_f64_int = 0;
    memcpy(&d_f32_frac, g_spawn_def_buf + {def_f32_frac_off}, 4u);
    memcpy(&d_f32_neg, g_spawn_def_buf + {def_f32_neg_off}, 4u);
    memcpy(&d_f64_frac, g_spawn_def_buf + {def_f64_frac_off}, 8u);
    memcpy(&d_f64_int, g_spawn_def_buf + {def_f64_int_off}, 8u);
    memcpy(&d_f32_min, g_spawn_def_buf + {def_f32_min_off}, 4u);
    memcpy(&d_f64_min, g_spawn_def_buf + {def_f64_min_off}, 8u);
    if (d_f32_frac != 98304 || d_f32_neg != -196608 || d_f64_frac != -9663676416ll || d_f64_int != (42ll << 32) || d_f32_min != INT32_MIN || d_f64_min != INT64_MIN) {{
        fprintf(stderr, "JIT spawn FixedDefaultsNet mismatch\n");
        return 7;
    }}

    /* Verify insert(e_def, FixedDefaultsNet {{ f32_frac: 0.3, f64_frac: -0.3 }}) */
    int32_t ins_f32_frac = 0, ins_f32_neg = 0;
    int64_t ins_f64_frac = 0, ins_f64_int = 0;
    memcpy(&ins_f32_frac, g_insert_def_buf + {def_f32_frac_off}, 4u);
    memcpy(&ins_f32_neg, g_insert_def_buf + {def_f32_neg_off}, 4u);
    memcpy(&ins_f64_frac, g_insert_def_buf + {def_f64_frac_off}, 8u);
    memcpy(&ins_f64_int, g_insert_def_buf + {def_f64_int_off}, 8u);
    if (ins_f32_frac != 19661 || ins_f32_neg != -196608 || ins_f64_frac != -1288490189ll || ins_f64_int != (42ll << 32)) {{
        fprintf(stderr, "JIT CmdInsert mismatch: %d %d %lld %lld\n", ins_f32_frac, ins_f32_neg, (long long)ins_f64_frac, (long long)ins_f64_int);
        return 8;
    }}

    /* Verify spawn AdvComp {{ ... }} */
    if (verify_adv_spawn_buf(g_spawn_adv_buf, "JIT spawn_adv") != 0) return 9;

    /* Verify spawn_batch(2) (Inst::SpawnBatchPush + SlotStore + helper fn(fix32)->fix64) */
    int32_t b0_f32 = 0, b1_f32 = 0;
    int64_t b0_f64 = 0, b0_int = 0, b1_f64 = 0, b1_int = 0;
    memcpy(&b0_f32, g_batch_adv_buf[0] + {adv_f32_frac_off}, 4u);
    memcpy(&b0_f64, g_batch_adv_buf[0] + {adv_f64_frac_off}, 8u);
    memcpy(&b0_int, g_batch_adv_buf[0] + {adv_f64_int_off}, 8u);
    memcpy(&b1_f32, g_batch_adv_buf[1] + {adv_f32_frac_off}, 4u);
    memcpy(&b1_f64, g_batch_adv_buf[1] + {adv_f64_frac_off}, 8u);
    memcpy(&b1_int, g_batch_adv_buf[1] + {adv_f64_int_off}, 8u);
    /* i=0: sx=0.3 (19661), helper(0.3) = (19661<<16) + (-1288490189) = 13107, helper(-10) = -1288490189 */
    /* i=1: sx=-5 (-327680), helper(-5) = -1288490189, helper(-10) = -1288490189 */
    if (b0_f32 != 19661 || b0_f64 != 13107ll || b0_int != -1288490189ll ||
        b1_f32 != -327680 || b1_f64 != -1288490189ll || b1_int != -1288490189ll) {{
        fprintf(stderr, "JIT spawn_batch mismatch: row0=(%d,%lld,%lld) row1=(%d,%lld,%lld)\n",
                b0_f32, (long long)b0_f64, (long long)b0_int, b1_f32, (long long)b1_f64, (long long)b1_int);
        return 10;
    }}

    /* 2. Query FieldStore + compound BinOp (`mutate_adv_fields`) */
    memset(g_mut_adv_buf, 0, sizeof(g_mut_adv_buf));
    g_active_sys = ACT_MUTATE;
    if (g_mut_sys.callback((BamSystemCtx*)&sctx, g_mut_sys.user_data) != 0u) return 11;
    int32_t m_f32_frac = 0, m_f32_neg = 0, m_arr32[2] = {{0, 0}};
    int64_t m_f64_frac = 0, m_f64_int = 0, m_arr64[2] = {{0, 0}};
    memcpy(&m_f32_frac, g_mut_adv_buf + {adv_f32_frac_off}, 4u);
    memcpy(&m_f32_neg, g_mut_adv_buf + {adv_f32_neg_off}, 4u);
    memcpy(&m_f64_frac, g_mut_adv_buf + {adv_f64_frac_off}, 8u);
    memcpy(&m_f64_int, g_mut_adv_buf + {adv_f64_int_off}, 8u);
    memcpy(m_arr32, g_mut_adv_buf + {adv_arr32_off}, 8u);
    memcpy(m_arr64, g_mut_adv_buf + {adv_arr64_off}, 16u);
    if (m_f32_frac != 52429 || m_f32_neg != (-97 * 65536) ||
        m_f64_frac != -2576980378ll || m_f64_int != (123ll << 32) ||
        m_arr32[0] != 163840 || m_arr32[1] != -262144 ||
        m_arr64[0] != -5368709120ll || m_arr64[1] != (7ll << 32)) {{
        fprintf(stderr, "JIT mutate_adv_fields mismatch: %d %d %lld %lld [%d,%d] [%lld,%lld]\n",
                m_f32_frac, m_f32_neg, (long long)m_f64_frac, (long long)m_f64_int,
                m_arr32[0], m_arr32[1], (long long)m_arr64[0], (long long)m_arr64[1]);
        return 12;
    }}

    /* 3. C99 ground-truth encode of AdvComp + FixedDefaultsNet & JIT TX/RX roundtrip */
    {c_def_ty} c_def = {c_def_fn}();
    StrataNetPacket c_def_pkt;
    memset(&c_def_pkt, 0, sizeof(c_def_pkt));
    strata_net_encode_FixedDefaultsNet(&c_def, g_ent_def, 0u, 0u, &c_def_pkt);

    {c_adv_ty} c_adv;
    memcpy(&c_adv, g_spawn_adv_buf, sizeof(c_adv));
    StrataNetPacket c_adv_pkt;
    memset(&c_adv_pkt, 0, sizeof(c_adv_pkt));
    strata_net_encode_AdvComp(&c_adv, g_ent_adv, 0u, 0u, &c_adv_pkt);

    /* TX emits packets for both replicated components; verify both match C99 */
    g_pkt_n = 0u;
    g_active_sys = ACT_TX;
    if (g_tx_sys.callback((BamSystemCtx*)&sctx, g_tx_sys.user_data) != 0u || g_pkt_n < 2u) return 13;
    const StrataNetPacket* jit_def_pkt = NULL;
    const StrataNetPacket* jit_adv_pkt = NULL;
    for (size_t i = 0u; i < g_pkt_n; ++i) {{
        if (g_pkts[i].item_schema_fingerprint == 0x{def_fp:016X}ull) {{
            jit_def_pkt = &g_pkts[i];
        }}
        if (g_pkts[i].item_schema_fingerprint == 0x{adv_fp:016X}ull) {{
            jit_adv_pkt = &g_pkts[i];
        }}
    }}
    if (!jit_def_pkt || memcmp(jit_def_pkt->payload, c_def_pkt.payload, {def_pbytes}u) != 0) {{
        fprintf(stderr, "JIT vs C99 FixedDefaultsNet TX payload mismatch\n");
        return 14;
    }}
    if (!jit_adv_pkt || memcmp(jit_adv_pkt->payload, c_adv_pkt.payload, {adv_pbytes}u) != 0) {{
        fprintf(stderr, "JIT vs C99 AdvComp TX payload mismatch\n");
        return 15;
    }}

    /* RX decodes both C99 packets into fresh buffers and verifies bit-exact match */
    memset(g_rx_def_buf, 0, sizeof(g_rx_def_buf));
    memset(g_rx_adv_buf, 0, sizeof(g_rx_adv_buf));
    g_pkts[0] = c_def_pkt;
    g_pkts[1] = c_adv_pkt;
    g_pkt_n = 2u;
    g_pkt_cur = 0u;
    g_mark_calls = 0u;
    g_active_sys = ACT_RX;
    if (g_rx_sys.callback((BamSystemCtx*)&sctx, g_rx_sys.user_data) != 0u) return 16;
    if (g_mark_calls != 2u || memcmp(g_rx_def_buf, g_spawn_def_buf, {def_sz}u) != 0 || verify_adv_spawn_buf(g_rx_adv_buf, "JIT rx_adv") != 0) return 17;

    /* Print AdvComp hex and FixedDefaultsNet default hex for Rust Guest & Bevy Native parity */
    for (size_t i = 0u; i < {adv_pbytes}u; ++i) printf("%02x", c_adv_pkt.payload[i]);
    printf(" ");
    for (size_t i = 0u; i < {def_pbytes}u; ++i) printf("%02x", c_def_pkt.payload[i]);
    printf("\n");

    shut_fn(inst);
    dlclose(lib);
    return 0;
}}
"#,
            c_file = c_main.path,
            def_sz = def_layout.size,
            def_al = def_layout.align.max(1),
            def_fp = def_nc.schema_fingerprint,
            adv_sz = adv_layout.size,
            adv_al = adv_layout.align.max(1),
            adv_fp = adv_nc.schema_fingerprint,
            tag_sz = tag_layout.size,
            tag_al = tag_layout.align.max(1),
            tag_fp = tag_layout.schema_fingerprint,
            pkt_canon = STRATA_NET_PACKET_CANONICAL_NAME,
            flag_msg = bamabi_sys::BAM_STORAGE_FLAG_MESSAGE,
            pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
            dylib = artifact.dylib_path.display(),
            def_f32_frac_off = foff(def_layout, "f32_frac"),
            def_f32_neg_off = foff(def_layout, "f32_neg"),
            def_f64_frac_off = foff(def_layout, "f64_frac"),
            def_f64_int_off = foff(def_layout, "f64_int"),
            def_f32_min_off = foff(def_layout, "f32_min"),
            def_f64_min_off = foff(def_layout, "f64_min"),
            adv_f32_frac_off = foff(adv_layout, "f32_frac"),
            adv_f32_neg_off = foff(adv_layout, "f32_neg"),
            adv_f64_frac_off = foff(adv_layout, "f64_frac"),
            adv_f64_int_off = foff(adv_layout, "f64_int"),
            adv_arr32_off = foff(adv_layout, "arr32"),
            adv_arr64_off = foff(adv_layout, "arr64"),
            adv_arr2d_32_off = foff(adv_layout, "arr2d_32"),
            adv_arr2d_64_off = foff(adv_layout, "arr2d_64"),
            adv_arr_inner_off = foff(adv_layout, "arr_inner"),
            arr_inner_stride = arr_inner_stride,
            in_a_off = foff(inner_layout, "a"),
            in_flag_off = foff(inner_layout, "flag"),
            adv_pbytes = adv_pbytes,
            def_pbytes = def_pbytes,
        );
        let c_path = tmp.path().join("jit_4backend_iter5_harness.c");
        let bin_path = tmp.path().join("jit_4backend_iter5_harness");
        fs::write(&c_path, c_src).unwrap();
        let cc = find_c_compiler();
        let mut cmd = Command::new(cc);
        cmd.args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&c_path)
        .arg("-o")
        .arg(&bin_path)
        .arg("-lm");
        if cfg!(target_os = "linux") {
            cmd.arg("-ldl");
        }
        let comp = cmd.output().unwrap();
        assert!(
            comp.status.success(),
            "JIT/C99 iter5 4-backend compile failed:\n{}",
            String::from_utf8_lossy(&comp.stderr)
        );
        let run = Command::new(&bin_path).output().unwrap();
        assert!(
            run.status.success(),
            "JIT/C99 iter5 4-backend harness failed ({:?}):\nstdout:\n{}\nstderr:\n{}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        let out_line = String::from_utf8_lossy(&run.stdout).trim().to_owned();
        let mut parts = out_line.split_whitespace();
        adv_hex_from_c99 = parts.next().unwrap().to_owned();
        def_hex_from_c99 = parts.next().unwrap().to_owned();
        assert_eq!(adv_hex_from_c99.len(), adv_pbytes * 2);
        assert_eq!(def_hex_from_c99.len(), def_pbytes * 2);
    }

    // 2. Rust Guest parity (`#![forbid(unsafe_code)] #![deny(warnings)]`)
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_jit_iter5_4backend".to_owned(),
        },
    )
    .expect("emit_rust_guest iter5_4backend");
    let rg_lib = &rg_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let rg_def_struct = rg_lib
        .split("strata_net_encode_FixedDefaultsNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_adv_struct = rg_lib
        .split("strata_net_encode_AdvComp(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_dir = tmp.path().join("rg_iter5_4backend");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let rg_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use guest_jit_iter5_4backend::*;

#[test]
fn rg_iter5_4backend_parity() {{
    let def = {rg_def_struct}::default();
    let dpkt = strata_net_encode_FixedDefaultsNet(&def, 101, 0, 0);
    let dhex: String = dpkt.payload[..{def_pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    if !"{def_hex_from_c99}".is_empty() {{
        assert_eq!(dhex, "{def_hex_from_c99}");
    }}

    let mut adv = {rg_adv_struct}::default();
    adv.f32_frac = 19_661;
    adv.f32_neg = -99 * 65_536;
    adv.f64_frac = -1_288_490_189;
    adv.f64_int = 123i64 << 32;
    adv.arr32 = [163_840, -262_144];
    adv.arr64 = [-5_368_709_120, 7i64 << 32];
    adv.arr2d_32 = [[163_840, -262_144], [19_661, -19_661]];
    adv.arr2d_64 = [[-5_368_709_120, 7i64 << 32], [1_288_490_189, -1_288_490_189]];
    adv.arr_inner[0][0] = 163_840u32;
    let pkt = strata_net_encode_AdvComp(&adv, 202, 0, 0);
    let hex: String = pkt.payload[..{adv_pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    if !"{adv_hex_from_c99}".is_empty() {{
        assert_eq!(hex, "{adv_hex_from_c99}");
    }}
    let mut dec = {rg_adv_struct}::default();
    assert!(strata_net_decode_AdvComp(&pkt, &mut dec));
    assert_eq!(dec, adv);
}}
"#
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/rg_4backend.rs"), rg_test).unwrap();
    write_offline_patch_config_jit(&ws_root, &rg_dir);
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd_jit()
            .current_dir(&rg_dir)
            .arg("test")
            .args(cargo_offline_flag_jit())
            .args(["--test", "rg_4backend", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        rg_out.status.success(),
        "RustGuest iter5 4-backend test failed:\n{}",
        String::from_utf8_lossy(&rg_out.stderr)
    );

    // 3. Bevy Native parity (`#![forbid(unsafe_code)] #![deny(warnings)]` + live Bevy App)
    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt")).unwrap();
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_jit_iter5_4backend".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native iter5_4backend");
    let bn_lib = &bn_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let bn_adv_struct = bn_lib
        .split("strata_net_encode_AdvComp(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_def_struct = bn_lib
        .split("strata_net_encode_FixedDefaultsNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_tag_struct = bn_lib
        .split("pub struct ")
        .filter_map(|s| s.split('{').next())
        .map(str::trim)
        .find(|n| n.contains("ExtraTag") && !n.ends_with("VTable"))
        .unwrap_or_else(|| panic!("ExtraTag struct not found in:\n{bn_lib}"))
        .to_owned();
    let bn_dir = tmp.path().join("bn_iter5_4backend");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use native_jit_iter5_4backend::*;

#[test]
fn bn_iter5_4backend_live_ecs_and_wire_parity() {{
    let mut app = bevy_app::App::new();
    app.add_plugins(StrataNativePlugin);
    app.world_mut().run_schedule(bevy_app::Startup);
    app.world_mut().run_schedule(bevy_app::FixedUpdate);

    let world = app.world_mut();
    let mut def_q = world.query::<&{bn_def_struct}>();
    let defs: Vec<_> = def_q.iter(world).collect();
    assert_eq!(defs.len(), 1);
    assert_eq!(defs[0].f32_frac, 19_661);
    assert_eq!(defs[0].f64_frac, -1_288_490_189);
    assert_eq!(defs[0].f32_min, i32::MIN);
    assert_eq!(defs[0].f64_min, i64::MIN);

    let mut adv_q = world.query_filtered::<&{bn_adv_struct}, bevy_ecs::query::Without<{bn_tag_struct}>>();
    let advs: Vec<_> = adv_q.iter(world).collect();
    assert_eq!(advs.len(), 1);
    let mut a = advs[0].clone();
    assert_eq!(a.f32_frac, 52_429);
    assert_eq!(a.f32_neg, -97 * 65_536);
    assert_eq!(a.f64_frac, -2_576_980_378);
    assert_eq!(a.f64_int, 123i64 << 32);
    assert_eq!(a.arr32, [163_840, -262_144]);
    assert_eq!(a.arr64, [-5_368_709_120, 7i64 << 32]);
    assert_eq!(a.arr2d_32, [[163_840, -262_144], [19_661, -19_661]]);
    assert_eq!(a.arr2d_64, [[-5_368_709_120, 7i64 << 32], [1_288_490_189, -1_288_490_189]]);
    assert_eq!(a.arr_inner[0][0], 163_840u32);
    assert_eq!(a.arr_inner[0][1] & 0xFF, 1u32);
    assert_eq!(a.arr_inner[1][0], 98_304u32);
    assert_eq!(a.arr_inner[1][1] & 0xFF, 1u32);

    // Restore pre-mutation scalar fields so wire payload matches the spawn snapshot across all 4 backends.
    a.f32_frac = 19_661;
    a.f32_neg = -99 * 65_536;
    a.f64_frac = -1_288_490_189;
    let pkt = strata_net_encode_AdvComp(&a, 202, 0, 0);
    let hex: String = pkt.payload[..{adv_pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    if !"{adv_hex_from_c99}".is_empty() {{
        assert_eq!(hex, "{adv_hex_from_c99}");
    }}

    let mut batch_q = world.query::<(&{bn_adv_struct}, &{bn_tag_struct})>();
    let mut batches: Vec<_> = batch_q.iter(world).collect();
    batches.sort_by_key(|(_, t)| t.batch_idx);
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].0.f32_frac, 19_661);
    assert_eq!(batches[0].0.f64_frac, 13_107);
    assert_eq!(batches[0].0.f64_int, -1_288_490_189);
    assert_eq!(batches[1].0.f32_frac, -327_680);
    assert_eq!(batches[1].0.f64_frac, -1_288_490_189);
    assert_eq!(batches[1].0.f64_int, -1_288_490_189);

    let def_pkt = strata_net_encode_FixedDefaultsNet(&{bn_def_struct}::default(), 101, 0, 0);
    let dhex: String = def_pkt.payload[..{def_pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    if !"{def_hex_from_c99}".is_empty() {{
        assert_eq!(dhex, "{def_hex_from_c99}");
    }}
}}
"#
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/bn_4backend.rs"), bn_test).unwrap();
    write_offline_patch_config_jit(&ws_root, &bn_dir);
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd_jit()
            .current_dir(&bn_dir)
            .arg("test")
            .args(cargo_offline_flag_jit())
            .args(["--test", "bn_4backend", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        bn_out.status.success(),
        "BevyNative iter5 4-backend test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr)
    );
}

#[test]
fn jit_wraparound_quantized_fixed_and_rpc_typed_fields_four_backend_parity() {
    use strata_codegen::emit_c99;

    let src = r#"
module game::jit_r6_parity @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
resource WrapRes {
    tick_val: u32 = 0,
}

@net(reliable, channel = 0)
@authority(server)
component QuantFixVec {
    @quantize(min = -10.0, max = 10.0, bits = 16)
    fx32: fix32 = 0.5,
    @quantize(min = -10.0, max = 10.0, bits = 16)
    fx64: fix64 = -2.25,
    @quantize(min = -7.5, max = 7.5, bits = 4)
    iv2: ivec2 = ivec2(0, 0),
    @quantize(min = -7.5, max = 7.5, bits = 4)
    iv3: ivec3 = ivec3(0, 0, 0),
    @quantize(min = 0.5, max = 15.5, bits = 4)
    uv2: uvec2 = uvec2(1, 1),
}

@net_rpc(direction = bidirectional, reliability = reliable, channel = 1)
rpc TypedRpc {
    @quantize(min = -7.5, max = 7.5, bits = 4)
    iv2: ivec2,
    @quantize(min = -7.5, max = 7.5, bits = 4)
    iv3: ivec3,
    @quantize(min = 0.5, max = 15.5, bits = 4)
    uv2: uvec2,
    @quantize(min = -10.0, max = 10.0, bits = 16)
    fx32: fix32,
    @quantize(min = -10.0, max = 10.0, bits = 16)
    fx64: fix64,
    asset_h: Asset<u32>,
}

schedule FixedUpdate {}
"#;
    let sema = analyze_source("jit_r6_parity.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    strata_mir::verify_mir(&mir).expect("verify_mir");

    let qnc = mir
        .net_components
        .iter()
        .find(|nc| nc.name == "QuantFixVec")
        .unwrap();
    let qlayout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == qnc.canonical_name)
        .unwrap();
    let wrap_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == "game::jit_r6_parity::WrapRes")
        .unwrap();

    let foff = |name: &str| -> usize {
        qlayout
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };
    let fx32_off = foff("fx32");
    let fx64_off = foff("fx64");
    let iv2_off = foff("iv2");
    let iv3_off = foff("iv3");
    let uv2_off = foff("uv2");

    // Oracle computation for QuantFixVec (0.5, -2.25, [-3, 1], [-2, -1, 2], [1, 3])
    let mut oracle_pl = [0u8; 128];
    let mut exp_fx32 = 0i32;
    let mut exp_fx64 = 0i64;
    for wf in &qnc.wire_fields {
        let q = wf.quantize.as_ref().unwrap();
        match wf.field_name.as_str() {
            "fx32" => {
                let qv = quantize_scalar_f64(0.5, q.min, q.max, q.bits, q.step);
                pack_bits_le(&mut oracle_pl, wf.bit_offset, q.bits, qv);
                exp_fx32 = (dequantize_scalar_f64(qv, q.min, q.max, q.bits, q.step) * 65_536.0)
                    .round() as i32;
            }
            "fx64" => {
                let qv = quantize_scalar_f64(-2.25, q.min, q.max, q.bits, q.step);
                pack_bits_le(&mut oracle_pl, wf.bit_offset, q.bits, qv);
                exp_fx64 = (dequantize_scalar_f64(qv, q.min, q.max, q.bits, q.step)
                    * 4_294_967_296.0)
                    .round() as i64;
            }
            "iv2" => {
                for (li, &v) in [-3i32, 1i32].iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    pack_bits_le(
                        &mut oracle_pl,
                        wf.bit_offset + (li as u32) * u32::from(q.bits),
                        q.bits,
                        qv,
                    );
                }
            }
            "iv3" => {
                for (li, &v) in [-2i32, -1i32, 2i32].iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    pack_bits_le(
                        &mut oracle_pl,
                        wf.bit_offset + (li as u32) * u32::from(q.bits),
                        q.bits,
                        qv,
                    );
                }
            }
            "uv2" => {
                for (li, &v) in [1u32, 3u32].iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    pack_bits_le(
                        &mut oracle_pl,
                        wf.bit_offset + (li as u32) * u32::from(q.bits),
                        q.bits,
                        qv,
                    );
                }
            }
            other => panic!("unexpected field {other}"),
        }
    }
    let oracle_c_bytes: String = oracle_pl[..qnc.packed_bytes as usize]
        .iter()
        .map(|b| format!("0x{b:02X}u"))
        .collect::<Vec<_>>()
        .join(", ");

    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }

    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_r6_parity".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile jit_r6_parity dylib");

    let c_art = emit_c99(&mir).expect("emit_c99 jit_r6_parity");
    for f in &c_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).unwrap();
    }
    let c_main = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let c_qtype = c_main
        .content
        .split("strata_net_encode_QuantFixVec(\n    const ")
        .nth(1)
        .and_then(|s| s.split('*').next())
        .unwrap()
        .trim()
        .to_owned();

    let harness = format!(
        r#"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include "{c_file}"

static const BamComponent g_wrap_h = 1u, g_q_h = 2u, g_net_h = 3u;
static uint32_t g_wrap_val = 77u;
static BamChangeTicks g_wrap_ticks = {{ 1u, 0u, 0xFFFFFFFEu, 1u }};

static uint8_t g_q_tx_buf[{q_sz}];
static uint8_t g_q_rx_buf[{q_sz}];
static BamEntity g_q_ent = 555ull;
static StrataNetPacket g_pkts[8];
static size_t g_pkt_n = 0u, g_pkt_cur = 0u;
static size_t g_mark_calls = 0u;
static int g_phase = 0; /* 0 = tx wrap+comp, 1 = tx wrap only */

static BamSystemDesc g_rx_sys, g_tx_sys;
static int g_has_rx = 0, g_has_tx = 0;

typedef struct MockIter {{ int kind; int step; }} MockIter;
static MockIter g_msg_it = {{ 0, 0 }}, g_q_it = {{ 1, 0 }};

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_reg_c(BamLoadCtx* l, const BamComponentDesc* d, BamComponent* o) {{
    (void)l;
    if (strcmp(d->name, "game::jit_r6_parity::QuantFixVec") == 0) *o = g_q_h;
    else *o = 10u;
    return BAM_RESULT_OK;
}}
static BamResult m_res(const BamHostCtx* h, const char* n, const BamComponentUuid* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "strata::net::StrataNetPacket") == 0) {{ *o = g_net_h; return BAM_RESULT_OK; }}
    if (strcmp(n, "game::jit_r6_parity::WrapRes") == 0) {{ *o = g_wrap_h; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h;
    memset(o, 0, sizeof(*o));
    o->struct_size = (uint32_t)sizeof(*o);
    if (c == g_net_h) {{
        o->flags = BAM_STORAGE_FLAG_MESSAGE;
        o->size = sizeof(StrataNetPacket);
        o->align = 8u;
        o->schema_fingerprint = STRATA_NET_PACKET_SCHEMA_FINGERPRINT;
        return BAM_RESULT_OK;
    }}
    if (c == g_wrap_h) {{
        o->flags = BAM_STORAGE_FLAG_RESOURCE;
        o->size = {wrap_sz}u;
        o->align = {wrap_al}u;
        o->schema_fingerprint = 0x{wrap_fp:016X}ull;
        return BAM_RESULT_OK;
    }}
    if (c == g_q_h) {{
        o->size = {q_sz}u;
        o->align = {q_al}u;
        o->schema_fingerprint = 0x{q_fp:016X}ull;
        return BAM_RESULT_OK;
    }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_s(BamLoadCtx* l, const BamSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "__strata_net_rx_0") == 0) {{ g_rx_sys = *d; g_has_rx = 1; }}
    if (strcmp(d->name, "__strata_net_tx_0") == 0) {{ g_tx_sys = *d; g_has_tx = 1; }}
    if (o) *o = 1u;
    return BAM_RESULT_OK;
}}
static BamResult m_mnt(BamLoadCtx* l, BamSystem s, BamScheduleId sc, BamSystemSet ss) {{ (void)l; (void)s; (void)sc; (void)ss; return BAM_RESULT_OK; }}
static BamResult m_sq(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc;
    if (qi == 0u) {{ *o = (BamIter*)&g_msg_it; return BAM_RESULT_OK; }}
    if (qi == 1u) {{ g_q_it.step = 0; *o = (BamIter*)&g_q_it; return BAM_RESULT_OK; }}
    *o = NULL;
    return BAM_RESULT_NOT_FOUND;
}}
static const uint8_t* m_res_ptr(const BamSystemCtx* sc, BamComponent c, BamChangeTicks* t) {{
    (void)sc;
    if (c == g_wrap_h) {{ if (t) *t = g_wrap_ticks; return (const uint8_t*)&g_wrap_val; }}
    return NULL;
}}
static BamResult m_it_rst(BamIter* i) {{ ((MockIter*)i)->step = 0; return BAM_RESULT_OK; }}
static BamBool m_it_next(BamIter* i, size_t* l) {{
    MockIter* mi = (MockIter*)i;
    if (mi->kind == 1 && g_phase == 0 && mi->step == 0) {{ mi->step = 1; *l = 1u; return BAM_TRUE; }}
    *l = 0u;
    return BAM_FALSE;
}}
static const BamEntity* m_it_ents(const BamIter* i) {{ (void)i; return &g_q_ent; }}
static const uint8_t* m_it_ro(const BamIter* i, size_t ti) {{ (void)i; (void)ti; return g_q_tx_buf; }}
static uint8_t* m_it_mut(BamIter* i, size_t ti) {{ (void)i; (void)ti; return g_q_rx_buf; }}
static BamResult m_it_mark(BamIter* i, size_t ti, size_t s, size_t l) {{
    (void)i; (void)ti; (void)s; (void)l;
    g_mark_calls += 1u;
    return BAM_RESULT_OK;
}}
static BamResult m_msg_rb(BamIter* i, size_t ti, uint8_t* b, size_t m, size_t* out_r) {{
    (void)i; (void)ti;
    size_t avail = g_pkt_n - g_pkt_cur;
    size_t n = avail < m ? avail : m;
    if (n > 0u) memcpy(b, &g_pkts[g_pkt_cur], n * sizeof(StrataNetPacket));
    g_pkt_cur += n;
    *out_r = n;
    return BAM_RESULT_OK;
}}
static BamResult m_msg_wb(BamIter* i, size_t ti, const uint8_t* b, size_t c) {{
    (void)i; (void)ti;
    if (c > 0u) {{ memcpy(&g_pkts[g_pkt_n], b, c * sizeof(StrataNetPacket)); g_pkt_n += c; }}
    return BAM_RESULT_OK;
}}

int main(void) {{
    void* lib = dlopen("{dylib}", RTLD_NOW);
    if (!lib) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }}
    typedef BamResult (*InitFn)(const BamHostApi*, BamLoadCtx*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(lib, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(lib, "bamabi_shutdown");
    if (!init_fn || !shut_fn) return 2;

    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.load_host_ctx = m_hc;
    api.register_component = m_reg_c;
    api.resolve_component = m_res;
    api.component_layout_info = m_linfo;
    api.register_system_handle = m_reg_s;
    api.mount_system_in_schedule = m_mnt;
    api.sys_query = m_sq;
    api.sys_res_ptr = m_res_ptr;
    api.iter_reset = m_it_rst;
    api.iter_next_chunk = m_it_next;
    api.iter_entities = m_it_ents;
    api.iter_column_readonly = m_it_ro;
    api.iter_column_mutable_untracked = m_it_mut;
    api.iter_mark_changed_range = m_it_mark;
    api.msg_read_batch = m_msg_rb;
    api.msg_write_batch = m_msg_wb;

    int lctx = 1, sctx = 1;
    void* inst = NULL;
    if (init_fn(&api, (BamLoadCtx*)&lctx, &inst) != BAM_RESULT_OK || !inst) return 3;
    if (!g_has_rx || !g_has_tx) return 4;

    /* Populate QuantFixVec buffer: fx32=0.5 (32768), fx64=-2.25 (-9663676416), iv2=[-3,1], iv3=[-2,-1,2], uv2=[1,3] */
    memset(g_q_tx_buf, 0, sizeof(g_q_tx_buf));
    int32_t fx32_in = 32768;
    int64_t fx64_in = -9663676416ll;
    int32_t iv2_in[2] = {{ -3, 1 }};
    int32_t iv3_in[3] = {{ -2, -1, 2 }};
    uint32_t uv2_in[2] = {{ 1u, 3u }};
    memcpy(g_q_tx_buf + {fx32_off}, &fx32_in, 4u);
    memcpy(g_q_tx_buf + {fx64_off}, &fx64_in, 8u);
    memcpy(g_q_tx_buf + {iv2_off}, iv2_in, 8u);
    memcpy(g_q_tx_buf + {iv3_off}, iv3_in, 12u);
    memcpy(g_q_tx_buf + {uv2_off}, uv2_in, 8u);

    /* Phase 0: TX with WrapRes changed=0 wraparound (1 res pkt) + QuantFixVec (1 comp pkt) */
    g_phase = 0;
    g_pkt_n = 0u;
    if (g_tx_sys.callback((BamSystemCtx*)&sctx, g_tx_sys.user_data) != BAM_RESULT_OK) return 5;
    if (g_pkt_n != 2u) {{
        fprintf(stderr, "expected 2 TX pkts (wraparound res + comp), got %zu\n", g_pkt_n);
        return 6;
    }}

    /* Verify JIT QuantFixVec TX payload matches BOTH oracle and C99 */
    const uint8_t oracle_bytes[{q_pb}] = {{ {oracle_c_bytes} }};
    const StrataNetPacket* jit_comp_pkt = (g_pkts[0].item_schema_fingerprint == 0x{q_fp:016X}ull) ? &g_pkts[0] : &g_pkts[1];
    if (memcmp(jit_comp_pkt->payload, oracle_bytes, {q_pb}u) != 0) {{
        fprintf(stderr, "JIT QuantFixVec TX payload mismatch vs oracle\n");
        return 7;
    }}

    {c_qtype} c_src;
    memcpy(&c_src, g_q_tx_buf, sizeof(c_src));
    StrataNetPacket c_pkt;
    strata_net_encode_QuantFixVec(&c_src, g_q_ent, 0u, 0u, &c_pkt);
    if (memcmp(jit_comp_pkt->payload, c_pkt.payload, {q_pb}u) != 0) {{
        fprintf(stderr, "JIT vs C99 QuantFixVec TX payload mismatch\n");
        return 8;
    }}

    /* Phase 0 RX: decode into fresh g_q_rx_buf via JIT RX and verify Q16.16 / Q32.32 / ivec / uvec */
    memset(g_q_rx_buf, 0, sizeof(g_q_rx_buf));
    g_pkts[0] = c_pkt;
    g_pkt_n = 1u;
    g_pkt_cur = 0u;
    g_mark_calls = 0u;
    if (g_rx_sys.callback((BamSystemCtx*)&sctx, g_rx_sys.user_data) != BAM_RESULT_OK) return 9;
    if (g_mark_calls != 1u) {{ fprintf(stderr, "expected 1 mark call, got %zu\n", g_mark_calls); return 10; }}

    int32_t out_fx32 = 0, out_iv2[2] = {{0}}, out_iv3[3] = {{0}};
    int64_t out_fx64 = 0;
    uint32_t out_uv2[2] = {{0}};
    memcpy(&out_fx32, g_q_rx_buf + {fx32_off}, 4u);
    memcpy(&out_fx64, g_q_rx_buf + {fx64_off}, 8u);
    memcpy(out_iv2, g_q_rx_buf + {iv2_off}, 8u);
    memcpy(out_iv3, g_q_rx_buf + {iv3_off}, 12u);
    memcpy(out_uv2, g_q_rx_buf + {uv2_off}, 8u);
    if (out_fx32 != {exp_fx32} || out_fx64 != {exp_fx64}ll ||
        out_iv2[0] != -3 || out_iv2[1] != 2 ||
        out_iv3[0] != -2 || out_iv3[1] != -1 || out_iv3[2] != 3 ||
        out_uv2[0] != 2u || out_uv2[1] != 4u) {{
        fprintf(stderr, "JIT RX decoded values mismatch: fx32=%d(exp=%d) fx64=%lld(exp=%lld) iv2=[%d,%d] iv3=[%d,%d,%d] uv2=[%u,%u]\n",
                out_fx32, {exp_fx32}, (long long)out_fx64, (long long){exp_fx64}ll,
                out_iv2[0], out_iv2[1], out_iv3[0], out_iv3[1], out_iv3[2], out_uv2[0], out_uv2[1]);
        return 11;
    }}

    /* Phase 1: WrapRes changed=0xFFFFFFFE, last_run=0, this_run=1 -> must emit 0 packets */
    g_phase = 1;
    g_wrap_ticks.changed = 0xFFFFFFFEu;
    g_wrap_ticks.last_run = 0u;
    g_wrap_ticks.this_run = 1u;
    g_pkt_n = 0u;
    if (g_tx_sys.callback((BamSystemCtx*)&sctx, g_tx_sys.user_data) != BAM_RESULT_OK) return 12;
    if (g_pkt_n != 0u) {{
        fprintf(stderr, "expected 0 TX pkts on old change with last_run=0, got %zu\n", g_pkt_n);
        return 13;
    }}

    shut_fn(inst);
    dlclose(lib);
    return 0;
}}
"#,
        c_file = c_main.path,
        dylib = artifact.dylib_path.display(),
        q_sz = qlayout.size,
        q_al = qlayout.align.max(1),
        q_fp = qlayout.schema_fingerprint,
        q_pb = qnc.packed_bytes,
        wrap_sz = wrap_layout.size,
        wrap_al = wrap_layout.align.max(1),
        wrap_fp = wrap_layout.schema_fingerprint,
    );

    let hpath = tmp.path().join("jit_r6_harness.c");
    fs::write(&hpath, harness).unwrap();
    let exe = tmp.path().join("jit_r6_harness");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let comp = Command::new(&cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&hpath)
        .arg("-o")
        .arg(&exe)
        .arg("-ldl")
        .arg("-lm")
        .output()
        .expect("compile jit_r6_harness");
    assert!(
        comp.status.success(),
        "JIT r6 harness compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&exe).output().expect("run jit_r6_harness");
    assert!(
        run.status.success(),
        "JIT r6 harness failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn jit_net_rx_drains_130_packets_and_emits_unconditional_rx_before_tx() {
    let src = r#"
module game::jit_130 @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
component Dot {
    v: u32 = 0,
}
"#;
    let sema = analyze_source("jit_130.strata", src);
    assert!(sema.ok(), "{:#?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let tmp = TempDir::new().unwrap();
    let art = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "jit_130_mod".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    let c99_art = strata_codegen::emit_c99(&mir).expect("emit_c99");
    let c_main = c99_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap();
    for f in &c99_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).unwrap();
    }
    let dot_layout = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name.ends_with("Dot"))
        .unwrap();

    let pkt_canon = strata_codegen::net::STRATA_NET_PACKET_CANONICAL_NAME;
    let pkt_fp = strata_codegen::net::STRATA_NET_PACKET_SCHEMA_FINGERPRINT;
    let flag_msg = bamabi_sys::BAM_STORAGE_FLAG_MESSAGE;

    let harness = format!(
        r#"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "{c_file}"

#define N_ENTS 130u
static BamSystemDesc g_rx_sys, g_tx_sys;
static int g_has_rx = 0, g_has_tx = 0, g_tx_after_rx = 0;
static BamComponent g_dot_comp = 10u, g_net_comp = 99u;
static BamEntity g_ents[N_ENTS];
static uint32_t g_cols[N_ENTS];
static StrataNetPacket g_in_pkts[N_ENTS];
static size_t g_in_cur = 0u;
static int g_msg_it = 0, g_q_it = 0, g_q_step = 0;

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_res(const BamHostCtx* h, const char* n, const BamComponentUuid* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "{pkt_canon}") == 0) {{ *o = g_net_comp; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_c(BamLoadCtx* l, const BamComponentDesc* d, BamComponent* o) {{
    (void)l; (void)d; *o = g_dot_comp; return BAM_RESULT_OK;
}}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h; memset(o, 0, sizeof(*o)); o->struct_size = (uint32_t)sizeof(*o);
    if (c == g_net_comp) {{ o->flags = {flag_msg}u; o->size = 184u; o->align = 8u; o->schema_fingerprint = 0x{pkt_fp:016X}ull; return BAM_RESULT_OK; }}
    if (c == g_dot_comp) {{ o->size = {dot_sz}u; o->align = {dot_al}u; o->schema_fingerprint = 0x{dot_fp:016X}ull; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_s(BamLoadCtx* l, const BamSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "__strata_net_rx_0") == 0) {{ g_rx_sys = *d; g_has_rx = 1; }}
    if (strcmp(d->name, "__strata_net_tx_0") == 0) {{
        g_tx_sys = *d; g_has_tx = 1;
        for (size_t i = 0u; i < d->after_weak_count; ++i) {{
            if (strcmp(d->after_weak[i], "__strata_net_rx_0") == 0) g_tx_after_rx = 1;
        }}
    }}
    if (o) *o = 1u;
    return BAM_RESULT_OK;
}}
static BamResult m_mnt(BamLoadCtx* l, BamSystem s, BamScheduleId sc, BamSystemSet ss) {{ (void)l;(void)s;(void)sc;(void)ss; return BAM_RESULT_OK; }}
static BamResult m_sq(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc;
    if (qi == 0u) {{ *o = (BamIter*)&g_msg_it; return BAM_RESULT_OK; }}
    if (qi == 1u) {{ g_q_step = 0; *o = (BamIter*)&g_q_it; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_it_rst(BamIter* i) {{ (void)i; g_q_step = 0; return BAM_RESULT_OK; }}
static BamBool m_it_next(BamIter* i, size_t* l) {{
    (void)i;
    if (g_q_step == 0) {{ g_q_step = 1; *l = N_ENTS; return BAM_TRUE; }}
    *l = 0u; return BAM_FALSE;
}}
static const BamEntity* m_it_ents(const BamIter* i) {{ (void)i; return g_ents; }}
static uint8_t* m_it_col_mut(BamIter* i, size_t ti) {{ (void)i; (void)ti; return (uint8_t*)g_cols; }}
static BamResult m_it_mark(BamIter* i, size_t ti, size_t s, size_t l) {{ (void)i;(void)ti;(void)s;(void)l; return BAM_RESULT_OK; }}
/* Intentionally mirror bamabi_host_sys::catalog.rs:209-212 cursor-advance-on-break! */
static BamResult m_msg_rb(BamIter* i, size_t ti, uint8_t* b, size_t m, size_t* out_r) {{
    (void)i; (void)ti;
    size_t w = 0u;
    while (g_in_cur < N_ENTS) {{
        StrataNetPacket pkt = g_in_pkts[g_in_cur++];
        if (w >= m) break;
        memcpy(b + w * sizeof(StrataNetPacket), &pkt, sizeof(StrataNetPacket));
        w += 1u;
    }}
    *out_r = w;
    return BAM_RESULT_OK;
}}

int main(void) {{
    for (uint32_t i = 0u; i < N_ENTS; ++i) {{
        g_ents[i] = (BamEntity)(2000ull + i);
        g_cols[i] = 0u;
        uint32_t v = i + 1u;
        strata_net_encode_Dot((const void*)&v, g_ents[i], 1u, 0u, &g_in_pkts[i]);
    }}
    void* lib = dlopen("{dylib}", RTLD_NOW);
    if (!lib) {{ fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }}
    typedef BamResult (*InitFn)(const BamHostApi*, BamLoadCtx*, void**);
    typedef void (*ShutFn)(void*);
    InitFn init_fn = (InitFn)dlsym(lib, "bamabi_init");
    ShutFn shut_fn = (ShutFn)dlsym(lib, "bamabi_shutdown");
    if (!init_fn || !shut_fn) return 2;

    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.load_host_ctx = m_hc;
    api.register_component = m_reg_c;
    api.resolve_component = m_res;
    api.component_layout_info = m_linfo;
    api.register_system_handle = m_reg_s;
    api.mount_system_in_schedule = m_mnt;
    api.sys_query = m_sq;
    api.iter_reset = m_it_rst;
    api.iter_next_chunk = m_it_next;
    api.iter_entities = m_it_ents;
    api.iter_column_mutable_untracked = m_it_col_mut;
    api.iter_mark_changed_range = m_it_mark;
    api.msg_read_batch = m_msg_rb;

    int lctx = 1, sctx = 1;
    void* inst = NULL;
    if (init_fn(&api, (BamLoadCtx*)&lctx, &inst) != BAM_RESULT_OK || !inst) return 3;
    if (!g_has_rx || !g_has_tx || !g_tx_after_rx) {{
        fprintf(stderr, "missing rx=%d tx=%d tx_after_rx=%d\n", g_has_rx, g_has_tx, g_tx_after_rx);
        return 4;
    }}
    if (g_rx_sys.callback((BamSystemCtx*)&sctx, g_rx_sys.user_data) != BAM_RESULT_OK) return 5;
    for (uint32_t i = 0u; i < N_ENTS; ++i) {{
        if (g_cols[i] != i + 1u) {{
            fprintf(stderr, "JIT entity %u mismatch: got %u expected %u\n", i, g_cols[i], i + 1u);
            return 6;
        }}
    }}
    shut_fn(inst);
    dlclose(lib);
    return 0;
}}
"#,
        c_file = c_main.path,
        dylib = art.dylib_path.display(),
        dot_sz = dot_layout.size,
        dot_al = dot_layout.align.max(1),
        dot_fp = dot_layout.schema_fingerprint,
    );
    let hpath = tmp.path().join("jit_130_harness.c");
    fs::write(&hpath, harness).unwrap();
    let exe = tmp.path().join("jit_130_harness");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let comp = Command::new(&cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&hpath)
        .arg("-o")
        .arg(&exe)
        .arg("-ldl")
        .arg("-lm")
        .output()
        .expect("compile jit_130_harness");
    assert!(
        comp.status.success(),
        "JIT 130-pkt harness compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&exe).output().expect("run jit_130_harness");
    assert!(
        run.status.success(),
        "JIT 130-pkt harness failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}
