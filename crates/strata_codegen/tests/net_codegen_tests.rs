mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use strata_codegen::net::{
    STRATA_NET_MAX_PAYLOAD_BYTES, STRATA_NET_PACKET_SCHEMA_FINGERPRINT, STRATA_NET_PACKET_SIZE,
    has_net_protocol,
};
use strata_codegen::{
    BevyNativeOptions, CodegenError, RustGuestOptions, emit_bevy_native, emit_c99, emit_rust_guest,
    emit_rust_guest_with,
};
use strata_mir::{MirNetComponent, MirRpc, lower_to_mir};
use strata_sema::analyze_source;
use strata_sema::hir::{AuthorityKind, NetDirection, NetReliability};
use tempfile::TempDir;

static GENERATED_CARGO_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

const NET_FIXTURE: &str = r#"
module game::mp_net @version(1.0.0);

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

fn find_c99_compiler() -> &'static str {
    for cc in ["clang", "gcc", "cc"] {
        if let Ok(out) = Command::new(cc).arg("--version").output()
            && out.status.success()
        {
            return cc;
        }
    }
    "cc"
}

fn write_offline_patch_config(ws_root: &Path, crate_dir: &Path) {
    common::write_patch_config(ws_root, crate_dir, true);
}

fn sanitized_cargo_cmd() -> Command {
    common::sanitized_cargo_cmd()
}

#[test]
fn non_net_modules_emit_zero_net_code_and_oversized_payload_is_rejected() {
    let non_net_src = r#"
module game::plain_test @version(1.0.0);
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
sys step() {
    for e in query(p: &mut Pos) {
        e.p.x += 1.0;
    }
}
schedule FixedUpdate { step }
"#;
    let sema_plain = analyze_source("plain.strata", non_net_src);
    assert!(sema_plain.ok(), "{:?}", sema_plain.diagnostics);
    let mir_plain = lower_to_mir(&sema_plain);
    assert!(!has_net_protocol(&mir_plain));

    let c_plain = emit_c99(&mir_plain).expect("emit_c99 plain");
    let c_src = &c_plain.files[1].content;
    assert!(!c_src.contains("StrataNetPacket"));
    assert!(!c_src.contains("STRATA_NET_MODULE_FINGERPRINT"));
    assert!(!c_src.contains("strata_net_"));

    let rg_plain = emit_rust_guest(&mir_plain).expect("emit_rust_guest plain");
    let rg_src = &rg_plain.files[1].content;
    assert!(!rg_src.contains("StrataNetPacket"));
    assert!(!rg_src.contains("STRATA_NET_MODULE_FINGERPRINT"));

    let bn_plain =
        emit_bevy_native(&mir_plain, &BevyNativeOptions::default()).expect("emit_bevy_native");
    let bn_src = &bn_plain.files[1].content;
    assert!(!bn_src.contains("StrataNetPacket"));
    assert!(!bn_src.contains("STRATA_NET_MODULE_FINGERPRINT"));

    // Oversized (>128B) net component & RPC rejected across all 3 backends.
    let net_sema = analyze_source("mp_net.strata", NET_FIXTURE);
    assert!(net_sema.ok(), "{:?}", net_sema.diagnostics);
    let mut oversized_comp_mir = lower_to_mir(&net_sema);
    oversized_comp_mir.net_components.push(MirNetComponent {
        name: "TooBig".to_owned(),
        canonical_name: "game::mp_net::TooBig".to_owned(),
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
        packed_bits: ((STRATA_NET_MAX_PAYLOAD_BYTES + 1) * 8) as u32,
        packed_bytes: (STRATA_NET_MAX_PAYLOAD_BYTES + 1) as u32,
    });
    assert!(matches!(
        emit_c99(&oversized_comp_mir),
        Err(CodegenError::Unsupported { .. })
    ));
    assert!(matches!(
        emit_rust_guest(&oversized_comp_mir),
        Err(CodegenError::Unsupported { .. })
    ));
    assert!(matches!(
        emit_bevy_native(&oversized_comp_mir, &BevyNativeOptions::default()),
        Err(CodegenError::Unsupported { .. })
    ));

    let mut oversized_rpc_mir = lower_to_mir(&net_sema);
    oversized_rpc_mir.rpcs.push(MirRpc {
        name: "TooBigRpc".to_owned(),
        canonical_name: "game::mp_net::TooBigRpc".to_owned(),
        direction: NetDirection::ClientToServer,
        reliability: NetReliability::Reliable,
        channel: 0,
        authority: AuthorityKind::Client,
        rpc_id: 99,
        schema_fingerprint: 1,
        fields: Vec::new(),
        quantize_specs: Vec::new(),
        wire_fields: Vec::new(),
        packed_bits: ((STRATA_NET_MAX_PAYLOAD_BYTES + 2) * 8) as u32,
        packed_bytes: (STRATA_NET_MAX_PAYLOAD_BYTES + 2) as u32,
        payload_bytes: (STRATA_NET_MAX_PAYLOAD_BYTES + 2) as u32,
    });
    assert!(matches!(
        emit_c99(&oversized_rpc_mir),
        Err(CodegenError::Unsupported { .. })
    ));
    assert!(matches!(
        emit_rust_guest(&oversized_rpc_mir),
        Err(CodegenError::Unsupported { .. })
    ));
    assert!(matches!(
        emit_bevy_native(&oversized_rpc_mir, &BevyNativeOptions::default()),
        Err(CodegenError::Unsupported { .. })
    ));
}

#[test]
fn c99_networking_compiles_pedantic_and_executes_vtable_roundtrip_and_handshake_checks() {
    let sema = analyze_source("mp_net.strata", NET_FIXTURE);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    assert!(has_net_protocol(&mir));

    let pose_layout_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::mp_net::FighterPose")
        .expect("FighterPose layout");
    let pose_ctype = format!("StrataType_{pose_layout_idx}_FighterPose");
    let pose_fp = mir.layouts[pose_layout_idx].schema_fingerprint;
    let mod_fp = mir.net_handshake.module_net_fingerprint;

    let c_art = emit_c99(&mir).expect("emit_c99 net");
    let c_src = &c_art.files[1].content;
    assert!(c_src.contains("STRATA_NET_MODULE_FINGERPRINT"));
    assert!(c_src.contains("BAM_ACCESS_CHANGED"));
    assert!(c_src.contains("msg_read_batch"));
    assert!(c_src.contains("msg_write_batch"));
    assert!(!c_src.contains("msg_send(NULL"));

    let tmp = TempDir::new().expect("tempdir");
    for f in &c_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).expect("write c file");
    }

    // Build a genuine ISO C99 executable driver including the generated C file, exercising:
    // - Quantized encode/decode round-trip (1b, 8b, 12b, 16b vec3, 32b + unaligned bool/u32)
    // - Handshake mismatch rejection BEFORE mutating state
    // - Mock BamHostApi vtable running bamabi_init (Slots 4, 53), Changed<T> check (flags == 0),
    //   Slots 14-15 (&mut?) + Slot 30 (msg_read_batch) + Slot 31 (msg_send) + Slot 32 (msg_write_batch)
    let harness = format!(
        r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "mp_net.c"

static void fail_if(int cond, const char* msg) {{
    if (cond) {{
        fprintf(stderr, "FAIL: %s\n", msg);
        exit(1);
    }}
}}

typedef struct MockSys {{
    char name[64];
    BamSystemFn cb;
    void* ud;
    BamAccessMode first_term_mode;
    BamAccessMode second_term_mode;
    uint32_t first_term_flags;
    BamComponent first_term_comp;
}} MockSys;

static MockSys g_sys[16];
static uint32_t g_sys_n = 0u;
static BamComponent g_pose_comp = 1u;
static BamComponent g_pred_comp = 2u;
static BamComponent g_hit_comp = 3u;
static BamComponent g_net_comp = 4u;

static {pose_ctype} g_poses[2];
static BamEntity g_ents[2] = {{ 101ull, 202ull }};
static uint32_t g_marked_rows[8];
static uint32_t g_marked_n = 0u;

static StrataNetPacket g_rx_pkts[8];
static size_t g_rx_n = 0u;
static size_t g_rx_cursor = 0u;

static StrataNetPacket g_tx_pkts[8];
static size_t g_tx_n = 0u;
static size_t g_msg_send_count = 0u;
static int g_force_bad_pkt_size = 0;

typedef struct MockIter {{
    uint32_t kind; /* 0 = msg, 1 = pose */
    uint32_t step;
}} MockIter;

static MockIter g_msg_iter = {{ 0u, 0u }};
static MockIter g_pose_iter = {{ 1u, 0u }};
static uint32_t g_active_sys_kind = 0u; /* 0 = rx, 1 = tx, 2 = emit, 3 = consume */

static const BamHostCtx* mock_load_host_ctx(const BamLoadCtx* lc) {{
    return (const BamHostCtx*)lc;
}}

static BamResult mock_resolve_comp(const BamHostCtx* hc, const char* name, const BamComponentUuid* u, BamComponent* out_c) {{
    (void)hc;
    (void)u;
    if (out_c == NULL || name == NULL) {{ return BAM_RESULT_NULL_POINTER; }}
    if (strcmp(name, "strata::net::StrataNetPacket") == 0) {{
        *out_c = g_net_comp;
        return BAM_RESULT_OK;
    }}
    if (strcmp(name, "game::mp_net::Hit") == 0) {{
        *out_c = g_hit_comp;
        return BAM_RESULT_OK;
    }}
    return BAM_RESULT_NOT_FOUND;
}}

static BamResult mock_register_comp(BamLoadCtx* lc, const BamComponentDesc* desc, BamComponent* out_c) {{
    (void)lc;
    if (strcmp(desc->name, "game::mp_net::FighterPose") == 0) {{
        *out_c = g_pose_comp;
    }} else if (strcmp(desc->name, "game::mp_net::PredictedInput") == 0) {{
        *out_c = g_pred_comp;
    }} else if (strcmp(desc->name, "game::mp_net::Hit") == 0) {{
        *out_c = g_hit_comp;
    }} else {{
        *out_c = 10u;
    }}
    return BAM_RESULT_OK;
}}

static BamResult mock_layout_info(const BamHostCtx* hc, BamComponent c, BamLayoutInfo* out_info) {{
    (void)hc;
    if (out_info == NULL) {{ return BAM_RESULT_NULL_POINTER; }}
    memset(out_info, 0, sizeof(*out_info));
    out_info->struct_size = (uint32_t)sizeof(BamLayoutInfo);
    if (c == g_net_comp) {{
        out_info->flags = BAM_STORAGE_FLAG_MESSAGE;
        out_info->size = g_force_bad_pkt_size ? 999u : sizeof(StrataNetPacket);
        out_info->align = 8u;
        out_info->schema_fingerprint = STRATA_NET_PACKET_SCHEMA_FINGERPRINT;
        return BAM_RESULT_OK;
    }}
    if (c == g_hit_comp) {{
        out_info->flags = BAM_STORAGE_FLAG_MESSAGE;
        out_info->size = 4u;
        out_info->align = 4u;
        return BAM_RESULT_OK;
    }}
    if (c == g_pose_comp) {{
        out_info->schema_fingerprint = 0x{pose_fp:016X}ull;
        out_info->size = sizeof({pose_ctype});
        out_info->align = 4u;
        return BAM_RESULT_OK;
    }}
    return BAM_RESULT_NOT_FOUND;
}}

static BamResult mock_register_sys_handle(BamLoadCtx* lc, const BamSystemDesc* desc, BamSystem* out_s) {{
    (void)lc;
    MockSys* ms = &g_sys[g_sys_n];
    memset(ms, 0, sizeof(*ms));
    if (desc->name != NULL) {{
        strncpy(ms->name, desc->name, sizeof(ms->name) - 1u);
    }}
    ms->cb = desc->callback;
    ms->ud = desc->user_data;
    if (desc->query_count > 0u && desc->queries != NULL && desc->queries[0].term_count > 0u) {{
        ms->first_term_mode = desc->queries[0].terms[0].mode;
        ms->first_term_flags = desc->queries[0].terms[0].flags;
        ms->first_term_comp = desc->queries[0].terms[0].component;
        if (desc->queries[0].term_count > 1u) {{
            ms->second_term_mode = desc->queries[0].terms[1].mode;
        }}
    }}
    if (out_s != NULL) {{ *out_s = (BamSystem)(g_sys_n + 1u); }}
    g_sys_n++;
    return BAM_RESULT_OK;
}}

static BamResult mock_mount_sys(BamLoadCtx* lc, BamSystem s, BamScheduleId sched, BamSystemSet set_h) {{
    (void)lc; (void)s; (void)sched; (void)set_h;
    return BAM_RESULT_OK;
}}

static BamResult mock_sys_query(BamSystemCtx* sc, size_t qi, BamIter** out_it) {{
    (void)sc;
    if (g_active_sys_kind == 0u || g_active_sys_kind == 1u) {{
        if (qi == 0u) {{
            g_msg_iter.kind = 0u;
            *out_it = (BamIter*)&g_msg_iter;
            return BAM_RESULT_OK;
        }}
        if (qi == 1u) {{
            g_pose_iter.kind = 1u;
            g_pose_iter.step = 0u;
            *out_it = (BamIter*)&g_pose_iter;
            return BAM_RESULT_OK;
        }}
    }} else if (g_active_sys_kind == 2u) {{
        if (qi == 0u) {{
            g_pose_iter.kind = 1u;
            g_pose_iter.step = 0u;
            *out_it = (BamIter*)&g_pose_iter;
            return BAM_RESULT_OK;
        }}
        if (qi == 1u) {{
            g_msg_iter.kind = 0u;
            *out_it = (BamIter*)&g_msg_iter;
            return BAM_RESULT_OK;
        }}
    }} else if (g_active_sys_kind == 3u && qi == 0u) {{
        g_msg_iter.kind = 0u;
        *out_it = (BamIter*)&g_msg_iter;
        return BAM_RESULT_OK;
    }}
    *out_it = NULL;
    return BAM_RESULT_NOT_FOUND;
}}

static BamResult mock_iter_reset(BamIter* it) {{
    MockIter* mi = (MockIter*)it;
    if (mi != NULL) {{ mi->step = 0u; }}
    return BAM_RESULT_OK;
}}

static BamBool mock_iter_next_chunk(BamIter* it, size_t* out_len) {{
    MockIter* mi = (MockIter*)it;
    if (mi == NULL || mi->kind != 1u || mi->step > 0u) {{
        *out_len = 0u;
        return BAM_FALSE;
    }}
    mi->step = 1u;
    *out_len = 2u;
    return BAM_TRUE;
}}

static const BamEntity* mock_iter_entities(const BamIter* it) {{
    (void)it;
    return g_ents;
}}

static const uint8_t* mock_iter_col_ro(const BamIter* it, size_t ti) {{
    (void)it; (void)ti;
    return (const uint8_t*)g_poses;
}}

static uint8_t* mock_iter_col_mut_untracked(BamIter* it, size_t ti) {{
    (void)it; (void)ti;
    return (uint8_t*)g_poses;
}}

static BamResult mock_iter_mark_changed_range(BamIter* it, size_t ti, size_t start, size_t count) {{
    (void)it; (void)ti;
    size_t i;
    for (i = 0u; i < count; ++i) {{
        g_marked_rows[g_marked_n++] = (uint32_t)(start + i);
    }}
    return BAM_RESULT_OK;
}}

static BamResult mock_msg_read_batch(BamIter* it, size_t ti, uint8_t* out_buf, size_t max_count, size_t* out_read) {{
    (void)ti;
    fail_if(it == NULL, "msg_read_batch called with NULL iter");
    if (g_active_sys_kind == 3u) {{
        /* Hit message stream */
        *out_read = 0u;
        return BAM_RESULT_OK;
    }}
    size_t avail = (g_rx_n > g_rx_cursor) ? (g_rx_n - g_rx_cursor) : 0u;
    size_t take = (avail < max_count) ? avail : max_count;
    if (take > 0u) {{
        memcpy(out_buf, &g_rx_pkts[g_rx_cursor], take * sizeof(StrataNetPacket));
        g_rx_cursor += take;
    }}
    *out_read = take;
    return BAM_RESULT_OK;
}}

static BamResult mock_msg_send(BamIter* it, size_t ti, const uint8_t* ptr, size_t len) {{
    (void)ti; (void)ptr; (void)len;
    fail_if(it == NULL, "msg_send called with NULL iter");
    g_msg_send_count++;
    return BAM_RESULT_OK;
}}

static BamResult mock_msg_write_batch(BamIter* it, size_t ti, const uint8_t* in_buf, size_t count) {{
    (void)ti;
    fail_if(it == NULL, "msg_write_batch called with NULL iter");
    if (count > 0u) {{
        memcpy(&g_tx_pkts[g_tx_n], in_buf, count * sizeof(StrataNetPacket));
        g_tx_n += count;
    }}
    return BAM_RESULT_OK;
}}

int main(void) {{
    /* 1. Verify POD packet size & module fingerprint */
    fail_if(sizeof(StrataNetPacket) != {pkt_sz}u, "StrataNetPacket sizeof != 184");
    fail_if(STRATA_NET_PACKET_SCHEMA_FINGERPRINT != 0x{pkt_fp:016X}ull, "StrataNetPacket fp mismatch");
    fail_if(STRATA_NET_MODULE_FINGERPRINT != 0x{mod_fp:016X}ull, "STRATA_NET_MODULE_FINGERPRINT mismatch");

    /* 2. Quantized bit-packed encode/decode round-trip (1b, 12b, 16b vec3, 32b + unaligned u32/bool) */
    {pose_ctype} src_pose;
    memset(&src_pose, 0, sizeof(src_pose));
    src_pose.yaw = 37.25f;
    src_pose.grounded = 1.0f;
    src_pose.precise = 1234.5f;
    src_pose.pos.x = -12.5f;
    src_pose.pos.y = 4.25f;
    src_pose.pos.z = 33.75f;
    src_pose.seq = 0xCAFEBABEu;
    src_pose.alive = 1u;

    StrataNetPacket pkt;
    strata_net_encode_FighterPose(&src_pose, 101ull, 7u, 2u, &pkt);
    fail_if(!strata_net_verify_handshake(&pkt, 0x{pose_fp:016X}ull), "valid handshake rejected");

    {pose_ctype} dst_pose;
    memset(&dst_pose, 0, sizeof(dst_pose));
    fail_if(!strata_net_decode_FighterPose(&pkt, &dst_pose), "valid FighterPose decode failed");
    fail_if(fabs((double)dst_pose.yaw - 37.25) > 0.05, "12-bit yaw out of tolerance");
    fail_if(fabs((double)dst_pose.grounded - 1.0) > 0.001, "1-bit grounded mismatch");
    fail_if(fabs((double)dst_pose.precise - 1234.5) > 0.01, "32-bit precise out of tolerance");
    fail_if(fabs((double)dst_pose.pos.x - (-12.5)) > 0.01, "16-bit vec3.x out of tolerance");
    fail_if(fabs((double)dst_pose.pos.y - 4.25) > 0.01, "16-bit vec3.y out of tolerance");
    fail_if(fabs((double)dst_pose.pos.z - 33.75) > 0.01, "16-bit vec3.z out of tolerance");
    fail_if(dst_pose.seq != 0xCAFEBABEu, "unaligned u32 seq mismatch");
    fail_if(dst_pose.alive != 1u, "unaligned bool alive mismatch");

    /* 3. Handshake mismatch rejection BEFORE mutating output */
    StrataNetPacket bad_pkt = pkt;
    bad_pkt.item_schema_fingerprint ^= 1ull;
    {pose_ctype} untouched;
    memset(&untouched, 0, sizeof(untouched));
    untouched.seq = 777u;
    fail_if(strata_net_verify_handshake(&bad_pkt, 0x{pose_fp:016X}ull), "corrupt item_fp accepted");
    fail_if(strata_net_decode_FighterPose(&bad_pkt, &untouched), "corrupt decode accepted");
    fail_if(untouched.seq != 777u, "corrupt decode mutated output");

    StrataNetPacket bad_mod_pkt = pkt;
    bad_mod_pkt.module_net_fingerprint ^= 0xFFull;
    fail_if(strata_net_decode_FighterPose(&bad_mod_pkt, &untouched), "corrupt module_fp accepted");
    fail_if(untouched.seq != 777u, "corrupt module_fp mutated output");

    /* 4. RPC round-trip + mismatch rejection */
    StrataRpc_MoveCmd rpc_in;
    memset(&rpc_in, 0, sizeof(rpc_in));
    rpc_in.dx = 0.5f;
    rpc_in.seq = 42u;
    StrataNetPacket rpc_pkt;
    strata_net_encode_rpc_MoveCmd(&rpc_in, 11u, 1u, &rpc_pkt);
    StrataRpc_MoveCmd rpc_out;
    memset(&rpc_out, 0, sizeof(rpc_out));
    fail_if(!strata_net_decode_rpc_MoveCmd(&rpc_pkt, &rpc_out), "RPC decode failed");
    fail_if(fabs((double)rpc_out.dx - 0.5) > 0.02, "RPC 8-bit dx out of tolerance");
    fail_if(rpc_out.seq != 42u, "RPC seq mismatch");
    rpc_pkt.module_net_fingerprint = 0ull;
    rpc_out.seq = 999u;
    fail_if(strata_net_decode_rpc_MoveCmd(&rpc_pkt, &rpc_out), "zero fp RPC accepted");
    fail_if(rpc_out.seq != 999u, "failed RPC mutated output");

    /* 5. Mock BamHostApi vtable init + Changed<T> + Messages<M> (Slots 30-32) + &mut? (Slots 14-15) */
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(BamHostApi);
    api.load_host_ctx = mock_load_host_ctx;
    api.resolve_component = mock_resolve_comp;
    api.register_component = mock_register_comp;
    api.component_layout_info = mock_layout_info;
    api.register_system_handle = mock_register_sys_handle;
    api.mount_system_in_schedule = mock_mount_sys;
    api.sys_query = mock_sys_query;
    api.iter_reset = mock_iter_reset;
    api.iter_next_chunk = mock_iter_next_chunk;
    api.iter_entities = mock_iter_entities;
    api.iter_column_readonly = mock_iter_col_ro;
    api.iter_column_mutable_untracked = mock_iter_col_mut_untracked;
    api.iter_mark_changed_range = mock_iter_mark_changed_range;
    api.msg_read_batch = mock_msg_read_batch;
    api.msg_send = mock_msg_send;
    api.msg_write_batch = mock_msg_write_batch;

    int dummy_ctx = 1;
    BamInstance* bad_inst = NULL;
    g_force_bad_pkt_size = 1;
    fail_if(bamabi_init(&api, (BamLoadCtx*)&dummy_ctx, &bad_inst) != BAM_RESULT_TYPE_MISMATCH, "mismatched StrataNetPacket size must return TYPE_MISMATCH");
    g_force_bad_pkt_size = 0;

    BamInstance* inst = NULL;
    fail_if(bamabi_init(&api, (BamLoadCtx*)&dummy_ctx, &inst) != BAM_RESULT_OK, "bamabi_init failed");
    fail_if(g_sys_n < 5u, "expected RX + 3 user systems + TX registered");
    fail_if(strcmp(g_sys[0].name, "__strata_net_rx_0") != 0, "RX must be registered before user systems");
    fail_if(strcmp(g_sys[g_sys_n - 1u].name, "__strata_net_tx_0") != 0, "TX must be registered after user systems");

    /* Verify emit_on_change bound BAM_ACCESS_CHANGED with flags == 0 */
    fail_if(g_sys[1].first_term_mode != BAM_ACCESS_CHANGED, "emit_on_change must bind BAM_ACCESS_CHANGED");
    fail_if(g_sys[1].first_term_flags != 0u, "BAM_TERM_KNOWN_FLAGS must be 0");
    /* Verify selective_pose_update bound BAM_ACCESS_WRITE */
    fail_if(g_sys[3].first_term_mode != BAM_ACCESS_WRITE, "selective_pose_update must bind BAM_ACCESS_WRITE");

    /* Run RX with 1 valid packet for entity 101 and 1 corrupt packet for entity 202 */
    memset(g_poses, 0, sizeof(g_poses));
    g_poses[1].seq = 555u;
    g_rx_pkts[0] = pkt; /* entity 101 */
    g_rx_pkts[1] = bad_pkt;
    g_rx_pkts[1].entity_bits = 202ull;
    g_rx_n = 2u;
    g_rx_cursor = 0u;
    g_marked_n = 0u;
    g_active_sys_kind = 0u;
    fail_if(g_sys[0].cb((BamSystemCtx*)&dummy_ctx, g_sys[0].ud) != BAM_RESULT_OK, "RX failed");
    fail_if(g_poses[0].seq != 0xCAFEBABEu, "RX did not update entity 101");
    fail_if(g_poses[1].seq != 555u, "RX corrupt packet mutated entity 202");
    fail_if(g_marked_n != 1u || g_marked_rows[0] != 0u, "RX must mark ONLY row 0 dirty");

    /* Re-run RX with identical packet for entity 101 -> must NOT mark any row dirty */
    g_rx_pkts[0] = pkt;
    g_rx_n = 1u;
    g_rx_cursor = 0u;
    g_marked_n = 0u;
    fail_if(g_sys[0].cb((BamSystemCtx*)&dummy_ctx, g_sys[0].ud) != BAM_RESULT_OK, "RX 2nd pass failed");
    fail_if(g_marked_n != 0u, "RX no-op packet dirtied row");

    /* Run emit_on_change (msg_send via Slot 31 with non-NULL iter) and consume_hits (Slot 30) */
    g_active_sys_kind = 2u;
    fail_if(g_sys[1].cb((BamSystemCtx*)&dummy_ctx, g_sys[1].ud) != BAM_RESULT_OK, "emit_on_change failed");
    fail_if(g_msg_send_count != 2u, "emit_on_change did not send 2 Hit messages");
    g_active_sys_kind = 3u;
    fail_if(g_sys[2].cb((BamSystemCtx*)&dummy_ctx, g_sys[2].ud) != BAM_RESULT_OK, "consume_hits failed");

    /* Run TX (msg_write_batch Slot 32) */
    g_active_sys_kind = 1u;
    g_tx_n = 0u;
    fail_if(g_sys[g_sys_n - 1u].cb((BamSystemCtx*)&dummy_ctx, g_sys[g_sys_n - 1u].ud) != BAM_RESULT_OK, "TX failed");
    fail_if(g_tx_n != 2u, "TX did not write 2 StrataNetPackets");
    fail_if(g_tx_pkts[0].entity_bits != 101ull || g_tx_pkts[1].entity_bits != 202ull, "TX entity_bits mismatch");

    bamabi_shutdown(inst);
    return 0;
}}
"#,
        pkt_sz = STRATA_NET_PACKET_SIZE,
        pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
    );

    let harness_path = tmp.path().join("c99_net_harness.c");
    fs::write(&harness_path, harness).expect("write c99_net_harness.c");
    let exe_path = tmp.path().join("c99_net_harness");
    let cc = find_c99_compiler();

    let compile_out = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&harness_path)
        .arg("-o")
        .arg(&exe_path)
        .output()
        .expect("compile c99_net_harness");
    assert!(
        compile_out.status.success(),
        "C99 harness compile failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compile_out.stdout),
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let run_out = Command::new(&exe_path)
        .output()
        .expect("execute c99_net_harness");
    assert!(
        run_out.status.success(),
        "C99 harness execution failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr)
    );
}

#[test]
fn rust_guest_networking_compiles_and_runs_quantized_roundtrip_and_handshake_tests() {
    let sema = analyze_source("mp_net.strata", NET_FIXTURE);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);

    let crate_name = "guest_mp_net_test";
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: crate_name.to_owned(),
        },
    )
    .expect("emit_rust_guest net");
    let rg_lib = &rg_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .expect("src/lib.rs")
        .content;

    assert!(rg_lib.contains("#![forbid(unsafe_code)]"));
    assert!(!rg_lib.contains("unsafe "));
    assert!(rg_lib.contains("STRATA_NET_MODULE_FINGERPRINT"));
    assert!(rg_lib.contains("strata_net_verify_handshake"));
    assert!(rg_lib.contains(".message_read::<"));
    assert!(rg_lib.contains(".message_write::<"));

    // Verify read-only `.changed()` deduplicates to `.changed::<T>()` (without redundant `.read::<T>()`),
    // and that RX/TX ordering edges (`before_weak` / `after_weak`) are emitted for `FixedUpdate`.
    assert!(
        rg_lib.contains(".query(|q| q.changed::<"),
        "synthesized TX must deduplicate to q.changed::<T>()"
    );
    assert!(
        rg_lib.contains("q = q.changed::<"),
        "read-only .changed() query must emit q.changed::<T>()"
    );
    assert!(
        rg_lib.contains(".after_weak(c\"__strata_net_rx_0\")"),
        "user FixedUpdate systems must emit .after_weak(__strata_net_rx_0)"
    );
    assert!(
        rg_lib.contains(".before_weak(c\"") && rg_lib.contains(".after_weak(c\""),
        "RX/TX systems must emit weak FixedUpdate ordering edges"
    );

    // Layout fingerprint parity
    for layout in &mir.layouts {
        let fp_hex = format!("0x{:016X}", layout.schema_fingerprint);
        assert!(
            rg_lib.contains(&fp_hex),
            "missing fingerprint {fp_hex} for {}",
            layout.canonical_name
        );
    }

    let tmp = TempDir::new().expect("tempdir");
    let rg_dir = tmp.path().join("rg_net");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, &f.content).unwrap();
    }

    // Append unit tests inside generated crate's tests/net_guest_e2e.rs and run `cargo test --offline`
    let pose_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::mp_net::FighterPose")
        .unwrap();
    let pose_struct = rg_lib
        .split("strata_net_encode_FighterPose(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .expect("pose struct in rg_lib")
        .trim()
        .to_owned();
    let pose_fp = mir.layouts[pose_idx].schema_fingerprint;

    let guest_test = format!(
        r#"#![forbid(unsafe_code)]
use bamabi_guest::prelude::ModComponent;
use bamabi_sys::FfiBool;
use {crate_name}::*;

#[test]
fn guest_quantized_roundtrip_and_handshake_mismatch() {{
    assert_eq!(core::mem::size_of::<StrataNetPacket>(), 184);
    assert_eq!(StrataNetPacket::SCHEMA_FINGERPRINT, 0x{pkt_fp:016X});
    assert_eq!(<{pose_struct} as ModComponent>::SCHEMA_FINGERPRINT, 0x{pose_fp:016X});

    let mut src = {pose_struct}::default();
    src.yaw = 37.25;
    src.grounded = 1.0;
    src.precise = 1234.5;
    src.pos = [-12.5, 4.25, 33.75];
    src.seq = 0xDEAD_BEEF;
    src.alive = FfiBool::TRUE;
    let pkt = strata_net_encode_FighterPose(&src, 42, 3, 1);
    assert!(strata_net_verify_handshake(&pkt, 0x{pose_fp:016X}));

    let mut dst = {pose_struct}::default();
    assert!(strata_net_decode_FighterPose(&pkt, &mut dst));
    assert!((dst.yaw - 37.25).abs() < 0.05);
    assert!((dst.grounded - 1.0).abs() < 0.001);
    assert!((dst.precise - 1234.5).abs() < 0.01);
    assert!((dst.pos[0] - (-12.5)).abs() < 0.01);
    assert!((dst.pos[1] - 4.25).abs() < 0.01);
    assert!((dst.pos[2] - 33.75).abs() < 0.01);
    assert_eq!(dst.seq, 0xDEAD_BEEF);
    assert!(dst.alive.get());

    // Handshake mismatch must reject BEFORE mutating dst
    let mut bad_pkt = pkt;
    bad_pkt.item_schema_fingerprint ^= 1;
    let mut untouched = {pose_struct}::default();
    untouched.seq = 777;
    assert!(!strata_net_verify_handshake(&bad_pkt, 0x{pose_fp:016X}));
    assert!(!strata_net_decode_FighterPose(&bad_pkt, &mut untouched));
    assert_eq!(untouched.seq, 777);

    // RPC round-trip
    let rpc = StrataRpc_MoveCmd {{ dx: -0.75, seq: 88 }};
    let rpkt = strata_net_encode_rpc_MoveCmd(&rpc, 9, 2);
    let mut rpc_out = StrataRpc_MoveCmd::default();
    assert!(strata_net_decode_rpc_MoveCmd(&rpkt, &mut rpc_out));
    assert!((rpc_out.dx - (-0.75)).abs() < 0.02);
    assert_eq!(rpc_out.seq, 88);
}}
"#,
        pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/net_guest_e2e.rs"), guest_test).unwrap();

    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    write_offline_patch_config(&ws_root, &rg_dir);
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    let out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "net_guest_e2e", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("run cargo test on generated RustGuest crate")
    };
    assert!(
        out.status.success(),
        "RustGuest cargo test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bevy_native_networking_compiles_and_runs_end_to_end_tx_rx_selective_mut_and_handshake() {
    let sema = analyze_source("mp_net.strata", NET_FIXTURE);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);

    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt"))
        .expect("canonicalize bamabi_native_rt");

    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_mp_net_test".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native net");
    let bn_lib = &bn_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .expect("src/lib.rs")
        .content;
    assert!(bn_lib.contains("#![forbid(unsafe_code)]"));
    assert!(!bn_lib.contains("unsafe "));
    assert!(bn_lib.contains("Changed<"));
    assert!(bn_lib.contains("MessageReader<"));
    assert!(bn_lib.contains("SelectiveMutSlice::from_contiguous_mut"));
    assert!(bn_lib.contains("register_strata_net_transport"));

    for layout in &mir.layouts {
        let fp_hex = format!("0x{:016X}", layout.schema_fingerprint);
        assert!(
            bn_lib.contains(&fp_hex),
            "missing fingerprint {fp_hex} for {}",
            layout.canonical_name
        );
    }

    let tmp = TempDir::new().expect("tempdir");
    let bn_dir = tmp.path().join("bn_net");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, &f.content).unwrap();
    }

    let pose_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::mp_net::FighterPose")
        .unwrap();
    let pose_struct = bn_lib
        .split("strata_net_encode_FighterPose(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .expect("pose struct in bn_lib")
        .trim()
        .to_owned();
    let pose_fp = mir.layouts[pose_idx].schema_fingerprint;

    let native_test = format!(
        r#"#![forbid(unsafe_code)]
use bamabi_native_rt::StrataNetPacket;
use bamabi_sys::{{FfiBool, ModComponent}};
use bevy_app::{{App, FixedUpdate}};
use bevy_ecs::message::{{MessageCursor, Messages}};
use bevy_ecs::prelude::*;
use native_mp_net_test::*;

#[derive(Resource, Default)]
struct PoseChangedCount(usize);

fn count_pose_changes(
    q: Query<&{pose_struct}, Changed<{pose_struct}>>,
    mut cnt: ResMut<PoseChangedCount>,
) {{
    cnt.0 += q.iter().count();
}}

#[test]
fn bevy_native_end_to_end_tx_rx_selective_mut_and_handshake_rejection() {{
    assert_eq!(core::mem::size_of::<StrataNetPacket>(), 184);
    assert_eq!(<{pose_struct} as ModComponent>::SCHEMA_FINGERPRINT, 0x{pose_fp:016X});

    let mut server = App::new();
    server.add_plugins(StrataNativePlugin);
    let mut server_pose = {pose_struct}::default();
    server_pose.yaw = 37.25;
    server_pose.grounded = 1.0;
    server_pose.precise = 1234.5;
    server_pose.pos = [-12.5, 4.25, 33.75];
    server_pose.seq = 42;
    server_pose.alive = FfiBool::TRUE;
    let server_ent = server.world_mut().spawn(server_pose).id();

    let mut client = App::new();
    client.add_plugins(StrataNativePlugin);
    // Spawn on fresh world before adding extra test systems so Entity bits match server_ent.
    let client_ent = client.world_mut().spawn({pose_struct}::default()).id();
    assert_eq!(server_ent.to_bits(), client_ent.to_bits());
    client.init_resource::<PoseChangedCount>();
    client.add_systems(FixedUpdate, count_pose_changes);

    // Initial FixedUpdate on client consumes the Added change tick so PoseChangedCount resets cleanly
    client.world_mut().run_schedule(FixedUpdate);
    client.world_mut().resource_mut::<PoseChangedCount>().0 = 0;

    // 1. Run server FixedUpdate -> Changed<{pose_struct}> triggers TX into Messages<StrataNetPacket>
    server.world_mut().run_schedule(FixedUpdate);
    let mut cursor = MessageCursor::<StrataNetPacket>::default();
    let tx_pkts: Vec<StrataNetPacket> = {{
        let msgs = server.world().resource::<Messages<StrataNetPacket>>();
        cursor.read(msgs).copied().collect()
    }};
    assert_eq!(tx_pkts.len(), 1, "expected 1 TX packet from Changed<FighterPose>");

    // 2. Pump packet to client -> RX decodes quantized delta via SelectiveMutSlice -> updates client & triggers Changed!
    client.world_mut().resource_mut::<Messages<StrataNetPacket>>().write(tx_pkts[0]);
    client.world_mut().run_schedule(FixedUpdate);

    let c_pose = client.world().get::<{pose_struct}>(client_ent).unwrap();
    assert!((c_pose.yaw - 37.25).abs() < 0.05, "yaw={{}}", c_pose.yaw);
    assert!((c_pose.grounded - 1.0).abs() < 0.001);
    assert!((c_pose.precise - 1234.5).abs() < 0.01);
    assert!((c_pose.pos[0] - (-12.5)).abs() < 0.01);
    assert!((c_pose.pos[1] - 4.25).abs() < 0.01);
    assert!((c_pose.pos[2] - 33.75).abs() < 0.01);
    assert_eq!(c_pose.seq, 42);
    assert!(c_pose.alive.get());
    assert_eq!(client.world().resource::<PoseChangedCount>().0, 1);

    // 3. Re-send identical packet -> SelectiveMutSlice skips dirty tick (no-op)
    client.world_mut().resource_mut::<PoseChangedCount>().0 = 0;
    client.world_mut().resource_mut::<Messages<StrataNetPacket>>().write(tx_pkts[0]);
    client.world_mut().run_schedule(FixedUpdate);
    assert_eq!(client.world().resource::<PoseChangedCount>().0, 0, "no-op packet must not trigger Changed");

    // 4. Send packet with mismatched SCHEMA_FINGERPRINT -> rejected before mutation!
    let mut bad_pkt = tx_pkts[0];
    bad_pkt.item_schema_fingerprint ^= 0xDEAD;
    bad_pkt.payload = [0xAA; 128];
    client.world_mut().resource_mut::<Messages<StrataNetPacket>>().write(bad_pkt);
    client.world_mut().run_schedule(FixedUpdate);
    let c_pose_after = client.world().get::<{pose_struct}>(client_ent).unwrap();
    assert_eq!(c_pose_after.seq, 42, "mismatched packet must not mutate state");
    assert_eq!(client.world().resource::<PoseChangedCount>().0, 0);

    // 5. RPC round-trip
    let rpc = StrataRpc_MoveCmd {{ dx: 0.25, seq: 100 }};
    let rpkt = strata_net_encode_rpc_MoveCmd(&rpc, 5, 0);
    let mut rpc_out = StrataRpc_MoveCmd::default();
    assert!(strata_net_decode_rpc_MoveCmd(&rpkt, &mut rpc_out));
    assert!((rpc_out.dx - 0.25).abs() < 0.02);
    assert_eq!(rpc_out.seq, 100);
}}
"#
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/net_native_e2e.rs"), native_test).unwrap();

    write_offline_patch_config(&ws_root, &bn_dir);
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    let out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "net_native_e2e", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("run cargo test on generated BevyNative crate")
    };
    assert!(
        out.status.success(),
        "BevyNative cargo test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn c99_regression_resource_ticks_quantize_rounding_zst_and_ordering() {
    let src = r#"
module game::c99_reg @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
resource NetClock {
    tick: u32 = 0,
}

@net(reliable, channel = 0)
@authority(server)
component QuantInts {
    @quantize(min = -10.0, max = 10.0, bits = 8)
    qi: i32 = 0,
    @quantize(min = 0.0, max = 1.0, bits = 1)
    half_test: f32 = 0.0,
}

@net(reliable, channel = 0)
@authority(server)
component ZstNetTag {}

@authority(server)
sys user_step() {
    for e in query(q: &mut QuantInts) {
        if e.q.qi == 9999 {
            e.q.qi += 1;
        }
    }
}

schedule FixedUpdate { user_step }
"#;
    let sema = analyze_source("c99_reg.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let c_art = emit_c99(&mir).expect("emit_c99");
    let c_src = &c_art.files[1].content;

    assert!(c_src.contains("#pragma STDC FP_CONTRACT OFF"));
    assert!(c_src.contains("bam_ticks_is_changed(&ticks)"));
    assert!(c_src.contains("round("));
    assert!(c_src.contains("before_weak"));
    assert!(c_src.contains("after_weak"));

    let q_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::c99_reg::QuantInts")
        .unwrap();
    let q_ctype = format!("StrataType_{q_idx}_QuantInts");
    let clk_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::c99_reg::NetClock")
        .unwrap();
    let clk_ctype = format!("StrataType_{clk_idx}_NetClock");
    let q_fp = mir.layouts[q_idx].schema_fingerprint;
    let clk_fp = mir.layouts[clk_idx].schema_fingerprint;
    let zst_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::c99_reg::ZstNetTag")
        .unwrap();
    let zst_fp = mir.layouts[zst_idx].schema_fingerprint;

    let tmp = TempDir::new().expect("tempdir");
    for f in &c_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).expect("write c file");
    }

    let harness = format!(
        r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c99_reg.c"

static void fail_if(int cond, const char* msg) {{
    if (cond) {{ fprintf(stderr, "FAIL: %s\n", msg); exit(1); }}
}}

static BamComponent g_clk = 1u, g_q = 2u, g_zst = 3u, g_net = 4u;
static {clk_ctype} g_clk_val = {{ 55u }};
static BamChangeTicks g_clk_ticks = {{ 1u, 10u, 10u, 11u }};
static StrataNetPacket g_tx[8];
static size_t g_tx_n = 0u;
static BamSystemFn g_tx_fn = NULL;
static void* g_tx_ud = NULL;
static BamSystemFn g_rx_fn = NULL;
static void* g_rx_ud = NULL;
static int g_rx_aw_ok = 0, g_tx_aw_ok = 0, g_user_aw_ok = 0;

typedef struct MockIter {{ uint32_t kind; uint32_t step; }} MockIter;
static MockIter g_msg_it = {{ 0u, 0u }};
static MockIter g_zst_it = {{ 1u, 0u }};
static BamEntity g_ent = 77ull;

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_res(const BamHostCtx* h, const char* n, const BamComponentUuid* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "strata::net::StrataNetPacket") == 0) {{ *o = g_net; return BAM_RESULT_OK; }}
    if (strcmp(n, "game::c99_reg::NetClock") == 0) {{ *o = g_clk; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_c(BamLoadCtx* l, const BamComponentDesc* d, BamComponent* o) {{
    (void)l;
    if (strcmp(d->name, "game::c99_reg::QuantInts") == 0) *o = g_q;
    else if (strcmp(d->name, "game::c99_reg::ZstNetTag") == 0) *o = g_zst;
    else *o = 10u;
    return BAM_RESULT_OK;
}}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h;
    memset(o, 0, sizeof(*o));
    o->struct_size = (uint32_t)sizeof(*o);
    if (c == g_net) {{
        o->flags = BAM_STORAGE_FLAG_MESSAGE;
        o->size = sizeof(StrataNetPacket);
        o->align = 8u;
        o->schema_fingerprint = STRATA_NET_PACKET_SCHEMA_FINGERPRINT;
        return BAM_RESULT_OK;
    }}
    if (c == g_clk) {{ o->flags = BAM_STORAGE_FLAG_RESOURCE; o->schema_fingerprint = 0x{clk_fp:016X}ull; return BAM_RESULT_OK; }}
    if (c == g_q) {{ o->schema_fingerprint = 0x{q_fp:016X}ull; return BAM_RESULT_OK; }}
    if (c == g_zst) {{ o->schema_fingerprint = 0x{zst_fp:016X}ull; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_s(BamLoadCtx* l, const BamSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "__strata_net_rx_0") == 0) {{
        g_rx_fn = d->callback; g_rx_ud = d->user_data;
        if (d->before_weak_count == 2u
            && ((strcmp(d->before_weak[0], "user_step") == 0 && strcmp(d->before_weak[1], "__strata_net_tx_0") == 0)
                || (strcmp(d->before_weak[1], "user_step") == 0 && strcmp(d->before_weak[0], "__strata_net_tx_0") == 0))) {{
            g_rx_aw_ok = 1;
        }}
    }} else if (strcmp(d->name, "__strata_net_tx_0") == 0) {{
        g_tx_fn = d->callback; g_tx_ud = d->user_data;
        if (d->after_weak_count == 2u
            && ((strcmp(d->after_weak[0], "user_step") == 0 && strcmp(d->after_weak[1], "__strata_net_rx_0") == 0)
                || (strcmp(d->after_weak[1], "user_step") == 0 && strcmp(d->after_weak[0], "__strata_net_rx_0") == 0))) {{
            g_tx_aw_ok = 1;
        }}
    }} else if (strcmp(d->name, "user_step") == 0) {{
        if (d->after_weak_count == 1u && strcmp(d->after_weak[0], "__strata_net_rx_0") == 0) g_user_aw_ok = 1;
    }}
    if (o) *o = 1u;
    return BAM_RESULT_OK;
}}
static BamResult m_mnt(BamLoadCtx* l, BamSystem s, BamScheduleId sc, BamSystemSet ss) {{ (void)l; (void)s; (void)sc; (void)ss; return BAM_RESULT_OK; }}
static BamResult m_sq(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc;
    if (qi == 0u) {{ *o = (BamIter*)&g_msg_it; return BAM_RESULT_OK; }}
    if (qi == 2u) {{ g_zst_it.step = 0u; *o = (BamIter*)&g_zst_it; return BAM_RESULT_OK; }}
    *o = NULL; return BAM_RESULT_NOT_FOUND;
}}
static const uint8_t* m_res_ptr(const BamSystemCtx* sc, BamComponent c, BamChangeTicks* t) {{
    (void)sc;
    if (c == g_clk) {{ if (t) *t = g_clk_ticks; return (const uint8_t*)&g_clk_val; }}
    return NULL;
}}
static BamResult m_it_rst(BamIter* i) {{ ((MockIter*)i)->step = 0u; return BAM_RESULT_OK; }}
static BamBool m_it_next(BamIter* i, size_t* l) {{
    MockIter* mi = (MockIter*)i;
    if (mi->kind == 1u && mi->step == 0u) {{ mi->step = 1u; *l = 1u; return BAM_TRUE; }}
    *l = 0u; return BAM_FALSE;
}}
static const BamEntity* m_it_ents(const BamIter* i) {{ (void)i; return &g_ent; }}
static const uint8_t* m_it_col_ro(const BamIter* i, size_t ti) {{ (void)i; (void)ti; return NULL; }}
static uint8_t* m_it_col_mut(BamIter* i, size_t ti) {{ (void)i; (void)ti; return NULL; }}
static BamResult m_msg_rb(BamIter* i, size_t ti, uint8_t* b, size_t m, size_t* out_r) {{
    (void)i; (void)ti; (void)b; (void)m; *out_r = 0u; return BAM_RESULT_OK;
}}
static BamResult m_msg_wb(BamIter* i, size_t ti, const uint8_t* b, size_t c) {{
    (void)i; (void)ti;
    if (c > 0u) {{ memcpy(&g_tx[g_tx_n], b, c * sizeof(StrataNetPacket)); g_tx_n += c; }}
    return BAM_RESULT_OK;
}}

int main(void) {{
    /* 1. Quantization rounding parity */
    uint64_t q_half = strata_net_quantize_scalar_f64(0.49999999999999994, 0.0, 1.0, 1u, 0.0, false);
    fail_if(q_half != 0ull, "0.49999999999999994 1-bit must quantize to 0");

    {q_ctype} qin, qout;
    memset(&qin, 0, sizeof(qin));
    memset(&qout, 0, sizeof(qout));
    qin.qi = 1;
    qin.half_test = 0.0f;
    StrataNetPacket qpkt;
    strata_net_encode_QuantInts(&qin, 1ull, 0u, 0u, &qpkt);
    fail_if(!strata_net_decode_QuantInts(&qpkt, &qout), "QuantInts decode failed");
    fail_if(qout.qi != 1, "quantized i32=1 [-10,10] 8-bit must decode to 1");

    /* 2. Init + weak ordering + resource ticks + ZST guard */
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.load_host_ctx = m_hc;
    api.resolve_component = m_res;
    api.register_component = m_reg_c;
    api.component_layout_info = m_linfo;
    api.register_system_handle = m_reg_s;
    api.mount_system_in_schedule = m_mnt;
    api.sys_query = m_sq;
    api.sys_res_ptr = m_res_ptr;
    api.iter_reset = m_it_rst;
    api.iter_next_chunk = m_it_next;
    api.iter_entities = m_it_ents;
    api.iter_column_readonly = m_it_col_ro;
    api.iter_column_mutable_untracked = m_it_col_mut;
    api.msg_read_batch = m_msg_rb;
    api.msg_write_batch = m_msg_wb;

    int ctx = 1;
    BamInstance* inst = NULL;
    fail_if(bamabi_init(&api, (BamLoadCtx*)&ctx, &inst) != BAM_RESULT_OK, "init failed");
    fail_if(!g_rx_aw_ok || !g_tx_aw_ok || !g_user_aw_ok, "FixedUpdate weak ordering edges missing");

    /* Unchanged resource: changed (10) == last_run (10), this_run = 11 -> must NOT transmit NetClock! (Only ZstNetTag transmits) */
    g_tx_n = 0u;
    fail_if(g_tx_fn((BamSystemCtx*)&ctx, g_tx_ud) != BAM_RESULT_OK, "tx 1 failed");
    fail_if(g_tx_n != 1u, "unchanged NetClock must NOT transmit (expected only 1 ZstNetTag pkt)");
    fail_if(g_tx[0].kind != STRATA_NET_KIND_COMPONENT_DELTA, "only ZstNetTag should have transmitted");

    /* Changed resource: changed (11) > last_run (10), this_run = 11 -> MUST transmit NetClock + ZstNetTag */
    g_clk_ticks.changed = 11u;
    g_tx_n = 0u;
    fail_if(g_tx_fn((BamSystemCtx*)&ctx, g_tx_ud) != BAM_RESULT_OK, "tx 2 failed");
    fail_if(g_tx_n != 2u, "changed NetClock must transmit");
    fail_if(g_tx[0].kind != STRATA_NET_KIND_RESOURCE_DELTA, "first pkt should be NetClock resource");

    /* Wraparound A: changed=0, last_run=0xFFFFFFFE, this_run=1 -> MUST transmit NetClock */
    g_clk_ticks.added = 1u;
    g_clk_ticks.changed = 0u;
    g_clk_ticks.last_run = 0xFFFFFFFEu;
    g_clk_ticks.this_run = 1u;
    g_tx_n = 0u;
    fail_if(g_tx_fn((BamSystemCtx*)&ctx, g_tx_ud) != BAM_RESULT_OK, "tx wrap A failed");
    fail_if(g_tx_n != 2u, "wraparound changed=0 NetClock must transmit");
    fail_if(g_tx[0].kind != STRATA_NET_KIND_RESOURCE_DELTA, "wrap A first pkt should be NetClock resource");

    /* Wraparound B: changed=0xFFFFFFFE, last_run=0, this_run=1 -> must NOT transmit NetClock */
    g_clk_ticks.added = 1u;
    g_clk_ticks.changed = 0xFFFFFFFEu;
    g_clk_ticks.last_run = 0u;
    g_clk_ticks.this_run = 1u;
    g_tx_n = 0u;
    fail_if(g_tx_fn((BamSystemCtx*)&ctx, g_tx_ud) != BAM_RESULT_OK, "tx wrap B failed");
    fail_if(g_tx_n != 1u, "wraparound old change with last_run=0 must NOT transmit NetClock");
    fail_if(g_tx[0].kind != STRATA_NET_KIND_COMPONENT_DELTA, "wrap B only ZstNetTag should transmit");

    bamabi_shutdown(inst);
    return 0;
}}
"#,
    );

    let h_path = tmp.path().join("c99_reg_harness.c");
    fs::write(&h_path, harness).unwrap();
    let exe = tmp.path().join("c99_reg_harness");
    let cc = find_c99_compiler();
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
        .arg(&h_path)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("compile c99_reg_harness");
    assert!(
        comp.status.success(),
        "C99 regression compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&exe).output().expect("run c99_reg_harness");
    assert!(
        run.status.success(),
        "C99 regression run failed:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn rust_guest_and_bevy_native_regressions_sparse_extra_changed_u16_struct_and_zero_field_rpc() {
    let src = r#"
module game::m4_reg @version(1.0.0);

struct SubU16 {
    a: u16,
    b: u16,
}

@net(reliable, channel = 0)
@authority(server)
@sparse
component SparseNet {
    val: u32 = 0,
}

@net(reliable, channel = 0)
@authority(server)
component ComplexNet {
    sub16: SubU16,
    arr_u16: [u16; 2] = [0, 0],
    arr_i16: [i16; 2] = [0, 0],
    arr_i8: [i8; 2] = [0, 0],
    arr_i64: [i64; 2] = [0, 0],
    @quantize(min = -10.0, max = 10.0, bits = 8)
    qi: i32 = 0,
}

component ExtraA { x: f32 = 0.0 }
component ExtraB { y: f32 = 0.0 }

@net(reliable, channel = 0)
@authority(server)
resource ResFirst { a: u32 = 1 }

@net(reliable, channel = 1)
@authority(server)
resource ResSecond { b: u32 = 2 }

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc Ping {}

sys use_extra_changed() {
    for e in query(p: &mut ExtraA).changed<ExtraB>() {
        e.p.x += 1.0;
    }
}

sys use_multi_changed() {
    for e in query(a: &ExtraA, b: &mut ExtraB).changed() {
        e.b.y += e.a.x;
    }
}

schedule FixedUpdate { use_extra_changed, use_multi_changed }
"#;
    let sema = analyze_source("m4_reg.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);

    // 1. C99 zero-field Ping RPC + multi-array compiles cleanly under strict -Werror
    let c_art = emit_c99(&mir).expect("emit_c99 reg");
    let tmp = TempDir::new().expect("tempdir");
    for f in &c_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).unwrap();
    }
    let c_probe = tmp.path().join("ping_probe.c");
    fs::write(
        &c_probe,
        "#include \"m4_reg.c\"\nint main(void) { StrataRpc_Ping p; memset(&p, 0, sizeof(p)); StrataNetPacket pkt; strata_net_encode_rpc_Ping(&p, 1u, 0u, &pkt); return strata_net_decode_rpc_Ping(&pkt, &p) ? 0 : 1; }\n",
    )
    .unwrap();
    let cc = find_c99_compiler();
    let c_comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&c_probe)
        .arg("-o")
        .arg(tmp.path().join("ping_probe"))
        .output()
        .unwrap();
    assert!(
        c_comp.status.success(),
        "C99 Ping/ComplexNet compile failed:\n{}",
        String::from_utf8_lossy(&c_comp.stderr)
    );

    // 2. Rust Guest codegen assertions + compile & test + dlopen multi-resource absent-first check
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "strata_guest_m4_reg_test".to_owned(),
        },
    )
    .expect("emit_rust_guest reg");
    let rg_lib = &rg_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    assert!(rg_lib.contains("strata_net_encode_SparseNet(&rows[row]"));
    assert!(rg_lib.contains("_tx_res_decl"));
    assert!(!rg_lib.contains("pkt.payload_bytes < 0"));

    let rg_dir = tmp.path().join("rg_reg");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let complex_struct = rg_lib
        .split("strata_net_encode_ComplexNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use {crate_name}::*;

#[test]
fn u16_struct_arrays_quant_i32_and_zero_field_rpc_roundtrip() {{
    let mut src = {complex_struct}::default();
    src.sub16 = [0x1234, 0xABCD];
    src.arr_u16 = [0x5566, 0x7788];
    src.arr_i16 = [-1234, 4321];
    src.arr_i8 = [-42, 99];
    src.arr_i64 = [-9_000_000_000, 9_000_000_000];
    src.qi = 1;
    let pkt = strata_net_encode_ComplexNet(&src, 99, 1, 0);
    let mut dst = {complex_struct}::default();
    assert!(strata_net_decode_ComplexNet(&pkt, &mut dst));
    assert_eq!(dst.sub16, [0x1234, 0xABCD]);
    assert_eq!(dst.arr_u16, [0x5566, 0x7788]);
    assert_eq!(dst.arr_i16, [-1234, 4321]);
    assert_eq!(dst.arr_i8, [-42, 99]);
    assert_eq!(dst.arr_i64, [-9_000_000_000, 9_000_000_000]);
    assert_eq!(dst.qi, 1);

    let rpkt = strata_net_encode_rpc_Ping(&StrataRpc_Ping, 7, 1);
    let mut rout = StrataRpc_Ping;
    assert!(strata_net_decode_rpc_Ping(&rpkt, &mut rout));
}}
"#,
        crate_name = "strata_guest_m4_reg_test",
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/reg_e2e.rs"), rg_test).unwrap();
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    write_offline_patch_config(&ws_root, &rg_dir);
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let rg_out = sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "reg_e2e", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap();
        assert!(
            rg_out.status.success(),
            "RustGuest reg test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&rg_out.stdout),
            String::from_utf8_lossy(&rg_out.stderr)
        );

        // Check zero compiler warnings on generated crate itself via `cargo rustc --lib -- -D warnings`
        let rg_warn = sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("rustc")
            .args(common::cargo_offline_flag())
            .args(["--lib", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .args(["--", "-D", "warnings"])
            .output()
            .unwrap();
        assert!(
            rg_warn.status.success(),
            "RustGuest lib had warnings:\n{}",
            String::from_utf8_lossy(&rg_warn.stderr)
        );

        // Build cdylib and test runtime multi-@net resource TX when first resource is absent (`NOT_FOUND`)
        let rg_cdylib_build = sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("build")
            .args(common::cargo_offline_flag())
            .arg("--manifest-path")
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap();
        assert!(rg_cdylib_build.status.success());

        let dylib_ext = if cfg!(target_os = "macos") {
            "dylib"
        } else if cfg!(target_os = "windows") {
            "dll"
        } else {
            "so"
        };
        let dylib_prefix = if cfg!(target_os = "windows") {
            ""
        } else {
            "lib"
        };
        let cdylib_path = target_dir.join("debug").join(format!(
            "{dylib_prefix}strata_guest_m4_reg_test.{dylib_ext}"
        ));
        if cfg!(any(target_os = "macos", target_os = "linux")) && cdylib_path.exists() {
            let res2_layout = mir
                .layouts
                .iter()
                .find(|l| l.canonical_name == "game::m4_reg::ResSecond")
                .unwrap();
            let res2_fp = res2_layout.schema_fingerprint;
            let res2_uuid_bytes: String = res2_layout
                .uuid_bytes
                .iter()
                .map(|b| format!("0x{b:02X}u"))
                .collect::<Vec<_>>()
                .join(", ");
            let pkt_uuid = strata_codegen::net::stratanet_packet_uuid();
            let pkt_uuid_bytes: String = pkt_uuid
                .as_bytes()
                .iter()
                .map(|b| format!("0x{b:02X}u"))
                .collect::<Vec<_>>()
                .join(", ");
            let bamabi_h = strata_codegen::emit_bamabi_header();
            fs::write(tmp.path().join("bamabi.h"), bamabi_h).unwrap();
            let dl_c = format!(
                r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "bamabi.h"

static BamComponent g_res2 = 2u, g_net = 9u;
static uint32_t g_res2_val = 42u;
static uint8_t g_tx_buf[184 * 4];
static size_t g_tx_cnt = 0u;
static BamSystemFn g_tx_fn = NULL;
static void* g_tx_ud = NULL;
static int g_tx_q0_n = 0;
static size_t g_tx_res_q_idx = 0u;

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_res(const BamHostCtx* h, const char* n, const BamComponentUuid* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "strata::net::StrataNetPacket") == 0) {{ *o = g_net; return BAM_RESULT_OK; }}
    if (strcmp(n, "game::m4_reg::ResSecond") == 0) {{ *o = g_res2; return BAM_RESULT_OK; }}
    if (strcmp(n, "game::m4_reg::SparseNet") == 0) {{ *o = 20u; return BAM_RESULT_OK; }}
    if (strcmp(n, "game::m4_reg::ComplexNet") == 0) {{ *o = 21u; return BAM_RESULT_OK; }}
    if (strcmp(n, "game::m4_reg::ExtraA") == 0) {{ *o = 22u; return BAM_RESULT_OK; }}
    if (strcmp(n, "game::m4_reg::ExtraB") == 0) {{ *o = 23u; return BAM_RESULT_OK; }}
    /* ResFirst intentionally returns NOT_FOUND */
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_c(BamLoadCtx* l, const BamComponentDesc* d, BamComponent* o) {{
    (void)l;
    if (strcmp(d->name, "game::m4_reg::SparseNet") == 0) *o = 20u;
    else if (strcmp(d->name, "game::m4_reg::ComplexNet") == 0) *o = 21u;
    else if (strcmp(d->name, "game::m4_reg::ExtraA") == 0) *o = 22u;
    else if (strcmp(d->name, "game::m4_reg::ExtraB") == 0) *o = 23u;
    else *o = 24u;
    return BAM_RESULT_OK;
}}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h;
    memset(o, 0, sizeof(*o));
    o->struct_size = (uint32_t)sizeof(*o);
    if (c == g_net) {{
        o->flags = BAM_STORAGE_FLAG_MESSAGE;
        o->size = 184u; o->align = 8u;
        o->schema_fingerprint = 0x{pkt_fp:016X}ull;
        return BAM_RESULT_OK;
    }}
    if (c == g_res2) {{
        o->flags = BAM_STORAGE_FLAG_RESOURCE;
        o->size = 4u; o->align = 4u;
        o->schema_fingerprint = 0x{res2_fp:016X}ull;
        return BAM_RESULT_OK;
    }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_s(BamLoadCtx* l, const BamSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "__strata_net_tx_0") == 0) {{
        g_tx_fn = d->callback; g_tx_ud = d->user_data;
        if (d->query_count > 0u && d->queries != NULL) {{
            size_t q_stride = (size_t)d->queries[0].struct_size;
            if (q_stride < sizeof(BamQueryDesc)) q_stride = sizeof(BamQueryDesc);
            g_tx_res_q_idx = d->query_count - 1u;
            const BamQueryDesc* last_q = (const BamQueryDesc*)((const uint8_t*)d->queries + g_tx_res_q_idx * q_stride);
            g_tx_q0_n = (int)last_q->term_count;
        }}
    }}
    if (o) *o = 1u;
    return BAM_RESULT_OK;
}}
static BamResult m_mnt(BamLoadCtx* l, BamSystem s, BamScheduleId sc, BamSystemSet ss) {{ (void)l; (void)s; (void)sc; (void)ss; return BAM_RESULT_OK; }}
static int g_msg_it = 0;
static BamResult m_sq(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc;
    if (qi == g_tx_res_q_idx) {{ *o = (BamIter*)&g_msg_it; return BAM_RESULT_OK; }}
    *o = NULL; return BAM_RESULT_NOT_FOUND;
}}
static const uint8_t* m_res_ptr(const BamSystemCtx* sc, BamComponent c, BamChangeTicks* t) {{
    (void)sc;
    if (c == g_res2) {{
        if (t) {{ t->added = 1u; t->changed = 5u; t->last_run = 4u; t->this_run = 5u; }}
        return (const uint8_t*)&g_res2_val;
    }}
    return NULL;
}}
static BamResult m_it_rst(BamIter* i) {{ (void)i; return BAM_RESULT_OK; }}
static BamBool m_it_next(BamIter* i, size_t* l) {{ (void)i; *l = 0u; return BAM_FALSE; }}
static BamResult m_msg_wb(BamIter* i, size_t ti, const uint8_t* b, size_t c) {{
    (void)i; (void)ti;
    if (c > 0u && c <= 4u) {{ memcpy(g_tx_buf, b, c * 184u); g_tx_cnt += c; }}
    return BAM_RESULT_OK;
}}

static const void* m_get_proc(const BamHostCtx* h, const char* n) {{ (void)h; (void)n; return NULL; }}
static size_t m_last_err(const BamHostCtx* h, char* b, size_t c) {{ (void)h; (void)b; (void)c; return 0u; }}
static const BamHostCtx* m_sys_hc(const BamSystemCtx* s) {{ (void)s; return NULL; }}
static BamResult m_sys_cmds(BamSystemCtx* s, BamCommands** o) {{ (void)s; (void)o; return BAM_RESULT_OK; }}
static const BamEntity* m_it_ents(const BamIter* i) {{ (void)i; return NULL; }}
static const uint8_t* m_it_ro(const BamIter* i, size_t ti) {{ (void)i; (void)ti; return NULL; }}
static uint8_t* m_it_mut(BamIter* i, size_t ti) {{ (void)i; (void)ti; return NULL; }}
static BamResult m_it_mark(BamIter* i, size_t ti, size_t s, size_t c) {{ (void)i; (void)ti; (void)s; (void)c; return BAM_RESULT_OK; }}
static const uint8_t* const* m_it_r_ro(BamIter* i, size_t ti) {{ (void)i; (void)ti; return NULL; }}
static uint8_t* const* m_it_r_mut(BamIter* i, size_t ti) {{ (void)i; (void)ti; return NULL; }}
static BamResult m_it_col_info(const BamIter* i, size_t ti, BamColumnInfo* o) {{
    (void)i;
    if (o != NULL) {{
        static const uint8_t res2_u[16] = {{ {res2_uuid_bytes} }};
        static const uint8_t pkt_u[16] = {{ {pkt_uuid_bytes} }};
        memset(o, 0, sizeof(*o));
        if (ti == 0u) {{
            o->component = g_res2;
            o->mode = BAM_ACCESS_RESOURCE_READ;
            memcpy(o->uuid.bytes, res2_u, 16u);
            o->size = 4u;
            o->align = 4u;
            o->storage_flags = BAM_STORAGE_FLAG_RESOURCE;
        }} else {{
            o->component = g_net;
            o->mode = BAM_ACCESS_MESSAGE_WRITE;
            memcpy(o->uuid.bytes, pkt_u, 16u);
            o->size = 184u;
            o->align = 8u;
            o->storage_flags = BAM_STORAGE_FLAG_MESSAGE;
        }}
    }}
    return BAM_RESULT_OK;
}}
static const uint8_t* m_r_ptr(const BamIter* i, size_t ti) {{
    (void)i;
    if (ti == 0u) return (const uint8_t*)&g_res2_val;
    return NULL;
}}
static BamResult m_r_ticks(const BamIter* i, size_t ti, BamChangeTicks* t) {{
    (void)i;
    if (ti == 0u && t != NULL) {{
        t->added = 1u; t->changed = 5u; t->last_run = 4u; t->this_run = 5u;
        return BAM_RESULT_OK;
    }}
    return BAM_RESULT_NOT_FOUND;
}}
static uint8_t* m_r_mut_ptr(BamIter* i, size_t ti) {{ (void)i; (void)ti; return NULL; }}
static BamResult m_c_spawn_empty(BamCommands* c, BamEntity* o) {{ (void)c; (void)o; return BAM_RESULT_OK; }}
static BamResult m_c_spawn(BamCommands* c, const BamComponent* cs, const uint8_t* const* ps, size_t n, BamEntity* o) {{ (void)c; (void)cs; (void)ps; (void)n; (void)o; return BAM_RESULT_OK; }}
static BamResult m_c_despawn(BamCommands* c, BamEntity e) {{ (void)c; (void)e; return BAM_RESULT_OK; }}
static BamResult m_c_ins(BamCommands* c, BamEntity e, BamComponent k, const uint8_t* p, size_t sz) {{ (void)c; (void)e; (void)k; (void)p; (void)sz; return BAM_RESULT_OK; }}
static BamResult m_c_ins_def(BamCommands* c, BamEntity e, BamComponent k) {{ (void)c; (void)e; (void)k; return BAM_RESULT_OK; }}
static BamResult m_c_rem(BamCommands* c, BamEntity e, BamComponent k) {{ (void)c; (void)e; (void)k; return BAM_RESULT_OK; }}
static BamResult m_cfg_set(BamLoadCtx* l, const BamScheduleSetDesc* d, BamSystemSet* o) {{
    (void)l; (void)d; if (o) *o = 1u; return BAM_RESULT_OK;
}}
static BamResult m_reg_s_simple(BamLoadCtx* l, const BamSystemDesc* d) {{
    BamSystem s = 0u; return m_reg_s(l, d, &s);
}}

int main(void) {{
    void* lib = dlopen("{cdylib}", RTLD_NOW);
    if (!lib) {{ fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }}
    BamInitFn init_fn = (BamInitFn)dlsym(lib, "bamabi_init");
    BamShutdownFn shut_fn = (BamShutdownFn)dlsym(lib, "bamabi_shutdown");
    if (!init_fn || !shut_fn) return 2;
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = BAM_ABI_VERSION;
    api.get_proc_address = m_get_proc;
    api.last_error = m_last_err;
    api.load_host_ctx = m_hc;
    api.register_component = m_reg_c;
    api.resolve_component = m_res;
    api.register_system = m_reg_s_simple;
    api.sys_host_ctx = m_sys_hc;
    api.sys_query = m_sq;
    api.sys_commands = m_sys_cmds;
    api.iter_next_chunk = m_it_next;
    api.iter_reset = m_it_rst;
    api.iter_entities = m_it_ents;
    api.iter_column_readonly = m_it_ro;
    api.iter_column_mutable = m_it_mut;
    api.iter_column_mutable_untracked = m_it_mut;
    api.iter_mark_changed_range = m_it_mark;
    api.iter_column_rows_readonly = m_it_r_ro;
    api.iter_column_rows_mutable = m_it_r_mut;
    api.iter_column_info = m_it_col_info;
    api.res_ptr = m_r_ptr;
    api.res_ticks = m_r_ticks;
    api.res_mut_ptr = m_r_mut_ptr;
    api.cmd_spawn_empty = m_c_spawn_empty;
    api.cmd_spawn = m_c_spawn;
    api.cmd_despawn = m_c_despawn;
    api.cmd_insert = m_c_ins;
    api.cmd_insert_default = m_c_ins_def;
    api.cmd_remove = m_c_rem;
    api.sys_res_ptr = m_res_ptr;
    api.msg_write_batch = m_msg_wb;
    api.component_layout_info = m_linfo;
    api.register_system_handle = m_reg_s;
    api.configure_schedule_set = m_cfg_set;
    api.mount_system_in_schedule = m_mnt;
    int ctx = 1;
    BamInstance* inst = NULL;
    BamResult init_rc = init_fn(&api, (BamLoadCtx*)&ctx, &inst);
    if (init_rc != BAM_RESULT_OK) {{ fprintf(stderr, "init_rc=%u\n", init_rc); return 3; }}
    if (!g_tx_fn || g_tx_q0_n != 2) {{ fprintf(stderr, "tx_fn=%d q0_n=%d q_idx=%zu\n", g_tx_fn != NULL, g_tx_q0_n, g_tx_res_q_idx); return 4; }} /* 1 res (ResSecond) + 1 msg */
    if (g_tx_fn((BamSystemCtx*)&ctx, g_tx_ud) != BAM_RESULT_OK) return 5;
    if (g_tx_cnt != 1u) return 6;
    shut_fn(inst);
    dlclose(lib);
    return 0;
}}
"#,
                pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
                cdylib = cdylib_path.display(),
            );
            let dl_c_path = tmp.path().join("rg_multi_res_dl.c");
            let dl_bin = tmp.path().join("rg_multi_res_dl");
            fs::write(&dl_c_path, dl_c).unwrap();
            let mut cmd = Command::new(cc);
            cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-I"])
                .arg(tmp.path())
                .arg(&dl_c_path)
                .arg("-o")
                .arg(&dl_bin);
            if cfg!(target_os = "linux") {
                cmd.arg("-ldl");
            }
            let dc = cmd.output().unwrap();
            assert!(
                dc.status.success(),
                "rg_multi_res_dl compile failed:\n{}",
                String::from_utf8_lossy(&dc.stderr)
            );
            let dr = Command::new(&dl_bin).output().unwrap();
            assert!(
                dr.status.success(),
                "rg_multi_res_dl failed with code {:?}\nstdout:\n{}\nstderr:\n{}",
                dr.status.code(),
                String::from_utf8_lossy(&dr.stdout),
                String::from_utf8_lossy(&dr.stderr)
            );
        }
    }

    // 3. Bevy Native `[u16; N]` / `align == 2` nested struct + zero-field Ping RPC + `-D warnings`
    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt")).unwrap();
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_m4_reg_test".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native reg");
    let bn_lib = &bn_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    assert!(!bn_lib.contains("pkt.payload_bytes < 0"));

    let bn_dir = tmp.path().join("bn_reg");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_complex_struct = bn_lib
        .split("strata_net_encode_ComplexNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use native_m4_reg_test::*;

#[test]
fn bevy_native_u16_struct_arrays_and_zero_field_rpc_roundtrip() {{
    let mut src = {bn_complex_struct}::default();
    src.sub16 = [0x1234, 0xABCD];
    src.arr_u16 = [0x5566, 0x7788];
    src.arr_i16 = [-1234, 4321];
    src.arr_i8 = [-42, 99];
    src.arr_i64 = [-9_000_000_000, 9_000_000_000];
    src.qi = 1;
    let pkt = strata_net_encode_ComplexNet(&src, 99, 1, 0);
    let mut dst = {bn_complex_struct}::default();
    assert!(strata_net_decode_ComplexNet(&pkt, &mut dst));
    assert_eq!(dst.sub16, [0x1234, 0xABCD]);
    assert_eq!(dst.arr_u16, [0x5566, 0x7788]);
    assert_eq!(dst.arr_i16, [-1234, 4321]);
    assert_eq!(dst.arr_i8, [-42, 99]);
    assert_eq!(dst.arr_i64, [-9_000_000_000, 9_000_000_000]);
    assert_eq!(dst.qi, 1);

    let rpkt = strata_net_encode_rpc_Ping(&StrataRpc_Ping, 7, 1);
    let mut rout = StrataRpc_Ping;
    assert!(strata_net_decode_rpc_Ping(&rpkt, &mut rout));
}}
"#
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/reg_native_e2e.rs"), bn_test).unwrap();
    write_offline_patch_config(&ws_root, &bn_dir);

    let (bn_out, bn_warn) = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let bn_out = sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "reg_native_e2e", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap();
        let bn_warn = sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("rustc")
            .args(common::cargo_offline_flag())
            .args(["--lib", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .args(["--", "-D", "warnings"])
            .output()
            .unwrap();
        (bn_out, bn_warn)
    };
    assert!(
        bn_out.status.success(),
        "BevyNative reg test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr)
    );
    assert!(
        bn_warn.status.success(),
        "BevyNative lib had warnings:\n{}",
        String::from_utf8_lossy(&bn_warn.stderr)
    );

    // 4. Explicit missing-field error across all 3 AOT backends (no silent drop)
    let mut missing_field_mir = mir;
    let nc = missing_field_mir
        .net_components
        .iter_mut()
        .find(|c| c.name == "SparseNet")
        .unwrap();
    nc.wire_fields[0].field_name = "missing_cold_field".to_owned();
    assert!(matches!(
        emit_c99(&missing_field_mir),
        Err(CodegenError::Unsupported { .. })
    ));
    assert!(matches!(
        emit_rust_guest(&missing_field_mir),
        Err(CodegenError::Unsupported { .. })
    ));
    assert!(matches!(
        emit_bevy_native(&missing_field_mir, &BevyNativeOptions::default()),
        Err(CodegenError::Unsupported { .. })
    ));
}

#[test]
fn asset_handle_and_nested_u16_array_roundtrip_across_rust_guest_and_bevy_native() {
    let src = r#"
module game::asset_grid_net @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
component AssetGridNet {
    icon: Asset<u32>,
    grid: [[u16; 2]; 2],
}

schedule FixedUpdate {}
"#;
    let sema = analyze_source("asset_grid_net.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    // 1. Rust Guest compile (`-D warnings`) + round-trip
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_asset_grid_test".to_owned(),
        },
    )
    .expect("emit_rust_guest AssetGridNet");
    let rg_lib = &rg_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    assert!(rg_lib.contains("asset_type.to_raw()"));
    assert!(!rg_lib.contains("asset_type.raw()"));

    let rg_dir = tmp.path().join("rg_asset");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let rg_struct = rg_lib
        .split("strata_net_encode_AssetGridNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use bamabi_sys::{{BamComponent, ComponentUuid, FfiAssetHandle}};
use guest_asset_grid_test::*;

#[test]
fn asset_handle_and_nested_u16_array_roundtrip() {{
    let mut src = {rg_struct}::default();
    src.icon = FfiAssetHandle::from_index(BamComponent::from_raw(7), 42, 3);
    src.grid = [[0x1234, 0xABCD], [0x55AA, 0xCAFE]];
    let pkt = strata_net_encode_AssetGridNet(&src, 123, 9, 2);
    let mut dst = {rg_struct}::default();
    assert!(strata_net_decode_AssetGridNet(&pkt, &mut dst));
    assert_eq!(dst.icon, src.icon);
    assert_eq!(dst.grid, [[0x1234, 0xABCD], [0x55AA, 0xCAFE]]);

    let uuid = ComponentUuid::from_bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
    src.icon = FfiAssetHandle::from_uuid(BamComponent::from_raw(11), uuid);
    let pkt2 = strata_net_encode_AssetGridNet(&src, 456, 10, 1);
    let mut dst2 = {rg_struct}::default();
    assert!(strata_net_decode_AssetGridNet(&pkt2, &mut dst2));
    assert_eq!(dst2.icon, src.icon);
    assert_eq!(dst2.grid, src.grid);

    // Emit deterministic hex line of payload for cross-backend comparison if needed.
    assert_eq!(pkt.payload_bytes, 40);
}}
"#
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/asset_e2e.rs"), rg_test).unwrap();
    write_offline_patch_config(&ws_root, &rg_dir);

    let (rg_out, rg_warn) = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let rg_out = sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "asset_e2e", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap();
        let rg_warn = sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("rustc")
            .args(common::cargo_offline_flag())
            .args(["--lib", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .args(["--", "-D", "warnings"])
            .output()
            .unwrap();
        (rg_out, rg_warn)
    };
    assert!(
        rg_out.status.success(),
        "RustGuest AssetGridNet test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rg_out.stdout),
        String::from_utf8_lossy(&rg_out.stderr)
    );
    assert!(
        rg_warn.status.success(),
        "RustGuest AssetGridNet lib warnings:\n{}",
        String::from_utf8_lossy(&rg_warn.stderr)
    );

    // 2. Bevy Native compile (`-D warnings`) + round-trip
    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt")).unwrap();
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_asset_grid_test".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native AssetGridNet");
    let bn_lib = &bn_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    assert!(bn_lib.contains("BamComponent"));

    let bn_dir = tmp.path().join("bn_asset");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_struct = bn_lib
        .split("strata_net_encode_AssetGridNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use bamabi_sys::{{BamComponent, ComponentUuid, FfiAssetHandle}};
use native_asset_grid_test::*;

#[test]
fn bevy_native_asset_handle_and_nested_u16_array_roundtrip() {{
    let mut src = {bn_struct}::default();
    src.icon = FfiAssetHandle::from_index(BamComponent::from_raw(7), 42, 3);
    src.grid = [[0x1234, 0xABCD], [0x55AA, 0xCAFE]];
    let pkt = strata_net_encode_AssetGridNet(&src, 123, 9, 2);
    let mut dst = {bn_struct}::default();
    assert!(strata_net_decode_AssetGridNet(&pkt, &mut dst));
    assert_eq!(dst.icon, src.icon);
    assert_eq!(dst.grid, [[0x1234, 0xABCD], [0x55AA, 0xCAFE]]);

    let uuid = ComponentUuid::from_bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);
    src.icon = FfiAssetHandle::from_uuid(BamComponent::from_raw(11), uuid);
    let pkt2 = strata_net_encode_AssetGridNet(&src, 456, 10, 1);
    let mut dst2 = {bn_struct}::default();
    assert!(strata_net_decode_AssetGridNet(&pkt2, &mut dst2));
    assert_eq!(dst2.icon, src.icon);
    assert_eq!(dst2.grid, src.grid);
}}
"#
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/asset_native_e2e.rs"), bn_test).unwrap();
    write_offline_patch_config(&ws_root, &bn_dir);

    let (bn_out, bn_warn) = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let bn_out = sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "asset_native_e2e", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap();
        let bn_warn = sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("rustc")
            .args(common::cargo_offline_flag())
            .args(["--lib", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .args(["--", "-D", "warnings"])
            .output()
            .unwrap();
        (bn_out, bn_warn)
    };
    assert!(
        bn_out.status.success(),
        "BevyNative AssetGridNet test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr)
    );
    assert!(
        bn_warn.status.success(),
        "BevyNative AssetGridNet lib warnings:\n{}",
        String::from_utf8_lossy(&bn_warn.stderr)
    );
}

#[test]
fn quantized_ivec_uvec_and_i64_u64_parity_across_c99_rust_guest_bevy_native_and_oracle() {
    use strata_codegen::net::{dequantize_scalar_f64, pack_bits_le, quantize_scalar_f64};

    let src = r#"
module game::ivec_quant_parity @version(1.0.0);

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
    let sema = analyze_source("ivec_quant_parity.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let nc = &mir.net_components[0];

    // Oracle computation using `strata_codegen::net`
    let mut oracle_payload = [0u8; 128];
    let mut oracle_tie_payload = [0u8; 128];
    let iv2_in = [-3i32, 1i32];
    let iv3_in = [-7i32, 0i32, 9i32];
    let uv2_in = [5u32, 99u32];
    let iv2_tie_in = [-1i32, 0i32];
    let qi64_in = -7i64;
    let qu64_in = 42u64;

    let mut exp_iv2 = [0i32; 2];
    let mut exp_iv3 = [0i32; 3];
    let mut exp_uv2 = [0u32; 2];
    let mut exp_qi64 = 0i64;
    let mut exp_qu64 = 0u64;

    for wf in &nc.wire_fields {
        let q = wf.quantize.as_ref().expect("quantize spec");
        match wf.field_name.as_str() {
            "iv2" => {
                for (li, &val) in iv2_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(val), q.min, q.max, q.bits, q.step);
                    let boff = wf.bit_offset + (li as u32) * u32::from(q.bits);
                    pack_bits_le(&mut oracle_payload, boff, q.bits, qv);
                    pack_bits_le(&mut oracle_tie_payload, boff, q.bits, qv);
                    exp_iv2[li] =
                        dequantize_scalar_f64(qv, q.min, q.max, q.bits, q.step).round() as i32;
                }
            }
            "iv3" => {
                for (li, &val) in iv3_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(val), q.min, q.max, q.bits, q.step);
                    let boff = wf.bit_offset + (li as u32) * u32::from(q.bits);
                    pack_bits_le(&mut oracle_payload, boff, q.bits, qv);
                    pack_bits_le(&mut oracle_tie_payload, boff, q.bits, qv);
                    exp_iv3[li] =
                        dequantize_scalar_f64(qv, q.min, q.max, q.bits, q.step).round() as i32;
                }
            }
            "uv2" => {
                for (li, &val) in uv2_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(val), q.min, q.max, q.bits, q.step);
                    let boff = wf.bit_offset + (li as u32) * u32::from(q.bits);
                    pack_bits_le(&mut oracle_payload, boff, q.bits, qv);
                    pack_bits_le(&mut oracle_tie_payload, boff, q.bits, qv);
                    exp_uv2[li] = dequantize_scalar_f64(qv, q.min, q.max, q.bits, q.step)
                        .round()
                        .max(0.0) as u32;
                }
            }
            "iv2_tie" => {
                for (li, &val) in iv2_tie_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(val), q.min, q.max, q.bits, q.step);
                    let boff = wf.bit_offset + (li as u32) * u32::from(q.bits);
                    pack_bits_le(&mut oracle_payload, boff, q.bits, qv);
                }
                // Tie-rounding wire probe: q = (1, 2) on [-1.5, 1.5] 2-bit -> dequant = (-0.5, +0.5) -> (-1, +1)
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
                exp_qi64 = dequantize_scalar_f64(qv, q.min, q.max, q.bits, q.step).round() as i64;
            }
            "qu64" => {
                let qv = quantize_scalar_f64(qu64_in as f64, q.min, q.max, q.bits, q.step);
                pack_bits_le(&mut oracle_payload, wf.bit_offset, q.bits, qv);
                pack_bits_le(&mut oracle_tie_payload, wf.bit_offset, q.bits, qv);
                exp_qu64 = dequantize_scalar_f64(qv, q.min, q.max, q.bits, q.step)
                    .round()
                    .max(0.0) as u64;
            }
            other => panic!("unexpected field {other}"),
        }
    }
    assert_eq!(exp_iv2, [-3, 1]);
    assert_eq!(exp_iv3, [-7, 0, 9]);
    assert_eq!(exp_uv2, [5, 99]);
    assert_eq!(exp_qi64, -7);
    assert_eq!(exp_qu64, 42);

    let oracle_hex: String = oracle_payload
        .iter()
        .take(nc.packed_bytes as usize)
        .map(|b| format!("{b:02x}"))
        .collect();
    let tie_arr_c: String = oracle_tie_payload
        .iter()
        .map(|b| format!("0x{b:02X}u"))
        .collect::<Vec<_>>()
        .join(", ");
    let tie_arr_rs: String = oracle_tie_payload
        .iter()
        .map(|b| format!("0x{b:02X}"))
        .collect::<Vec<_>>()
        .join(", ");

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    // 1. C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`) encode + decode + tie-rounding
    let c_art = emit_c99(&mir).expect("emit_c99 ivec_quant_parity");
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
    let oracle_c_arr: String = oracle_payload[..nc.packed_bytes as usize]
        .iter()
        .map(|b| format!("0x{b:02X}u"))
        .collect::<Vec<_>>()
        .join(", ");

    let c_probe = format!(
        r#"
#include <stdio.h>
#include "{c_file}"

int main(void) {{
    {c_type} src;
    memset(&src, 0, sizeof(src));
    src.iv2 = strata_ivec2(-3, 1);
    src.iv3 = strata_ivec3(-7, 0, 9);
    src.uv2 = strata_uvec2(5u, 99u);
    src.iv2_tie = strata_ivec2(-1, 0);
    src.qi64 = -7;
    src.qu64 = 42ull;

    StrataNetPacket pkt;
    strata_net_encode_IntVecQuantNet(&src, 42ull, 1u, 0u, &pkt);
    const uint8_t exp_bytes[{pbytes}] = {{ {oracle_c_arr} }};
    if (memcmp(pkt.payload, exp_bytes, {pbytes}u) != 0) {{
        fprintf(stderr, "C99 TX payload mismatch\n");
        return 1;
    }}

    {c_type} dst;
    memset(&dst, 0, sizeof(dst));
    if (!strata_net_decode_IntVecQuantNet(&pkt, &dst)) {{
        return 2;
    }}
    if (dst.iv2.x != -3 || dst.iv2.y != 1) {{
        fprintf(stderr, "C99 iv2=(%d,%d)\n", dst.iv2.x, dst.iv2.y);
        return 3;
    }}
    if (dst.iv3.x != -7 || dst.iv3.y != 0 || dst.iv3.z != 9) {{
        fprintf(stderr, "C99 iv3=(%d,%d,%d)\n", dst.iv3.x, dst.iv3.y, dst.iv3.z);
        return 4;
    }}
    if (dst.uv2.x != 5u || dst.uv2.y != 99u) {{
        fprintf(stderr, "C99 uv2=(%u,%u)\n", dst.uv2.x, dst.uv2.y);
        return 5;
    }}
    if (dst.qi64 != -7 || dst.qu64 != 42ull) {{
        fprintf(stderr, "C99 i64/u64=(%lld,%llu)\n", (long long)dst.qi64, (unsigned long long)dst.qu64);
        return 6;
    }}

    StrataNetPacket tie_pkt = pkt;
    const uint8_t tie_bytes[128] = {{ {tie_arr_c} }};
    memcpy(tie_pkt.payload, tie_bytes, 128u);
    {c_type} tie_dst;
    memset(&tie_dst, 0, sizeof(tie_dst));
    if (!strata_net_decode_IntVecQuantNet(&tie_pkt, &tie_dst)) {{
        return 7;
    }}
    if (tie_dst.iv2_tie.x != -1 || tie_dst.iv2_tie.y != 1) {{
        fprintf(stderr, "C99 tie iv2_tie=(%d,%d) expected (-1,1)\n", tie_dst.iv2_tie.x, tie_dst.iv2_tie.y);
        return 8;
    }}
    return 0;
}}
"#,
        c_file = c_main.path,
        pbytes = nc.packed_bytes,
    );
    let c_probe_path = tmp.path().join("ivec_c99_parity.c");
    let c_bin = tmp.path().join("ivec_c99_parity");
    fs::write(&c_probe_path, c_probe).unwrap();
    let cc = find_c99_compiler();
    let c_comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&c_probe_path)
        .arg("-o")
        .arg(&c_bin)
        .arg("-lm")
        .output()
        .unwrap();
    assert!(
        c_comp.status.success(),
        "C99 ivec parity compile failed:\n{}",
        String::from_utf8_lossy(&c_comp.stderr)
    );
    let c_run = Command::new(&c_bin).output().unwrap();
    assert!(
        c_run.status.success(),
        "C99 ivec parity run failed ({:?}):\n{}",
        c_run.status.code(),
        String::from_utf8_lossy(&c_run.stderr)
    );

    // 2. Rust Guest encode + decode + tie-rounding
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_ivec_quant_test".to_owned(),
        },
    )
    .expect("emit_rust_guest ivec_quant_parity");
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
    let rg_dir = tmp.path().join("rg_ivec");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let rg_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use guest_ivec_quant_test::*;

#[test]
fn rust_guest_ivec_uvec_i64_u64_parity() {{
    let mut src = {rg_struct}::default();
    src.iv2 = [-3, 1];
    src.iv3 = [-7, 0, 9];
    src.uv2 = [5, 99];
    src.iv2_tie = [-1, 0];
    src.qi64 = -7;
    src.qu64 = 42;
    let pkt = strata_net_encode_IntVecQuantNet(&src, 42, 1, 0);
    let got_hex: String = pkt.payload[..{pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(got_hex, "{oracle_hex}");
    let mut dst = {rg_struct}::default();
    assert!(strata_net_decode_IntVecQuantNet(&pkt, &mut dst));
    assert_eq!(dst.iv2, [-3, 1]);
    assert_eq!(dst.iv3, [-7, 0, 9]);
    assert_eq!(dst.uv2, [5, 99]);
    assert_eq!(dst.qi64, -7);
    assert_eq!(dst.qu64, 42);

    let mut tie_pkt = pkt;
    tie_pkt.payload = [{tie_arr_rs}];
    let mut tie_dst = {rg_struct}::default();
    assert!(strata_net_decode_IntVecQuantNet(&tie_pkt, &mut tie_dst));
    assert_eq!(tie_dst.iv2_tie, [-1, 1]);
}}
"#,
        pbytes = nc.packed_bytes,
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/ivec_rg_e2e.rs"), rg_test).unwrap();
    write_offline_patch_config(&ws_root, &rg_dir);
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "ivec_rg_e2e", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        rg_out.status.success(),
        "RustGuest ivec parity failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rg_out.stdout),
        String::from_utf8_lossy(&rg_out.stderr)
    );

    // 3. Bevy Native encode + decode + tie-rounding
    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt")).unwrap();
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_ivec_quant_test".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native ivec_quant_parity");
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
    let bn_dir = tmp.path().join("bn_ivec");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use native_ivec_quant_test::*;

#[test]
fn bevy_native_ivec_uvec_i64_u64_parity() {{
    let mut src = {bn_struct}::default();
    src.iv2 = [-3, 1];
    src.iv3 = [-7, 0, 9];
    src.uv2 = [5, 99];
    src.iv2_tie = [-1, 0];
    src.qi64 = -7;
    src.qu64 = 42;
    let pkt = strata_net_encode_IntVecQuantNet(&src, 42, 1, 0);
    let got_hex: String = pkt.payload[..{pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(got_hex, "{oracle_hex}");
    let mut dst = {bn_struct}::default();
    assert!(strata_net_decode_IntVecQuantNet(&pkt, &mut dst));
    assert_eq!(dst.iv2, [-3, 1]);
    assert_eq!(dst.iv3, [-7, 0, 9]);
    assert_eq!(dst.uv2, [5, 99]);
    assert_eq!(dst.qi64, -7);
    assert_eq!(dst.qu64, 42);

    let mut tie_pkt = pkt;
    tie_pkt.payload = [{tie_arr_rs}];
    let mut tie_dst = {bn_struct}::default();
    assert!(strata_net_decode_IntVecQuantNet(&tie_pkt, &mut tie_dst));
    assert_eq!(tie_dst.iv2_tie, [-1, 1]);
}}
"#,
        pbytes = nc.packed_bytes,
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/ivec_bn_e2e.rs"), bn_test).unwrap();
    write_offline_patch_config(&ws_root, &bn_dir);
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "ivec_bn_e2e", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        bn_out.status.success(),
        "BevyNative ivec parity failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr)
    );
}

#[test]
fn three_backend_fix32_fix64_defaults_compile_match_q_values_and_roundtrip_wire() {
    let src = r#"
module game::fixed_defaults_net @version(1.0.0);

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
}

schedule FixedUpdate {}
"#;
    let sema = analyze_source("fixed_defaults_net.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let nc = mir
        .net_components
        .iter()
        .find(|c| c.name == "FixedDefaultsNet")
        .expect("FixedDefaultsNet net component");
    let pbytes = nc.packed_bytes as usize;

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

    // 1. C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`)
    let c_art = emit_c99(&mir).expect("emit_c99 fixed_defaults_net");
    for f in &c_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).unwrap();
    }
    let c_main = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let comp_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::fixed_defaults_net::FixedDefaultsNet")
        .expect("FixedDefaultsNet layout");
    let res_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::fixed_defaults_net::FixedNetRes")
        .expect("FixedNetRes layout");
    let c_type = format!("StrataType_{comp_idx}_FixedDefaultsNet");
    let c_def_fn = format!("strata_default_{comp_idx}_FixedDefaultsNet");
    let c_res_type = format!("StrataType_{res_idx}_FixedNetRes");
    let c_res_def_fn = format!("strata_default_{res_idx}_FixedNetRes");

    let c_probe = format!(
        r#"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "{c_file}"

int main(void) {{
    {c_type} def = {c_def_fn}();
    if (def.f32_frac != 98304 || def.f32_neg != -196608) {{
        fprintf(stderr, "C99 f32 defaults mismatch: %d %d\n", def.f32_frac, def.f32_neg);
        return 1;
    }}
    if (def.f64_frac != -9663676416ll || def.f64_int != (42ll << 32)) {{
        fprintf(stderr, "C99 f64 defaults mismatch: %lld %lld\n", (long long)def.f64_frac, (long long)def.f64_int);
        return 2;
    }}
    if (def.f32_min != INT32_MIN || def.f64_min != INT64_MIN) {{
        fprintf(stderr, "C99 min defaults mismatch\n");
        return 3;
    }}
    int32_t arr32[2];
    int64_t arr64[2];
    memcpy(arr32, def.arr32, sizeof(arr32));
    memcpy(arr64, def.arr64, sizeof(arr64));
    if (arr32[0] != 98304 || arr32[1] != -196608) {{
        fprintf(stderr, "C99 arr32 mismatch: %d %d\n", arr32[0], arr32[1]);
        return 4;
    }}
    if (arr64[0] != -9663676416ll || arr64[1] != (42ll << 32)) {{
        fprintf(stderr, "C99 arr64 mismatch: %lld %lld\n", (long long)arr64[0], (long long)arr64[1]);
        return 5;
    }}

    {c_res_type} rdef = {c_res_def_fn}();
    if (rdef.r32 != 98304 || rdef.r64 != -9663676416ll) {{
        fprintf(stderr, "C99 resource defaults mismatch\n");
        return 6;
    }}

    StrataNetPacket pkt;
    strata_net_encode_FixedDefaultsNet(&def, 77ull, 3u, 0u, &pkt);
    {c_type} decoded;
    memset(&decoded, 0, sizeof(decoded));
    if (!strata_net_decode_FixedDefaultsNet(&pkt, &decoded)) {{
        fprintf(stderr, "C99 decode failed\n");
        return 7;
    }}
    if (memcmp(&def, &decoded, sizeof(def)) != 0) {{
        fprintf(stderr, "C99 decode roundtrip mismatch\n");
        return 8;
    }}
    for (size_t i = 0u; i < {pbytes}u; ++i) {{
        printf("%02x", pkt.payload[i]);
    }}
    printf("\n");
    return 0;
}}
"#,
        c_file = c_main.path,
    );
    let c_probe_path = tmp.path().join("fixed_defaults_c99.c");
    let c_bin = tmp.path().join("fixed_defaults_c99");
    fs::write(&c_probe_path, c_probe).unwrap();
    let cc = find_c99_compiler();
    let c_comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&c_probe_path)
        .arg("-o")
        .arg(&c_bin)
        .arg("-lm")
        .output()
        .unwrap();
    assert!(
        c_comp.status.success(),
        "C99 fixed defaults compile failed:\n{}",
        String::from_utf8_lossy(&c_comp.stderr)
    );
    let c_run = Command::new(&c_bin).output().unwrap();
    assert!(
        c_run.status.success(),
        "C99 fixed defaults run failed ({:?}):\n{}",
        c_run.status.code(),
        String::from_utf8_lossy(&c_run.stderr)
    );
    let c99_hex = String::from_utf8_lossy(&c_run.stdout).trim().to_owned();
    assert_eq!(c99_hex.len(), pbytes * 2);

    // 2. Rust Guest
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_fixed_defaults_test".to_owned(),
        },
    )
    .expect("emit_rust_guest fixed_defaults_net");
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
    let rg_dir = tmp.path().join("rg_fixed_defaults");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let rg_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use guest_fixed_defaults_test::*;

#[test]
fn rust_guest_fixed_defaults_and_wire_parity() {{
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

    let pkt = strata_net_encode_FixedDefaultsNet(&def, 77, 3, 0);
    let got_hex: String = pkt.payload[..{pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(got_hex, "{c99_hex}");

    let mut decoded = {rg_struct}::default();
    decoded.f32_frac = 0;
    decoded.f32_neg = 0;
    decoded.f64_frac = 0;
    decoded.f64_int = 0;
    decoded.arr32 = [0, 0];
    decoded.arr64 = [0, 0];
    decoded.f32_min = 0;
    decoded.f64_min = 0;
    assert!(strata_net_decode_FixedDefaultsNet(&pkt, &mut decoded));
    assert_eq!(decoded, def);
}}
"#
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/fixed_defaults_rg.rs"), rg_test).unwrap();
    write_offline_patch_config(&ws_root, &rg_dir);
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "fixed_defaults_rg", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        rg_out.status.success(),
        "RustGuest fixed defaults parity failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rg_out.stdout),
        String::from_utf8_lossy(&rg_out.stderr)
    );

    // 3. Bevy Native
    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt")).unwrap();
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_fixed_defaults_test".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native fixed_defaults_net");
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
    let bn_dir = tmp.path().join("bn_fixed_defaults");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use native_fixed_defaults_test::*;

#[test]
fn bevy_native_fixed_defaults_and_wire_parity() {{
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

    let pkt = strata_net_encode_FixedDefaultsNet(&def, 77, 3, 0);
    let got_hex: String = pkt.payload[..{pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(got_hex, "{c99_hex}");

    let mut decoded = {bn_struct}::default();
    decoded.f32_frac = 0;
    decoded.f32_neg = 0;
    decoded.f64_frac = 0;
    decoded.f64_int = 0;
    decoded.arr32 = [0, 0];
    decoded.arr64 = [0, 0];
    decoded.f32_min = 0;
    decoded.f64_min = 0;
    assert!(strata_net_decode_FixedDefaultsNet(&pkt, &mut decoded));
    assert_eq!(decoded, def);
}}
"#
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/fixed_defaults_bn.rs"), bn_test).unwrap();
    write_offline_patch_config(&ws_root, &bn_dir);
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "fixed_defaults_bn", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        bn_out.status.success(),
        "BevyNative fixed defaults parity failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr)
    );
}

#[test]
fn three_backend_iteration5_nested_structs_2d_arrays_consts_spawns_and_precision_parity() {
    let src = r#"
module game::iter5_fix_parity @version(1.0.0);

const C_F32_FRAC: fix32 = 1.5;
const C_F32_NEG: fix32 = -3;
const C_F32_MIN: fix32 = -32768;
const C_F64_FRAC: fix64 = -2.25;
const C_F64_INT: fix64 = 42;
const C_F64_MIN: fix64 = -2147483648;

struct InnerDef {
    f32_d: fix32 = 1.5,
    f64_d: fix64 = -2.25,
}

struct InnerFix {
    a: fix32 = 1.5,
    arr32: [fix32; 2] = [1.5, -3],
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
component NestedFixNet {
    in_def: InnerFix,
    in_ov: InnerFix = InnerFix { a: -3, arr32: [2.5, -4] },
    arr_def: [InnerFix; 2],
    mat32: [[fix32; 2]; 2] = [[1.5, -3], [2.5, -4]],
    mat64: [[fix64; 2]; 2] = [[-2.25, 42], [0.3, -0.3]],
    def_wrap: InnerDef,
}

@net(reliable, channel = 2)
@authority(server)
resource NestedFixRes {
    arr_in: [InnerFix; 2],
    r_in: InnerFix,
    r_ov: InnerFix = InnerFix { a: 0.3 },
    f64_half: fix64 = -0.3,
    f32_third: fix32 = 0.3,
}

component ExtraFlag { active: bool = false }

fn helper_neg_third() -> fix64 {
    return -0.3;
}

fn helper_tup_check() -> i32 {
    let (t0, _t1): (i32, [fix32; 2]) = (7, [2.5, -4]);
    let a: fix32 = 1.5;
    let b: fix32 = -3;
    let c: fix64 = -0.3;
    let d: fix64 = 42;
    let arr: [fix64; 2] = [-1.25, 7];
    if a > b && c < d && arr[0] < arr[1] {
        return t0;
    }
    return 0;
}

sys spawn_and_insert_step() {
    let e_def = spawn { FixedDefaultsNet {} };
    let _e_ov = spawn {
        FixedDefaultsNet {
            f32_frac: 0.3,
            f32_neg: -99,
            f64_frac: -0.3,
            f64_int: 123,
            arr32: [2.5, -4],
            arr64: [-1.25, 7],
        }
    };
    let _e_part = spawn {
        NestedFixNet {
            def_wrap: InnerDef {},
            in_ov: InnerFix { a: 0.3 },
        }
    };
    insert(e_def, FixedDefaultsNet { f32_frac: 0.3 });
    spawn_batch(2) |i| {
        let mut x: fix32 = 1.5;
        if i == 1 {
            x = 0.3;
        }
        { FixedDefaultsNet { f32_frac: x, f64_frac: helper_neg_third() }, ExtraFlag { active: true } }
    };
}

sys fast_field_update(res: &mut res NestedFixRes) {
    for e in query(c: &mut FixedDefaultsNet).without<ExtraFlag>() {
        e.c.f32_neg = -99;
        e.c.f32_frac = 0.3;
        e.c.f64_frac = -0.3;
        e.c.f64_int = 123;
        e.c.arr32 = [2.5, -4];
        e.c.arr64 = [-1.25, 7];
    }
    res.r_ov.a = 0.3;
}

sys fallback_field_update() {
    for e in query(c: &mut FixedDefaultsNet, f: &ExtraFlag) {
        if e.f.active {
            e.c.f32_frac = 0.3;
            e.c.f32_neg = -99;
            e.c.f64_frac = -0.3;
            e.c.f64_int = 123;
            e.c.arr32 = [2.5, -4];
            if helper_tup_check() == 7 {
                let _s = spawn { ExtraFlag { active: false } };
            }
        }
    }
}

schedule Startup { spawn_and_insert_step }
schedule FixedUpdate { fast_field_update, fallback_field_update }
"#;
    let sema = analyze_source("iter5_fix_parity.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    strata_mir::verify_mir(&mir).expect("MIR verify");

    let nc_nested = mir
        .net_components
        .iter()
        .find(|c| c.name == "NestedFixNet")
        .expect("NestedFixNet");
    let nested_pbytes = nc_nested.packed_bytes as usize;
    let nc_res = mir
        .net_components
        .iter()
        .find(|c| c.name == "NestedFixRes")
        .expect("NestedFixRes");
    let res_pbytes = nc_res.packed_bytes as usize;

    let exp_f32_third: i32 = 19_661;
    let exp_f64_pos_third: i64 = 1_288_490_189;
    let exp_f64_neg_third: i64 = -1_288_490_189;

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    // 1. C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror` at `-O0` and `-O2`)
    let c_art = emit_c99(&mir).expect("emit_c99 iter5_fix_parity");
    for f in &c_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).unwrap();
    }
    let c_main = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let nested_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::iter5_fix_parity::NestedFixNet")
        .unwrap();
    let res_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::iter5_fix_parity::NestedFixRes")
        .unwrap();
    let inner_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::iter5_fix_parity::InnerFix")
        .unwrap();
    let c_inner_ty = format!("StrataType_{inner_idx}_InnerFix");
    let c_nested_ty = format!("StrataType_{nested_idx}_NestedFixNet");
    let c_nested_def = format!("strata_default_{nested_idx}_NestedFixNet");
    let c_res_ty = format!("StrataType_{res_idx}_NestedFixRes");
    let c_res_def = format!("strata_default_{res_idx}_NestedFixRes");

    let c_probe = format!(
        r#"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "{c_file}"

int main(void) {{
    StrataModState mod_state;
    memset(&mod_state, 0, sizeof(mod_state));
    if (strata_fn_helper_neg_third(&mod_state) != -1288490189ll || strata_fn_helper_tup_check(&mod_state) != 7) {{
        fprintf(stderr, "C99 helpers mismatch: %lld %d\n",
                (long long)strata_fn_helper_neg_third(&mod_state),
                strata_fn_helper_tup_check(&mod_state));
        return 3;
    }}

    {c_nested_ty} def = {c_nested_def}();
    if (def.in_def.a != 98304 || def.in_def.flag != 1) {{
        fprintf(stderr, "C99 in_def mismatch\n");
        return 4;
    }}
    int32_t in_ov_arr[2];
    memcpy(in_ov_arr, def.in_ov.arr32, sizeof(in_ov_arr));
    if (def.in_ov.a != -196608 || in_ov_arr[0] != 163840 || in_ov_arr[1] != -262144 || def.in_ov.flag != 1) {{
        fprintf(stderr, "C99 in_ov mismatch\n");
        return 5;
    }}
    {c_inner_ty} arr_def[2];
    memcpy(arr_def, def.arr_def, sizeof(arr_def));
    if (arr_def[0].a != 98304 || arr_def[1].flag != 1) {{
        fprintf(stderr, "C99 arr_def mismatch\n");
        return 6;
    }}
    int32_t mat32[2][2];
    memcpy(mat32, def.mat32, sizeof(mat32));
    if (mat32[0][0] != 98304 || mat32[1][1] != -262144) {{
        fprintf(stderr, "C99 mat32 mismatch\n");
        return 7;
    }}
    int64_t mat64[2][2];
    memcpy(mat64, def.mat64, sizeof(mat64));
    if (mat64[1][0] != 1288490189ll || mat64[1][1] != -1288490189ll) {{
        fprintf(stderr, "C99 mat64 mismatch: %lld %lld\n",
                (long long)mat64[1][0], (long long)mat64[1][1]);
        return 8;
    }}
    if (def.def_wrap.f32_d != 98304 || def.def_wrap.f64_d != -9663676416ll) {{
        fprintf(stderr, "C99 def_wrap mismatch\n");
        return 9;
    }}

    {c_res_ty} rdef = {c_res_def}();
    {c_inner_ty} res_arr[2];
    memcpy(res_arr, rdef.arr_in, sizeof(res_arr));
    if (res_arr[1].a != 98304 || rdef.r_in.a != 98304 || rdef.r_ov.a != 19661 || rdef.r_ov.flag != 1) {{
        fprintf(stderr, "C99 res nested mismatch\n");
        return 10;
    }}
    if (rdef.f64_half != -1288490189ll || rdef.f32_third != 19661) {{
        fprintf(stderr, "C99 res 0.3/-0.3 mismatch\n");
        return 11;
    }}

    StrataNetPacket npkt;
    memset(&npkt, 0, sizeof(npkt));
    strata_net_encode_NestedFixNet(&def, 10, 1, 0, &npkt);
    {c_nested_ty} ndec;
    memset(&ndec, 0, sizeof(ndec));
    if (!strata_net_decode_NestedFixNet(&npkt, &ndec) || memcmp(&ndec, &def, sizeof(def)) != 0) {{
        fprintf(stderr, "C99 NestedFixNet roundtrip mismatch\n");
        return 12;
    }}

    StrataNetPacket rpkt;
    memset(&rpkt, 0, sizeof(rpkt));
    strata_net_encode_NestedFixRes(&rdef, 11, 2, 0, &rpkt);
    {c_res_ty} rdec;
    memset(&rdec, 0, sizeof(rdec));
    if (!strata_net_decode_NestedFixRes(&rpkt, &rdec) || memcmp(&rdec, &rdef, sizeof(rdef)) != 0) {{
        fprintf(stderr, "C99 NestedFixRes roundtrip mismatch\n");
        return 13;
    }}

    for (size_t i = 0; i < {nested_pbytes}; ++i) printf("%02x", npkt.payload[i]);
    printf(" ");
    for (size_t i = 0; i < {res_pbytes}; ++i) printf("%02x", rpkt.payload[i]);
    printf("\n");
    return 0;
}}
"#,
        c_file = c_main.path,
    );
    let c_probe_path = tmp.path().join("c_probe_iter5.c");
    fs::write(&c_probe_path, c_probe).unwrap();

    let cc = find_c99_compiler();
    let mut c99_out_line = String::new();
    for opt in ["-O0", "-O2"] {
        let c_bin = tmp
            .path()
            .join(format!("c_probe_iter5_{}", opt.trim_start_matches('-')));
        let c_comp = Command::new(cc)
            .args([
                "-std=c99",
                opt,
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-I",
            ])
            .arg(tmp.path())
            .arg(&c_probe_path)
            .arg("-o")
            .arg(&c_bin)
            .arg("-lm")
            .output()
            .unwrap();
        assert!(
            c_comp.status.success(),
            "C99 iter5 compile ({opt}) failed:\n{}",
            String::from_utf8_lossy(&c_comp.stderr)
        );
        let c_run = Command::new(&c_bin).output().unwrap();
        assert!(
            c_run.status.success(),
            "C99 iter5 run ({opt}) failed ({:?}):\n{}",
            c_run.status.code(),
            String::from_utf8_lossy(&c_run.stderr)
        );
        let line = String::from_utf8_lossy(&c_run.stdout).trim().to_owned();
        if c99_out_line.is_empty() {
            c99_out_line = line;
        } else {
            assert_eq!(c99_out_line, line, "C99 -O0 vs -O2 wire mismatch");
        }
    }
    let mut c_hex_parts = c99_out_line.split_whitespace();
    let c99_nested_hex = c_hex_parts.next().unwrap().to_owned();
    let c99_res_hex = c_hex_parts.next().unwrap().to_owned();
    assert_eq!(c99_nested_hex.len(), nested_pbytes * 2);
    assert_eq!(c99_res_hex.len(), res_pbytes * 2);

    // 2. Rust Guest
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_iter5_parity_test".to_owned(),
        },
    )
    .expect("emit_rust_guest iter5_fix_parity");
    let rg_lib = &rg_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let rg_nested_struct = rg_lib
        .split("strata_net_encode_NestedFixNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_res_struct = rg_lib
        .split("strata_net_encode_NestedFixRes(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_dir = tmp.path().join("rg_iter5");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let rg_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use guest_iter5_parity_test::*;

#[test]
fn rust_guest_iter5_parity() {{
    assert_eq!(STRATA_CONST_C_F32_FRAC, 98_304);
    assert_eq!(STRATA_CONST_C_F32_NEG, -196_608);
    assert_eq!(STRATA_CONST_C_F32_MIN, i32::MIN);
    assert_eq!(STRATA_CONST_C_F64_FRAC, -9_663_676_416);
    assert_eq!(STRATA_CONST_C_F64_INT, 42i64 << 32);
    assert_eq!(STRATA_CONST_C_F64_MIN, i64::MIN);

    let def = {rg_nested_struct}::default();
    let rdef = {rg_res_struct}::default();
    assert_eq!(rdef.f64_half, {exp_f64_neg_third});
    assert_eq!(rdef.f32_third, {exp_f32_third});
    assert_eq!(def.mat64[1][0], {exp_f64_pos_third});
    assert_eq!(def.mat64[1][1], {exp_f64_neg_third});

    let pkt = strata_net_encode_NestedFixNet(&def, 10, 1, 0);
    let got_hex: String = pkt.payload[..{nested_pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(got_hex, "{c99_nested_hex}");
    let mut ndec = {rg_nested_struct}::default();
    assert!(strata_net_decode_NestedFixNet(&pkt, &mut ndec));
    assert_eq!(ndec, def);

    let rpkt = strata_net_encode_NestedFixRes(&rdef, 11, 2, 0);
    let got_rhex: String = rpkt.payload[..{res_pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(got_rhex, "{c99_res_hex}");
    let mut rdec = {rg_res_struct}::default();
    assert!(strata_net_decode_NestedFixRes(&rpkt, &mut rdec));
    assert_eq!(rdec, rdef);
}}
"#
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/iter5_rg.rs"), rg_test).unwrap();
    write_offline_patch_config(&ws_root, &rg_dir);
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "iter5_rg", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        rg_out.status.success(),
        "RustGuest iter5 parity failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rg_out.stdout),
        String::from_utf8_lossy(&rg_out.stderr)
    );

    // 3. Bevy Native (Defaults + Wire Parity + Live ECS Execution)
    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt")).unwrap();
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_iter5_parity_test".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native iter5_fix_parity");
    let bn_lib = &bn_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let bn_fixed_struct = bn_lib
        .split("strata_net_encode_FixedDefaultsNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_nested_struct = bn_lib
        .split("strata_net_encode_NestedFixNet(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_res_struct = bn_lib
        .split("strata_net_encode_NestedFixRes(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_inner_struct = bn_lib
        .split("pub struct ")
        .skip(1)
        .filter_map(|chunk| {
            chunk
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
        })
        .find(|n| n.contains("InnerFix"))
        .unwrap()
        .to_owned();
    let bn_extra_struct = bn_lib
        .split("pub struct ")
        .skip(1)
        .filter_map(|chunk| {
            chunk
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
        })
        .find(|n| n.contains("ExtraFlag"))
        .unwrap()
        .to_owned();
    let bn_dir = tmp.path().join("bn_iter5");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use bevy_app::{{App, FixedUpdate, Startup}};
use native_iter5_parity_test::*;

#[test]
fn bevy_native_iter5_parity_and_ecs_execution() {{
    assert_eq!(STRATA_CONST_C_F32_FRAC.0, 98_304);
    assert_eq!(STRATA_CONST_C_F32_NEG.0, -196_608);
    assert_eq!(STRATA_CONST_C_F32_MIN.0, i32::MIN);
    assert_eq!(STRATA_CONST_C_F64_FRAC.0, -9_663_676_416);
    assert_eq!(STRATA_CONST_C_F64_INT.0, 42i64 << 32);
    assert_eq!(STRATA_CONST_C_F64_MIN.0, i64::MIN);

    let def = {bn_nested_struct}::default();
    let rdef = {bn_res_struct}::default();
    assert_eq!(rdef.f64_half, {exp_f64_neg_third});
    assert_eq!(rdef.f32_third, {exp_f32_third});
    assert_eq!(def.mat64[1][0], {exp_f64_pos_third});
    assert_eq!(def.mat64[1][1], {exp_f64_neg_third});

    let pkt = strata_net_encode_NestedFixNet(&def, 10, 1, 0);
    let got_hex: String = pkt.payload[..{nested_pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(got_hex, "{c99_nested_hex}");
    let mut ndec = {bn_nested_struct}::default();
    assert!(strata_net_decode_NestedFixNet(&pkt, &mut ndec));
    assert_eq!(ndec, def);

    let rpkt = strata_net_encode_NestedFixRes(&rdef, 11, 2, 0);
    let got_rhex: String = rpkt.payload[..{res_pbytes}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(got_rhex, "{c99_res_hex}");
    let mut rdec = {bn_res_struct}::default();
    assert!(strata_net_decode_NestedFixRes(&rpkt, &mut rdec));
    assert_eq!(rdec, rdef);

    let mut app = App::new();
    app.add_plugins(StrataNativePlugin);
    // Run Startup: spawns e_def (+ insert), _e_ov, _e_part, and spawn_batch(2)
    app.world_mut().run_schedule(Startup);

    {{
        let mut q_pre = app.world_mut().query::<(&{bn_fixed_struct}, Option<&{bn_extra_struct}>)>();
        let pre_rows: Vec<_> = q_pre.iter(app.world()).collect();
        assert_eq!(pre_rows.len(), 4, "expected 4 FixedDefaultsNet entities after Startup");
        assert!(pre_rows.iter().any(|(c, ex)| ex.is_none() && c.f32_frac == {exp_f32_third} && c.f32_neg == -196_608));
        assert!(pre_rows.iter().any(|(c, ex)| ex.is_none() && c.f32_frac == {exp_f32_third} && c.f32_neg == -99 * 65536 && c.f64_frac == {exp_f64_neg_third} && c.arr64 == [-5_368_709_120, 7i64 << 32]));
        assert!(pre_rows.iter().any(|(c, ex)| ex.is_some() && c.f32_frac == 98_304 && c.f64_frac == {exp_f64_neg_third}));
        assert!(pre_rows.iter().any(|(c, ex)| ex.is_some() && c.f32_frac == {exp_f32_third} && c.f64_frac == {exp_f64_neg_third}));
    }}

    // Run FixedUpdate: fast_field_update & fallback_field_update mutate all 4 entities + res.r_ov.a
    app.world_mut().run_schedule(FixedUpdate);

    let mut q_fixed = app.world_mut().query::<(&{bn_fixed_struct}, Option<&{bn_extra_struct}>)>();
    let rows: Vec<_> = q_fixed.iter(app.world()).collect();
    assert_eq!(rows.len(), 4);
    for (c, extra) in &rows {{
        assert!(extra.is_none_or(|ex| ex.active.get()));
        assert_eq!(c.f32_frac, {exp_f32_third});
        assert_eq!(c.f32_neg, -99 * 65536);
        assert_eq!(c.f64_frac, {exp_f64_neg_third});
        assert_eq!(c.f64_int, 123i64 << 32);
        assert_eq!(c.arr32, [163_840, -262_144]);
    }}

    let mut q_nested = app.world_mut().query::<&{bn_nested_struct}>();
    let nested_rows: Vec<_> = q_nested.iter(app.world()).collect();
    assert!(!nested_rows.is_empty());
    let n0 = nested_rows[0];
    let ov_check = {bn_inner_struct}::default();
    assert!(ov_check.flag.get());
    assert_eq!(n0.in_ov[0], {exp_f32_third} as u32);
    assert_eq!(n0.in_ov[1], ov_check.arr32[0] as u32);
    assert_eq!(n0.in_ov[2], ov_check.arr32[1] as u32);
    assert_eq!(n0.in_ov[3] & 0xFF, 1);
    let res_after = app.world().resource::<{bn_res_struct}>();
    assert_eq!(res_after.r_ov[0], {exp_f32_third} as u32);
}}
"#
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/iter5_bn.rs"), bn_test).unwrap();
    write_offline_patch_config(&ws_root, &bn_dir);
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "iter5_bn", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        bn_out.status.success(),
        "BevyNative iter5 parity failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr)
    );
}

#[test]
fn phase3_r2_wraparound_quantized_fixed_and_rpc_typed_fields_three_backend_parity() {
    use strata_codegen::net::{dequantize_scalar_f64, pack_bits_le, quantize_scalar_f64};

    let src = r#"
module game::r6_parity @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
resource WrapRes {
    tick_val: u32 = 0,
}

@net(reliable, channel = 0)
@authority(server)
component QuantFix {
    @quantize(min = -10.0, max = 10.0, bits = 16)
    x: fix32 = 0.5,
    @quantize(min = -10.0, max = 10.0, bits = 16)
    y: fix64 = -2.25,
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
    let sema = analyze_source("r6_parity.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    strata_mir::verify_mir(&mir).expect("verify_mir");

    let qfix_nc = mir
        .net_components
        .iter()
        .find(|nc| nc.name == "QuantFix")
        .unwrap();
    let rpc = mir.rpcs.iter().find(|r| r.name == "TypedRpc").unwrap();

    // Oracle payload for QuantFix (x = 0.5 = 32768, y = -2.25 = -9663676416)
    let mut qfix_oracle = [0u8; 128];
    let mut exp_x_raw = 0i32;
    let mut exp_y_raw = 0i64;
    for wf in &qfix_nc.wire_fields {
        let q = wf.quantize.as_ref().unwrap();
        match wf.field_name.as_str() {
            "x" => {
                let qv = quantize_scalar_f64(0.5, q.min, q.max, q.bits, q.step);
                pack_bits_le(&mut qfix_oracle, wf.bit_offset, q.bits, qv);
                exp_x_raw = (dequantize_scalar_f64(qv, q.min, q.max, q.bits, q.step) * 65_536.0)
                    .round() as i32;
            }
            "y" => {
                let qv = quantize_scalar_f64(-2.25, q.min, q.max, q.bits, q.step);
                pack_bits_le(&mut qfix_oracle, wf.bit_offset, q.bits, qv);
                exp_y_raw = (dequantize_scalar_f64(qv, q.min, q.max, q.bits, q.step)
                    * 4_294_967_296.0)
                    .round() as i64;
            }
            other => panic!("unexpected QuantFix field {other}"),
        }
    }
    assert!((exp_x_raw - 32_768).abs() <= 20, "exp_x_raw={exp_x_raw}");
    assert!(
        (exp_y_raw - (-9_663_676_416i64)).abs() <= 2_000_000,
        "exp_y_raw={exp_y_raw}"
    );
    let qfix_oracle_hex: String = qfix_oracle[..qfix_nc.packed_bytes as usize]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Oracle payload for TypedRpc:
    // iv2 = [-3, 1], iv3 = [-2, -1, 2], uv2 = [1, 3], fx32 = 0.5 (32768), fx64 = -2.25 (-9663676416),
    // asset_h = uuid [1..=16] with kind=2 (UUID), asset_type=7
    let mut rpc_oracle = [0u8; 128];
    let mut rpc_tie_oracle = [0u8; 128];
    let iv2_in = [-3i32, 1i32];
    let iv3_in = [-2i32, -1i32, 2i32];
    let uv2_in = [1u32, 3u32];
    let asset_uuid: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut asset_bytes = [0u8; 32];
    asset_bytes[0] = 2; // KIND_UUID
    asset_bytes[4..8].copy_from_slice(&7u32.to_le_bytes()); // asset_type
    asset_bytes[16..32].copy_from_slice(&asset_uuid);

    for wf in &rpc.wire_fields {
        match wf.field_name.as_str() {
            "iv2" => {
                let q = wf.quantize.as_ref().unwrap();
                for (li, &v) in iv2_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    pack_bits_le(
                        &mut rpc_oracle,
                        wf.bit_offset + (li as u32) * u32::from(q.bits),
                        q.bits,
                        qv,
                    );
                }
                // Half-away-from-zero ties on [-7.5, 7.5] 4-bit (step = 1.0):
                // q=5 -> -2.5 -> -3, q=8 -> 0.5 -> 1
                pack_bits_le(&mut rpc_tie_oracle, wf.bit_offset, q.bits, 5);
                pack_bits_le(
                    &mut rpc_tie_oracle,
                    wf.bit_offset + u32::from(q.bits),
                    q.bits,
                    8,
                );
            }
            "iv3" => {
                let q = wf.quantize.as_ref().unwrap();
                for (li, &v) in iv3_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    pack_bits_le(
                        &mut rpc_oracle,
                        wf.bit_offset + (li as u32) * u32::from(q.bits),
                        q.bits,
                        qv,
                    );
                }
                // q=6 -> -1.5 -> -2, q=7 -> -0.5 -> -1, q=10 -> 2.5 -> 3
                pack_bits_le(&mut rpc_tie_oracle, wf.bit_offset, q.bits, 6);
                pack_bits_le(
                    &mut rpc_tie_oracle,
                    wf.bit_offset + u32::from(q.bits),
                    q.bits,
                    7,
                );
                pack_bits_le(
                    &mut rpc_tie_oracle,
                    wf.bit_offset + 2 * u32::from(q.bits),
                    q.bits,
                    10,
                );
            }
            "uv2" => {
                let q = wf.quantize.as_ref().unwrap();
                for (li, &v) in uv2_in.iter().enumerate() {
                    let qv = quantize_scalar_f64(f64::from(v), q.min, q.max, q.bits, q.step);
                    pack_bits_le(
                        &mut rpc_oracle,
                        wf.bit_offset + (li as u32) * u32::from(q.bits),
                        q.bits,
                        qv,
                    );
                }
                // On [0.5, 15.5] 4-bit (step = 1.0): q=0 -> 0.5 -> 1, q=2 -> 2.5 -> 3
                pack_bits_le(&mut rpc_tie_oracle, wf.bit_offset, q.bits, 0);
                pack_bits_le(
                    &mut rpc_tie_oracle,
                    wf.bit_offset + u32::from(q.bits),
                    q.bits,
                    2,
                );
            }
            "fx32" => {
                let q = wf.quantize.as_ref().unwrap();
                let qv = quantize_scalar_f64(0.5, q.min, q.max, q.bits, q.step);
                pack_bits_le(&mut rpc_oracle, wf.bit_offset, q.bits, qv);
                pack_bits_le(&mut rpc_tie_oracle, wf.bit_offset, q.bits, qv);
            }
            "fx64" => {
                let q = wf.quantize.as_ref().unwrap();
                let qv = quantize_scalar_f64(-2.25, q.min, q.max, q.bits, q.step);
                pack_bits_le(&mut rpc_oracle, wf.bit_offset, q.bits, qv);
                pack_bits_le(&mut rpc_tie_oracle, wf.bit_offset, q.bits, qv);
            }
            "asset_h" => {
                for (bi, &byte) in asset_bytes.iter().enumerate() {
                    pack_bits_le(
                        &mut rpc_oracle,
                        wf.bit_offset + (bi as u32) * 8,
                        8,
                        u64::from(byte),
                    );
                    pack_bits_le(
                        &mut rpc_tie_oracle,
                        wf.bit_offset + (bi as u32) * 8,
                        8,
                        u64::from(byte),
                    );
                }
            }
            other => panic!("unexpected TypedRpc field {other}"),
        }
    }
    let rpc_oracle_hex: String = rpc_oracle[..rpc.packed_bytes as usize]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let tie_c_bytes: String = rpc_tie_oracle
        .iter()
        .map(|b| format!("0x{b:02X}u"))
        .collect::<Vec<_>>()
        .join(", ");
    let tie_rs_bytes: String = rpc_tie_oracle
        .iter()
        .map(|b| format!("0x{b:02X}"))
        .collect::<Vec<_>>()
        .join(", ");

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let target_dir = ws_root.join("target").join("strata_generated_cache");

    // 1. C99 (-O0 and -O2, -std=c99 -Wall -Wextra -Wpedantic -Werror)
    let c_art = emit_c99(&mir).expect("emit_c99 r6_parity");
    let c_src = &c_art.files[1].content;
    assert!(c_src.contains("bam_ticks_is_changed(&ticks)"));
    assert!(c_src.contains("StrataIVec2 iv2;"));
    assert!(c_src.contains("StrataIVec3 iv3;"));
    assert!(c_src.contains("StrataUVec2 uv2;"));
    assert!(c_src.contains("BamAssetHandle asset_h;"));

    let qfix_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::r6_parity::QuantFix")
        .unwrap();
    let qfix_cty = format!("StrataType_{qfix_idx}_QuantFix");
    let wrap_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name == "game::r6_parity::WrapRes")
        .unwrap();
    let wrap_cty = format!("StrataType_{wrap_idx}_WrapRes");
    let wrap_fp = mir.layouts[wrap_idx].schema_fingerprint;
    let qfix_fp = mir.layouts[qfix_idx].schema_fingerprint;

    let c_dir = tmp.path().join("c99_r6");
    fs::create_dir_all(&c_dir).unwrap();
    for f in &c_art.files {
        fs::write(c_dir.join(&f.path), &f.content).unwrap();
    }
    let c_harness = format!(
        r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "r6_parity.c"

static void fail_if(int cond, const char* msg) {{
    if (cond) {{ fprintf(stderr, "FAIL: %s\n", msg); exit(1); }}
}}

static BamComponent g_wrap = 1u, g_qfix = 2u, g_net = 3u;
static {wrap_cty} g_wrap_val = {{ 99u }};
static BamChangeTicks g_wrap_ticks = {{ 1u, 0u, 0xFFFFFFFEu, 1u }};
static StrataNetPacket g_tx[8];
static size_t g_tx_n = 0u;
static BamSystemFn g_tx_fn = NULL;
static void* g_tx_ud = NULL;
typedef struct MockIter {{ int dummy; }} MockIter;
static MockIter g_msg_it = {{ 0 }};

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_res(const BamHostCtx* h, const char* n, const BamComponentUuid* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "strata::net::StrataNetPacket") == 0) {{ *o = g_net; return BAM_RESULT_OK; }}
    if (strcmp(n, "game::r6_parity::WrapRes") == 0) {{ *o = g_wrap; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_c(BamLoadCtx* l, const BamComponentDesc* d, BamComponent* o) {{
    (void)l;
    if (strcmp(d->name, "game::r6_parity::QuantFix") == 0) *o = g_qfix;
    else *o = 10u;
    return BAM_RESULT_OK;
}}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h;
    memset(o, 0, sizeof(*o));
    o->struct_size = (uint32_t)sizeof(*o);
    if (c == g_net) {{
        o->flags = BAM_STORAGE_FLAG_MESSAGE;
        o->size = sizeof(StrataNetPacket);
        o->align = 8u;
        o->schema_fingerprint = STRATA_NET_PACKET_SCHEMA_FINGERPRINT;
        return BAM_RESULT_OK;
    }}
    if (c == g_wrap) {{ o->flags = BAM_STORAGE_FLAG_RESOURCE; o->schema_fingerprint = 0x{wrap_fp:016X}ull; return BAM_RESULT_OK; }}
    if (c == g_qfix) {{ o->schema_fingerprint = 0x{qfix_fp:016X}ull; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_s(BamLoadCtx* l, const BamSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "__strata_net_tx_0") == 0) {{ g_tx_fn = d->callback; g_tx_ud = d->user_data; }}
    if (o) *o = 1u;
    return BAM_RESULT_OK;
}}
static BamResult m_mnt(BamLoadCtx* l, BamSystem s, BamScheduleId sc, BamSystemSet ss) {{ (void)l; (void)s; (void)sc; (void)ss; return BAM_RESULT_OK; }}
static BamResult m_sq(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc;
    if (qi == 0u) {{ *o = (BamIter*)&g_msg_it; return BAM_RESULT_OK; }}
    *o = NULL; return BAM_RESULT_NOT_FOUND;
}}
static const uint8_t* m_res_ptr(const BamSystemCtx* sc, BamComponent c, BamChangeTicks* t) {{
    (void)sc;
    if (c == g_wrap) {{ if (t) *t = g_wrap_ticks; return (const uint8_t*)&g_wrap_val; }}
    return NULL;
}}
static BamResult m_it_rst(BamIter* i) {{ (void)i; return BAM_RESULT_OK; }}
static BamBool m_it_next(BamIter* i, size_t* l) {{ (void)i; *l = 0u; return BAM_FALSE; }}
static const BamEntity* m_it_ents(const BamIter* i) {{ (void)i; return NULL; }}
static const uint8_t* m_it_col_ro(const BamIter* i, size_t ti) {{ (void)i; (void)ti; return NULL; }}
static uint8_t* m_it_col_mut(BamIter* i, size_t ti) {{ (void)i; (void)ti; return NULL; }}
static BamResult m_msg_rb(BamIter* i, size_t ti, uint8_t* b, size_t m, size_t* out_r) {{
    (void)i; (void)ti; (void)b; (void)m; *out_r = 0u; return BAM_RESULT_OK;
}}
static BamResult m_msg_wb(BamIter* i, size_t ti, const uint8_t* b, size_t c) {{
    (void)i; (void)ti;
    if (c > 0u) {{ memcpy(&g_tx[g_tx_n], b, c * sizeof(StrataNetPacket)); g_tx_n += c; }}
    return BAM_RESULT_OK;
}}

int main(void) {{
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.load_host_ctx = m_hc;
    api.resolve_component = m_res;
    api.register_component = m_reg_c;
    api.component_layout_info = m_linfo;
    api.register_system_handle = m_reg_s;
    api.mount_system_in_schedule = m_mnt;
    api.sys_query = m_sq;
    api.sys_res_ptr = m_res_ptr;
    api.iter_reset = m_it_rst;
    api.iter_next_chunk = m_it_next;
    api.iter_entities = m_it_ents;
    api.iter_column_readonly = m_it_col_ro;
    api.iter_column_mutable_untracked = m_it_col_mut;
    api.msg_read_batch = m_msg_rb;
    api.msg_write_batch = m_msg_wb;

    int ctx = 1;
    BamInstance* inst = NULL;
    fail_if(bamabi_init(&api, (BamLoadCtx*)&ctx, &inst) != BAM_RESULT_OK, "init failed");

    /* Bug 1 wraparound: changed=0, last_run=0xFFFFFFFE, this_run=1 -> 1 packet */
    g_tx_n = 0u;
    fail_if(g_tx_fn((BamSystemCtx*)&ctx, g_tx_ud) != BAM_RESULT_OK, "tx wrap A");
    fail_if(g_tx_n != 1u, "expected 1 packet on changed=0 wraparound");

    /* Bug 1 wraparound: changed=0xFFFFFFFE, last_run=0, this_run=1 -> 0 packets */
    g_wrap_ticks.changed = 0xFFFFFFFEu;
    g_wrap_ticks.last_run = 0u;
    g_wrap_ticks.this_run = 1u;
    g_tx_n = 0u;
    fail_if(g_tx_fn((BamSystemCtx*)&ctx, g_tx_ud) != BAM_RESULT_OK, "tx wrap B");
    fail_if(g_tx_n != 0u, "expected 0 packets on old change with last_run=0");

    /* Bug 2: quantized fix32/fix64 */
    {qfix_cty} qin = strata_default_{qfix_idx}_QuantFix();
    {qfix_cty} qout;
    memset(&qout, 0, sizeof(qout));
    StrataNetPacket qpkt;
    strata_net_encode_QuantFix(&qin, 11ull, 2u, 0u, &qpkt);
    fail_if(!strata_net_decode_QuantFix(&qpkt, &qout), "QuantFix decode failed");
    fail_if(qout.x != {exp_x_raw}, "QuantFix x mismatch");
    fail_if(qout.y != {exp_y_raw}ll, "QuantFix y mismatch");

    /* Bug 3: rpc with ivec2/ivec3/uvec2/fix32/fix64/Asset<u32> */
    StrataRpc_TypedRpc rin, rout;
    memset(&rin, 0, sizeof(rin));
    memset(&rout, 0, sizeof(rout));
    rin.iv2 = strata_ivec2(-3, 1);
    rin.iv3 = strata_ivec3(-2, -1, 2);
    rin.uv2 = strata_uvec2(1u, 3u);
    rin.fx32 = 32768;
    rin.fx64 = -9663676416ll;
    BamComponentUuid uuid_val = {{ {{ 1u,2u,3u,4u,5u,6u,7u,8u,9u,10u,11u,12u,13u,14u,15u,16u }} }};
    rin.asset_h = bam_asset_handle_from_uuid(7u, uuid_val);
    StrataNetPacket rpkt;
    strata_net_encode_rpc_TypedRpc(&rin, 5u, 1u, &rpkt);
    fail_if(!strata_net_decode_rpc_TypedRpc(&rpkt, &rout), "TypedRpc decode failed");
    fail_if(rout.iv2.x != -3 || rout.iv2.y != 2, "TypedRpc iv2 mismatch");
    fail_if(rout.iv3.x != -2 || rout.iv3.y != -1 || rout.iv3.z != 3, "TypedRpc iv3 mismatch");
    fail_if(rout.uv2.x != 2u || rout.uv2.y != 4u, "TypedRpc uv2 mismatch");
    fail_if(rout.fx32 != {exp_x_raw} || rout.fx64 != {exp_y_raw}ll, "TypedRpc fix mismatch");
    fail_if(memcmp(&rout.asset_h, &rin.asset_h, sizeof(BamAssetHandle)) != 0, "TypedRpc asset_h mismatch");

    /* Tie rounding on rpc ivec2/ivec3/uvec2 */
    StrataNetPacket tie_pkt = rpkt;
    uint8_t tie_pl[128] = {{ {tie_c_bytes} }};
    memcpy(tie_pkt.payload, tie_pl, 128u);
    StrataRpc_TypedRpc tie_out;
    memset(&tie_out, 0, sizeof(tie_out));
    fail_if(!strata_net_decode_rpc_TypedRpc(&tie_pkt, &tie_out), "TypedRpc tie decode failed");
    fail_if(tie_out.iv2.x != -3 || tie_out.iv2.y != 1, "TypedRpc tie iv2 mismatch");
    fail_if(tie_out.iv3.x != -2 || tie_out.iv3.y != -1 || tie_out.iv3.z != 3, "TypedRpc tie iv3 mismatch");
    fail_if(tie_out.uv2.x != 1u || tie_out.uv2.y != 3u, "TypedRpc tie uv2 mismatch");

    for (size_t i = 0u; i < {qfix_pb}u; ++i) printf("%02x", qpkt.payload[i]);
    printf(" ");
    for (size_t i = 0u; i < {rpc_pb}u; ++i) printf("%02x", rpkt.payload[i]);
    printf("\n");

    bamabi_shutdown(inst);
    return 0;
}}
"#,
        qfix_pb = qfix_nc.packed_bytes,
        rpc_pb = rpc.packed_bytes,
    );
    let c_hpath = c_dir.join("r6_harness.c");
    fs::write(&c_hpath, &c_harness).unwrap();
    let cc = find_c99_compiler();
    for opt in ["-O0", "-O2"] {
        let exe = c_dir.join(format!("r6_harness_{opt}"));
        let comp = Command::new(cc)
            .args([
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                opt,
                "-I",
            ])
            .arg(&c_dir)
            .arg(&c_hpath)
            .arg("-o")
            .arg(&exe)
            .output()
            .expect("compile c99 r6 harness");
        assert!(
            comp.status.success(),
            "C99 {opt} compile failed:\n{}",
            String::from_utf8_lossy(&comp.stderr)
        );
        let run = Command::new(&exe).output().expect("run c99 r6 harness");
        assert!(
            run.status.success(),
            "C99 {opt} run failed:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
        let out_s = String::from_utf8_lossy(&run.stdout);
        let parts: Vec<&str> = out_s.split_whitespace().collect();
        assert_eq!(parts.len(), 2, "unexpected C99 output: {out_s}");
        assert_eq!(parts[0], qfix_oracle_hex, "C99 {opt} QuantFix hex mismatch");
        assert_eq!(parts[1], rpc_oracle_hex, "C99 {opt} TypedRpc hex mismatch");
    }

    // 2. Rust Guest (#![forbid(unsafe_code)] #![deny(warnings)])
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_r6_parity".to_owned(),
        },
    )
    .expect("emit_rust_guest r6_parity");
    let rg_lib = &rg_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let rg_qfix_struct = rg_lib
        .split("strata_net_encode_QuantFix(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let rg_dir = tmp.path().join("rg_r6");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let rg_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use bamabi_sys::{{BamComponent, ComponentUuid, FfiAssetHandle}};
use guest_r6_parity::*;

#[test]
fn rust_guest_r6_parity() {{
    let qin = {rg_qfix_struct}::default();
    assert_eq!(qin.x, 32_768);
    assert_eq!(qin.y, -9_663_676_416);
    let qpkt = strata_net_encode_QuantFix(&qin, 11, 2, 0);
    let qhex: String = qpkt.payload[..{qfix_pb}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(qhex, "{qfix_oracle_hex}");
    let mut qout = {rg_qfix_struct}::default();
    qout.x = 0;
    qout.y = 0;
    assert!(strata_net_decode_QuantFix(&qpkt, &mut qout));
    assert_eq!(qout.x, {exp_x_raw});
    assert_eq!(qout.y, {exp_y_raw});

    let rin = StrataRpc_TypedRpc {{
        iv2: [-3, 1],
        iv3: [-2, -1, 2],
        uv2: [1, 3],
        fx32: 32_768,
        fx64: -9_663_676_416,
        asset_h: FfiAssetHandle::from_uuid(
            BamComponent::from_raw(7),
            ComponentUuid::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        ),
    }};
    let rpkt = strata_net_encode_rpc_TypedRpc(&rin, 5, 1);
    let rhex: String = rpkt.payload[..{rpc_pb}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(rhex, "{rpc_oracle_hex}");
    let mut rout = StrataRpc_TypedRpc::default();
    assert!(strata_net_decode_rpc_TypedRpc(&rpkt, &mut rout));
    assert_eq!(rout.iv2, [-3, 2]);
    assert_eq!(rout.iv3, [-2, -1, 3]);
    assert_eq!(rout.uv2, [2, 4]);
    assert_eq!(rout.fx32, {exp_x_raw});
    assert_eq!(rout.fx64, {exp_y_raw});
    assert_eq!(rout.asset_h, rin.asset_h);

    let mut tie_pkt = rpkt;
    tie_pkt.payload = [{tie_rs_bytes}];
    let mut tie_out = StrataRpc_TypedRpc::default();
    assert!(strata_net_decode_rpc_TypedRpc(&tie_pkt, &mut tie_out));
    assert_eq!(tie_out.iv2, [-3, 1]);
    assert_eq!(tie_out.iv3, [-2, -1, 3]);
    assert_eq!(tie_out.uv2, [1, 3]);
}}
"#,
        qfix_pb = qfix_nc.packed_bytes,
        rpc_pb = rpc.packed_bytes,
    );
    fs::create_dir_all(rg_dir.join("tests")).unwrap();
    fs::write(rg_dir.join("tests/rg_r6.rs"), rg_test).unwrap();
    write_offline_patch_config(&ws_root, &rg_dir);
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "rg_r6", "--manifest-path"])
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        rg_out.status.success(),
        "RustGuest r6 parity failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rg_out.stdout),
        String::from_utf8_lossy(&rg_out.stderr)
    );

    // 3. Bevy Native (#![forbid(unsafe_code)] #![deny(warnings)] + live ECS)
    let native_rt_abs = ws_root.join("crates").join("bamabi_native_rt");
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_r6_parity".to_owned(),
            native_rt_path: Some(native_rt_abs.display().to_string()),
            static_console: true,
        },
    )
    .expect("emit_bevy_native r6_parity");
    let bn_lib = &bn_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    let bn_qfix_struct = bn_lib
        .split("strata_net_encode_QuantFix(src: &")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap()
        .trim()
        .to_owned();
    let bn_dir = tmp.path().join("bn_r6");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_test = format!(
        r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use bamabi_sys::{{BamComponent, ComponentUuid, FfiAssetHandle}};
use bevy_app::{{App, FixedUpdate}};
use native_r6_parity::*;

#[test]
fn bevy_native_r6_parity() {{
    let mut app = App::new();
    app.add_plugins(StrataNativePlugin);
    app.world_mut().run_schedule(FixedUpdate);

    let qin = {bn_qfix_struct}::default();
    assert_eq!(qin.x, 32_768);
    assert_eq!(qin.y, -9_663_676_416);
    let qpkt = strata_net_encode_QuantFix(&qin, 11, 2, 0);
    let qhex: String = qpkt.payload[..{qfix_pb}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(qhex, "{qfix_oracle_hex}");
    let mut qout = {bn_qfix_struct}::default();
    qout.x = 0;
    qout.y = 0;
    assert!(strata_net_decode_QuantFix(&qpkt, &mut qout));
    assert_eq!(qout.x, {exp_x_raw});
    assert_eq!(qout.y, {exp_y_raw});

    let rin = StrataRpc_TypedRpc {{
        iv2: [-3, 1],
        iv3: [-2, -1, 2],
        uv2: [1, 3],
        fx32: 32_768,
        fx64: -9_663_676_416,
        asset_h: FfiAssetHandle::from_uuid(
            BamComponent::from_raw(7),
            ComponentUuid::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        ),
    }};
    let rpkt = strata_net_encode_rpc_TypedRpc(&rin, 5, 1);
    let rhex: String = rpkt.payload[..{rpc_pb}].iter().map(|b| format!("{{b:02x}}")).collect();
    assert_eq!(rhex, "{rpc_oracle_hex}");
    let mut rout = StrataRpc_TypedRpc::default();
    assert!(strata_net_decode_rpc_TypedRpc(&rpkt, &mut rout));
    assert_eq!(rout.iv2, [-3, 2]);
    assert_eq!(rout.iv3, [-2, -1, 3]);
    assert_eq!(rout.uv2, [2, 4]);
    assert_eq!(rout.fx32, {exp_x_raw});
    assert_eq!(rout.fx64, {exp_y_raw});
    assert_eq!(rout.asset_h, rin.asset_h);

    let mut tie_pkt = rpkt;
    tie_pkt.payload = [{tie_rs_bytes}];
    let mut tie_out = StrataRpc_TypedRpc::default();
    assert!(strata_net_decode_rpc_TypedRpc(&tie_pkt, &mut tie_out));
    assert_eq!(tie_out.iv2, [-3, 1]);
    assert_eq!(tie_out.iv3, [-2, -1, 3]);
    assert_eq!(tie_out.uv2, [1, 3]);
}}
"#,
        qfix_pb = qfix_nc.packed_bytes,
        rpc_pb = rpc.packed_bytes,
    );
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/bn_r6.rs"), bn_test).unwrap();
    write_offline_patch_config(&ws_root, &bn_dir);
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "bn_r6", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        bn_out.status.success(),
        "BevyNative r6 parity failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr)
    );
}

#[test]
fn net_rx_before_tx_without_user_fixed_systems_all_targets_and_live_bevy_native() {
    let src = r#"
module game::no_fixed_user @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
component Actor {
    @quantize(min = -100.0, max = 100.0, bits = 16)
    x: f32 = 9.0,
}

object Hero {
    Actor { x: 9.0 },
}
"#;
    let sema = analyze_source("no_fixed_user.strata", src);
    assert!(sema.ok(), "{:#?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);

    // 1. C99 codegen: emits before_weak("__strata_net_tx_0") and after_weak("__strata_net_rx_0")
    let c99_art = emit_c99(&mir).expect("emit_c99");
    let c99_src = &c99_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .content;
    assert!(
        c99_src.contains("\"__strata_net_tx_0\""),
        "C99 RX must reference __strata_net_tx_0 even with 0 user FixedUpdate systems"
    );
    assert!(
        c99_src.contains("\"__strata_net_rx_0\""),
        "C99 TX must reference __strata_net_rx_0 even with 0 user FixedUpdate systems"
    );

    // 2. Rust Guest codegen: emits .before_weak(c"__strata_net_tx_0") and .after_weak(c"__strata_net_rx_0")
    let rg_art = emit_rust_guest(&mir).expect("emit_rust_guest");
    let rg_lib = &rg_art
        .files
        .iter()
        .find(|f| f.path == "src/lib.rs")
        .unwrap()
        .content;
    assert!(
        rg_lib.contains(".before_weak(c\"__strata_net_tx_0\")"),
        "RustGuest RX must emit .before_weak(__strata_net_tx_0)"
    );
    assert!(
        rg_lib.contains(".after_weak(c\"__strata_net_rx_0\")"),
        "RustGuest TX must emit .after_weak(__strata_net_rx_0)"
    );

    // 3. Bevy Native codegen + live execution: tick 1 emits 1 TX packet, ticks 2 and 3 emit 0
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let target_dir = ws_root.join("target").join("strata_generated_cache");
    let native_rt_abs = fs::canonicalize(ws_root.join("crates/bamabi_native_rt")).unwrap();
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_no_user_fixed".to_owned(),
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
    assert!(
        bn_lib.contains("StrataLeafSet_strata_net_rx.before(StrataLeafSet_strata_net_tx)"),
        "BevyNative must unconditionally order StrataLeafSet_strata_net_rx before StrataLeafSet_strata_net_tx"
    );

    let tmp = TempDir::new().unwrap();
    let bn_dir = tmp.path().join("bn_no_user");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, &f.content).unwrap();
    }
    let bn_test = r#"#![forbid(unsafe_code)]
#![deny(warnings)]
use bamabi_native_rt::StrataNetPacket;
use bevy_app::{App, FixedUpdate, Startup};
use bevy_ecs::message::{MessageCursor, Messages};
use native_no_user_fixed::*;

#[test]
fn live_no_user_fixed_update_emits_once_without_loopback() {
    let mut app = App::new();
    app.add_plugins(StrataNativePlugin);
    app.world_mut().run_schedule(Startup);

    let mut cur: MessageCursor<StrataNetPacket> = MessageCursor::default();

    // Tick 1: Startup-spawned Actor is Added/Changed -> RX runs BEFORE TX (sees 0), TX emits 1 packet.
    app.world_mut().run_schedule(FixedUpdate);
    let t1_pkts: usize = cur
        .read(app.world().resource::<Messages<StrataNetPacket>>())
        .count();
    assert_eq!(t1_pkts, 1, "tick 1 must emit exactly 1 TX packet");

    // Host drains/clears outbound TX queue between ticks; ticks 2 and 3 must emit 0 packets.
    app.world_mut().resource_mut::<Messages<StrataNetPacket>>().clear();
    app.world_mut().run_schedule(FixedUpdate);
    let t2_pkts: usize = cur
        .read(app.world().resource::<Messages<StrataNetPacket>>())
        .count();
    assert_eq!(t2_pkts, 0, "tick 2 must emit 0 TX packets");

    app.world_mut().resource_mut::<Messages<StrataNetPacket>>().clear();
    app.world_mut().run_schedule(FixedUpdate);
    let t3_pkts: usize = cur
        .read(app.world().resource::<Messages<StrataNetPacket>>())
        .count();
    assert_eq!(t3_pkts, 0, "tick 3 must emit 0 TX packets");
}
"#;
    fs::create_dir_all(bn_dir.join("tests")).unwrap();
    fs::write(bn_dir.join("tests/bn_no_user.rs"), bn_test).unwrap();
    write_offline_patch_config(&ws_root, &bn_dir);
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .args(["--test", "bn_no_user", "--manifest-path"])
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .unwrap()
    };
    assert!(
        bn_out.status.success(),
        "BevyNative no-user-FixedUpdate test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr)
    );
}

#[test]
fn c99_net_rx_drains_130_packets_without_batch_drop() {
    let src = r#"
module game::c99_130 @version(1.0.0);

@net(reliable, channel = 0)
@authority(server)
component Dot {
    v: u32 = 0,
}
"#;
    let sema = analyze_source("c99_130.strata", src);
    assert!(sema.ok(), "{:#?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit_c99(&mir).expect("emit_c99");
    let c_name = art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .path
        .clone();

    let tmp = TempDir::new().unwrap();
    for f in &art.files {
        fs::write(tmp.path().join(&f.path), &f.content).unwrap();
    }
    let dot_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name.ends_with("Dot"))
        .unwrap();
    let fp = mir.layouts[dot_idx].schema_fingerprint;
    let mod_c_struct = format!("StrataType_{dot_idx}_Dot");

    let harness = format!(
        r#"
#include <stdio.h>
#include <string.h>
#include "{c_name}"

#define N_ENTS 130u
static BamComponent g_net = 90u, g_dot = 10u;
static BamResult (*g_rx_fn)(BamSystemCtx*, void*) = NULL;
static void* g_rx_ud = NULL;
static int g_rx_bw_tx = 0;
static BamEntity g_ents[N_ENTS];
static {mod_c_struct} g_cols[N_ENTS];
static StrataNetPacket g_in_pkts[N_ENTS];
static size_t g_in_cur = 0u;
static int g_msg_it = 0, g_q_it = 0, g_q_step = 0;

static const BamHostCtx* m_hc(const BamLoadCtx* l) {{ return (const BamHostCtx*)l; }}
static BamResult m_res(const BamHostCtx* h, const char* n, const BamComponentUuid* u, BamComponent* o) {{
    (void)h; (void)u;
    if (strcmp(n, "strata::net::StrataNetPacket") == 0) {{ *o = g_net; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_c(BamLoadCtx* l, const BamComponentDesc* d, BamComponent* o) {{
    (void)l; (void)d; *o = g_dot; return BAM_RESULT_OK;
}}
static BamResult m_linfo(const BamHostCtx* h, BamComponent c, BamLayoutInfo* o) {{
    (void)h; memset(o, 0, sizeof(*o)); o->struct_size = (uint32_t)sizeof(*o);
    if (c == g_net) {{
        o->flags = BAM_STORAGE_FLAG_MESSAGE; o->size = sizeof(StrataNetPacket);
        o->align = 8u; o->schema_fingerprint = STRATA_NET_PACKET_SCHEMA_FINGERPRINT;
        return BAM_RESULT_OK;
    }}
    if (c == g_dot) {{ o->size = sizeof({mod_c_struct}); o->align = 4u; o->schema_fingerprint = 0x{fp:016X}ull; return BAM_RESULT_OK; }}
    return BAM_RESULT_NOT_FOUND;
}}
static BamResult m_reg_s(BamLoadCtx* l, const BamSystemDesc* d, BamSystem* o) {{
    (void)l;
    if (strcmp(d->name, "__strata_net_rx_0") == 0) {{
        g_rx_fn = d->callback; g_rx_ud = d->user_data;
        for (size_t i = 0u; i < d->before_weak_count; ++i) {{
            if (strcmp(d->before_weak[i], "__strata_net_tx_0") == 0) g_rx_bw_tx = 1;
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
        g_ents[i] = (BamEntity)(1000ull + i);
        g_cols[i].v = 0u;
        {mod_c_struct} tmp; tmp.v = i + 1u;
        strata_net_encode_Dot(&tmp, g_ents[i], 1u, 0u, &g_in_pkts[i]);
    }}
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.load_host_ctx = m_hc;
    api.resolve_component = m_res;
    api.register_component = m_reg_c;
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

    int ctx = 1;
    BamInstance* inst = NULL;
    if (bamabi_init(&api, (BamLoadCtx*)&ctx, &inst) != BAM_RESULT_OK) return 1;
    if (!g_rx_bw_tx) return 2;
    if (g_rx_fn((BamSystemCtx*)&ctx, g_rx_ud) != BAM_RESULT_OK) return 3;
    for (uint32_t i = 0u; i < N_ENTS; ++i) {{
        if (g_cols[i].v != i + 1u) {{
            fprintf(stderr, "entity %u mismatch: got %u expected %u\n", i, g_cols[i].v, i + 1u);
            return 4;
        }}
    }}
    bamabi_shutdown(inst);
    return 0;
}}
"#
    );
    let h_path = tmp.path().join("c99_130_harness.c");
    fs::write(&h_path, harness).unwrap();
    let exe = tmp.path().join("c99_130_harness");
    let cc = find_c99_compiler();
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
        .arg(&h_path)
        .arg("-o")
        .arg(&exe)
        .output()
        .unwrap();
    assert!(
        comp.status.success(),
        "C99 130-pkt compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&exe).output().unwrap();
    assert!(
        run.status.success(),
        "C99 130-pkt run failed:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
}
