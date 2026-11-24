#![cfg(feature = "sim-runner")]
#![forbid(unsafe_code)]

use bamabi_host::{
    AbiModPlugin, LoadOptions, ModErrorPolicy, ModRegistry, ModWorldExt, read_entity_pod_bytes,
    write_entity_pod_bytes,
};
use bamabi_native_rt::{SharedBridgeAppExt, StrataNetPacket};
use bevy_app::{App, FixedUpdate, PostStartup, Startup};
use bevy_ecs::message::{MessageCursor, Messages};
use bevy_ecs::schedule::SingleThreadedExecutor;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use strata_syntax::graph_ir::{GraphIrDocument, GraphNodeKind};
use stratac::cli::{BuildTarget, OutputFormat};
use stratac::commands::graph_cmd::cmd_graph_export;
use stratac::commands::{cmd_build, cmd_test};
use stratac::{EXIT_OK, EXIT_SIM_TEST_FAILED};
use tempfile::TempDir;

static NET_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn cookbooks_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks")
}

#[test]
fn net_sim_authority_isolation_latency_and_loss_behave_genuinely() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    // 1. Latency=50ms delays delivery past tick 1, converges after enough ticks;
    //    `@authority(server)` never executes on client.
    let delayed_path = tmp.path().join("delayed.strata");
    fs::write(
        &delayed_path,
        r#"
module test::net_delay @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component NetFlag {
    val: u32 = 0,
}

object Anchor {
    NetFlag { val: 0 },
}

@authority(server)
sys server_set() {
    for f in query(n: &mut NetFlag) {
        if f.n.val == 0_u32 {
            f.n.val = 42_u32;
        }
    }
}

schedule FixedUpdate { server_set }

net_sim_test "latency_delays_tick_1_then_converges"(latency: 50ms, jitter: 0ms, loss: 0.0, seed: 7) {
    clients(1);
    step_net(1);
    assert_eq(server_query(n: &NetFlag).on(Anchor).unwrap().n.val, 42_u32);
    assert_eq(client_query(0, n: &NetFlag).on(Anchor).unwrap().n.val, 0_u32);
    step_net(5);
    assert_converged();
    assert_eq(client_query(0, n: &NetFlag).on(Anchor).unwrap().n.val, 42_u32);
}
"#,
    )
    .unwrap();
    let (rc, out) = cmd_test(&delayed_path, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "delayed net_sim_test failed:\n{out}");
    let rep: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(rep["all_passed"], true);
    assert_eq!(rep["tests"][0]["passed"], true);

    // 2. 100% loss must drop every packet + retry and fail convergence (EXIT_SIM_TEST_FAILED = 2).
    let loss_path = tmp.path().join("total_loss.strata");
    fs::write(
        &loss_path,
        r#"
module test::net_loss @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
component Counter {
    v: u32 = 0,
}

object Box { Counter { v: 0 } }

@authority(server)
sys bump() {
    for c in query(v: &mut Counter) {
        c.v.v += 1_u32;
    }
}

schedule FixedUpdate { bump }

net_sim_test "loss_100_percent_fails"(latency: 0ms, jitter: 0ms, loss: 1.0, seed: 99) {
    clients(1);
    step_net(10);
    assert_converged();
}
"#,
    )
    .unwrap();
    let (rc_loss, out_loss) = cmd_test(&loss_path, OutputFormat::Json);
    assert_eq!(
        rc_loss, EXIT_SIM_TEST_FAILED,
        "100% loss must fail convergence:\n{out_loss}"
    );
    let rep_loss: serde_json::Value = serde_json::from_str(&out_loss).unwrap();
    assert_eq!(rep_loss["all_passed"], false);
    assert_eq!(rep_loss["tests"][0]["passed"], false);
    let detail = rep_loss["tests"][0]["detail"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(!detail.contains("stub") && !detail.contains("unimplemented"));
}

#[test]
fn net_sim_reliable_arq_partial_loss_determinism_and_quantization() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();
    let src = r#"
module test::net_arq @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component QuantState {
    @quantize(min = -100.0, max = 100.0, bits = 16)
    x: f32 = 0.0,
    seq: u32 = 0,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc PingCmd {
    seq: u32,
}

object Target { QuantState { x: 0.0, seq: 0 } }

@authority(server)
sys drive() {
    for s in query(q: &mut QuantState) {
        if s.q.seq < 3_u32 {
            s.q.seq += 1_u32;
            s.q.x = 37.25;
        }
    }
}

schedule FixedUpdate { drive }

net_sim_test "arq_recovers_and_is_deterministic"(latency: 20ms, jitter: 15ms, loss: 0.35, seed: 42, clients: 2) {
    send_rpc(0, PingCmd { seq: 1_u32 });
    step_net(35);
    assert_converged();
    assert_converged(1, 0.02);
    let cx = client_query(0, q: &QuantState).on(Target).unwrap().q.x;
    assert(abs(cx - 37.25) < 0.01);
}
"#;
    let p = tmp.path().join("arq.strata");
    fs::write(&p, src).unwrap();

    let (rc1, out1) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc1, EXIT_OK, "run 1 failed:\n{out1}");
    let (rc2, out2) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc2, EXIT_OK, "run 2 failed:\n{out2}");

    let v1: serde_json::Value = serde_json::from_str(&out1).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&out2).unwrap();
    assert_eq!(v1["tests"], v2["tests"], "repeated runs must be identical");
}

#[test]
fn net_sim_supports_spawn_res_mut_query_and_per_world_step() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("ops.strata");
    fs::write(
        &p,
        r#"
module test::net_ops @version(1.0.0);

resource MatchCfg {
    bonus: u32 = 5,
}

@authority(server)
@net(reliable, channel = 0)
component Unit {
    hp: u32 = 10,
}

object Hero { Unit { hp: 10 } }

@authority(server)
sys add_bonus(cfg: &res MatchCfg) {
    for u in query(unit: &mut Unit) {
        u.unit.hp += cfg.bonus;
    }
}

schedule FixedUpdate { add_bonus }

net_sim_test "all_net_ops_work"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 1) {
    spawn_client(1);
    server_res<MatchCfg>().bonus = 2_u32;
    let srv_ent = server_spawn(Unit { hp: 50_u32 });
    let cli_ent = client_spawn(0, Unit { hp: 25_u32 });
    server_step(1);
    client_step(0, 1);
    assert_eq(server_query(u: &Unit).on(srv_ent).unwrap().u.hp, 52_u32);
    assert_eq(client_query(0, u: &Unit).on(cli_ent).unwrap().u.hp, 25_u32);
    if let Some(mut_row) = client_query(1, u: &mut Unit).on(Hero) {
        mut_row.u.hp = 99_u32;
    }
    assert_eq(client_query(1, u: &Unit).on(Hero).unwrap().u.hp, 99_u32);
    let mut sum: u32 = 0_u32;
    for row in server_query(u: &Unit) {
        sum += row.u.hp;
    }
    assert(sum >= 64_u32);
}
"#,
    )
    .unwrap();
    let (rc, out) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "net ops test failed:\n{out}");
}

#[test]
fn cookbooks_07_and_08_pass_end_to_end_and_are_deterministic() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let p07 = cookbooks_dir().join("07_visual_boss_graph.strata");
    let (exp_rc, exp_json) = cmd_graph_export(&p07, OutputFormat::Json);
    assert_eq!(exp_rc, EXIT_OK, "07 graph export failed: {exp_json}");
    let doc: GraphIrDocument = serde_json::from_str(&exp_json).unwrap();
    let kinds: HashSet<GraphNodeKind> = doc.nodes.iter().map(|n| n.kind).collect();
    assert_eq!(kinds.len(), 8, "expected all 8 graph node kinds in 07");

    let (t7_rc, t7_out) = cmd_test(&p07, OutputFormat::Json);
    assert_eq!(t7_rc, EXIT_OK, "07 sim_test failed:\n{t7_out}");

    let p08 = cookbooks_dir().join("08_authoritative_multiplayer.strata");
    let (r1, o1) = cmd_test(&p08, OutputFormat::Json);
    let (r2, o2) = cmd_test(&p08, OutputFormat::Json);
    assert_eq!(r1, EXIT_OK, "08 test run 1 failed:\n{o1}");
    assert_eq!(r2, EXIT_OK, "08 test run 2 failed:\n{o2}");
    let v1: serde_json::Value = serde_json::from_str(&o1).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&o2).unwrap();
    assert_eq!(v1["all_passed"], true);
    assert!(v1["tests"].as_array().unwrap().len() >= 2);
    assert_eq!(v1["tests"], v2["tests"]);
}

#[test]
fn net_sim_mod_local_server_resource_replicates_and_loss_reports_mismatch() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    let ok_path = tmp.path().join("mod_res_ok.strata");
    fs::write(
        &ok_path,
        r#"
module test::mod_res_ok @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
resource MatchState {
    round: u32 = 1,
    timer: f32 = 0.0,
}

@authority(server)
sys advance_round(ms: &mut res MatchState) {
    if ms.round < 3_u32 {
        ms.round += 1_u32;
        ms.timer += 1.5;
    }
}

schedule FixedUpdate { advance_round }

net_sim_test "mod_res_replicates"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 5) {
    clients(1);
    step_net(5);
    assert_converged();
    assert_eq(client_res<MatchState>(0).round, 3_u32);
    assert(abs(client_res<MatchState>(0).timer - 3.0) < 0.01);
}
"#,
    )
    .unwrap();
    let (rc_ok, out_ok) = cmd_test(&ok_path, OutputFormat::Json);
    assert_eq!(
        rc_ok, EXIT_OK,
        "mod-local server resource failed:\n{out_ok}"
    );

    let loss_path = tmp.path().join("mod_res_loss.strata");
    fs::write(
        &loss_path,
        r#"
module test::mod_res_loss @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
resource MatchState {
    round: u32 = 1,
}

@authority(server)
sys advance_round(ms: &mut res MatchState) {
    if ms.round < 3_u32 {
        ms.round += 1_u32;
    }
}

schedule FixedUpdate { advance_round }

net_sim_test "mod_res_loss_fails"(latency: 0ms, jitter: 0ms, loss: 1.0, seed: 6) {
    clients(1);
    step_net(5);
    assert_converged();
}
"#,
    )
    .unwrap();
    let (rc_loss, out_loss) = cmd_test(&loss_path, OutputFormat::Json);
    assert_eq!(
        rc_loss, EXIT_SIM_TEST_FAILED,
        "100% loss on mod-local resource must fail:\n{out_loss}"
    );
    let rep: serde_json::Value = serde_json::from_str(&out_loss).unwrap();
    let detail = rep["tests"][0]["detail"].as_str().unwrap().to_lowercase();
    assert!(
        detail.contains("resource") && detail.contains("matchstate") && detail.contains("round"),
        "expected resource MatchState.round mismatch, got: {detail}"
    );
}

#[test]
fn net_sim_direct_client_res_assignment_replicates_and_rejects_oob() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    let ok_path = tmp.path().join("client_res_ok.strata");
    fs::write(
        &ok_path,
        r#"
module test::client_res_ok @version(1.0.0);

@authority(client)
@net(reliable, channel = 0)
resource ClientCfg {
    bonus: u32 = 1,
}

net_sim_test "client_res_direct_assign"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 11) {
    clients(1);
    client_res<ClientCfg>(0).bonus = 9_u32;
    client_res<ClientCfg>(0).bonus += 4_u32;
    step_net(2);
    assert_converged();
    assert_eq(server_res<ClientCfg>().bonus, 13_u32);
}
"#,
    )
    .unwrap();
    let (rc_ok, out_ok) = cmd_test(&ok_path, OutputFormat::Json);
    assert_eq!(rc_ok, EXIT_OK, "direct client_res assign failed:\n{out_ok}");

    let oob_path = tmp.path().join("client_res_oob.strata");
    fs::write(
        &oob_path,
        r#"
module test::client_res_oob @version(1.0.0);

@authority(client)
@net(reliable, channel = 0)
resource ClientCfg {
    bonus: u32 = 1,
}

net_sim_test "client_res_oob_fails"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 12) {
    clients(1);
    client_res<ClientCfg>(5).bonus = 1_u32;
}
"#,
    )
    .unwrap();
    let (rc_oob, out_oob) = cmd_test(&oob_path, OutputFormat::Json);
    assert_eq!(
        rc_oob, EXIT_SIM_TEST_FAILED,
        "out-of-range client_res must fail:\n{out_oob}"
    );
    let rep: serde_json::Value = serde_json::from_str(&out_oob).unwrap();
    let detail = rep["tests"][0]["detail"].as_str().unwrap().to_lowercase();
    assert!(
        detail.contains("out of range"),
        "expected out-of-range error detail, got: {detail}"
    );
}

#[test]
fn net_sim_shared_resource_replicates_without_rx_tx_echo() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    let p = tmp.path().join("shared_res.strata");
    fs::write(
        &p,
        r#"
module test::shared_res @version(1.0.0);

@authority(shared)
@net(reliable, channel = 0)
resource SharedState {
    phase: u32 = 0,
}

net_sim_test "shared_res_no_echo"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 22) {
    clients(1);
    server_res<SharedState>().phase = 7_u32;
    step_net(3);
    assert_converged();
    assert_eq(client_res<SharedState>(0).phase, 7_u32);

    server_res<SharedState>().phase = 15_u32;
    step_net(3);
    assert_converged();
    assert_eq(client_res<SharedState>(0).phase, 15_u32);

    client_res<SharedState>(0).phase = 21_u32;
    step_net(3);
    assert_converged();
    assert_eq(server_res<SharedState>().phase, 21_u32);
}
"#,
    )
    .unwrap();
    let (rc1, out1) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc1, EXIT_OK, "shared resource run 1 failed:\n{out1}");
    let (rc2, out2) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc2, EXIT_OK, "shared resource run 2 failed:\n{out2}");
    let v1: serde_json::Value = serde_json::from_str(&out1).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&out2).unwrap();
    assert_eq!(v1["tests"], v2["tests"]);
}

#[test]
fn sim_test_nonzero_fsm_initial_state_and_enum_field_load() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    let p = tmp.path().join("fsm_enum.strata");
    fs::write(
        &p,
        r#"
module test::fsm_enum @version(1.0.0);

enum Tier {
    Low = 0,
    High = 1,
}

table TierBonus by Tier {
    mult: f32,
} = {
    Low => { mult: 1.0 },
    High => { mult: 3.5 },
};

fn pick_tier(flag: bool, cur: Tier) -> Tier {
    let mut chosen = Tier::Low;
    if flag {
        chosen = Tier::High;
    } else {
        chosen = cur;
    }
    return chosen;
}

resource FsmProbe {
    active_ticks: u32 = 0,
    idle_ticks: u32 = 0,
    bonus_acc: f32 = 0.0,
    tier_matched: bool = false,
}

component Agent {
    tier: Tier = Tier::High,
}

object Unit {
    Agent { tier: Tier::High },
}

fsm NonZeroFsm(probe: &mut res FsmProbe) @require(Agent) {
    initial Active;

    state Idle {
        on_tick {
            probe.idle_ticks += 1_u32;
        }
        to Active when false;
    }

    state Active {
        on_tick {
            probe.active_ticks += 1_u32;
        }
        to Idle when false;
    }
}

sys check_enums_and_fsm(probe: &mut res FsmProbe) {
    for row in query(a: &Agent) {
        insert @if_new(row.id, NonZeroFsm::start());
        let t: Tier = row.a.tier;
        if t == Tier::High {
            probe.tier_matched = true;
        }
        let b = TierBonus[t].mult;
        let next_t = pick_tier(false, t);
        let mut p = Tier::Low;
        if next_t == Tier::High {
            p = Tier::High;
        }
        probe.bonus_acc = TierBonus[p].mult + b;
    }
}

schedule FixedUpdate {
    seq Frame {
        check_enums_and_fsm,
        NonZeroFsm,
    }
}

sim_test "nonzero_fsm_and_enums" {
    step_fixed(3);
    assert_eq(res<FsmProbe>().active_ticks, 3_u32);
    assert_eq(res<FsmProbe>().idle_ticks, 0_u32);
    assert_eq(res<FsmProbe>().tier_matched, true);
    assert(abs(res<FsmProbe>().bonus_acc - 7.0) < 0.01);
}
"#,
    )
    .unwrap();
    let (rc, out) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "nonzero FSM + enum test failed:\n{out}");
}

#[test]
fn net_sim_ivec_uvec_replication_and_mismatch_rejection() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    let ok_p = tmp.path().join("ivec_uvec_ok.strata");
    fs::write(
        &ok_p,
        r#"
module test::ivec_uvec @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
component PackedBounds {
    iv: ivec2 = ivec2(0, 0),
    iv3: ivec3 = ivec3(0, 0, 0),
    uv: uvec2 = uvec2(0_u32, 0_u32),
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc BoundsRpc {
    @quantize(min = -10.0, max = 10.0, bits = 8)
    step: ivec2,
    @quantize(min = 0.0, max = 20.0, bits = 8)
    uoff: uvec2,
}

object BoundsObj {
    PackedBounds { iv: ivec2(0, 0), iv3: ivec3(0, 0, 0), uv: uvec2(0_u32, 0_u32) },
}

@authority(server)
sys noop_srv() {}

schedule FixedUpdate { noop_srv }

net_sim_test "ivec_uvec_replicates"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 11) {
    clients(1);
    send_rpc(0, BoundsRpc { step: ivec2(-3, 5), uoff: uvec2(2_u32, 8_u32) });
    if let Some(mut_row) = server_query(b: &mut PackedBounds).on(BoundsObj) {
        mut_row.b.iv = ivec2(-3, 5);
        mut_row.b.iv3 = ivec3(-7, 2, 11);
        mut_row.b.uv = uvec2(10_u32, 95_u32);
    }
    step_net(3);
    assert_converged();
    let cb = client_query(0, b: &PackedBounds).on(BoundsObj).unwrap().b;
    assert_eq(cb.iv.x, -3);
    assert_eq(cb.iv.y, 5);
    assert_eq(cb.iv, ivec2(-3, 5));
    assert(cb.iv3.x == -7);
    assert(cb.iv3.z == 11);
    assert_eq(cb.iv3, ivec3(-7, 2, 11));
    assert(cb.uv.x > 5_u32);
    assert_eq(cb.uv.y, 95_u32);
    assert_eq(cb.uv, uvec2(10_u32, 95_u32));
}
"#,
    )
    .unwrap();
    let (rc, out) = cmd_test(&ok_p, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "ivec/uvec replication failed:\n{out}");

    // Mismatch rejection: client modified after latency=100ms before delivery must fail assert_converged()
    let bad_p = tmp.path().join("ivec_uvec_mismatch.strata");
    fs::write(
        &bad_p,
        r#"
module test::ivec_uvec_bad @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
component PackedBounds {
    iv: ivec2 = ivec2(0, 0),
    uv: uvec2 = uvec2(0_u32, 0_u32),
}

object BoundsObj {
    PackedBounds { iv: ivec2(0, 0), uv: uvec2(0_u32, 0_u32) },
}

@authority(server)
sys noop_srv() {}

schedule FixedUpdate { noop_srv }

net_sim_test "ivec_mismatch_detected"(latency: 100ms, jitter: 0ms, loss: 0.0, seed: 11) {
    clients(1);
    if let Some(mut_row) = server_query(b: &mut PackedBounds).on(BoundsObj) {
        mut_row.b.iv = ivec2(-3, 5);
        mut_row.b.uv = uvec2(10_u32, 95_u32);
    }
    step_net(1);
    assert_converged();
}
"#,
    )
    .unwrap();
    let (rc_bad, out_bad) = cmd_test(&bad_p, OutputFormat::Json);
    assert_eq!(
        rc_bad, EXIT_SIM_TEST_FAILED,
        "ivec/uvec mismatch must fail:\n{out_bad}"
    );
}

#[test]
fn net_sim_nine_net_components_with_zero_client_fixed_systems_converges() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("nine_comps.strata");
    fs::write(
        &p,
        r#"
module test::nine_comps @version(1.0.0);

@authority(server) @net(reliable, channel = 0) component C0 { v: u32 = 1 }
@authority(server) @net(reliable, channel = 0) component C1 { v: u32 = 2 }
@authority(server) @net(reliable, channel = 0) component C2 { v: u32 = 3 }
@authority(server) @net(reliable, channel = 0) component C3 { v: u32 = 4 }
@authority(server) @net(reliable, channel = 0) component C4 { v: u32 = 5 }
@authority(server) @net(reliable, channel = 0) component C5 { v: u32 = 6 }
@authority(server) @net(reliable, channel = 0) component C6 { v: u32 = 7 }
@authority(server) @net(reliable, channel = 0) component C7 { v: u32 = 8 }
@authority(server) @net(reliable, channel = 0) component C8 { v: u32 = 9 }

object MultiObj {
    C0 { v: 1 }, C1 { v: 2 }, C2 { v: 3 },
    C3 { v: 4 }, C4 { v: 5 }, C5 { v: 6 },
    C6 { v: 7 }, C7 { v: 8 }, C8 { v: 9 },
}

@authority(server)
sys bump_all() {
    for r in query(c0: &mut C0, c1: &mut C1, c2: &mut C2, c3: &mut C3, c4: &mut C4, c5: &mut C5, c6: &mut C6) {
        if r.c0.v == 1_u32 {
            r.c0.v = 11_u32; r.c1.v = 22_u32; r.c2.v = 33_u32; r.c3.v = 44_u32;
            r.c4.v = 55_u32; r.c5.v = 66_u32; r.c6.v = 77_u32;
        }
    }
    for r in query(c7: &mut C7, c8: &mut C8) {
        if r.c7.v == 8_u32 {
            r.c7.v = 88_u32;
            r.c8.v = 99_u32;
        }
    }
}

schedule FixedUpdate { bump_all }

net_sim_test "nine_comps_no_client_fixed_systems"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 3) {
    clients(1);
    step_net(5);
    assert_converged();
    assert_eq(client_query(0, c: &C0).on(MultiObj).unwrap().c.v, 11_u32);
    assert_eq(client_query(0, c: &C6).on(MultiObj).unwrap().c.v, 77_u32);
    assert_eq(client_query(0, c: &C7).on(MultiObj).unwrap().c.v, 88_u32);
    assert_eq(client_query(0, c: &C8).on(MultiObj).unwrap().c.v, 99_u32);
}
"#,
    )
    .unwrap();
    let (rc, out) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "nine_comps failed:\n{out}");
}

#[test]
fn net_sim_65_entities_replicates_all_without_batch_drop() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();
    let mut src = String::from(
        r#"
module test::batch_65 @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
component Dot {
    v: u32 = 0,
}
"#,
    );
    for i in 0..65 {
        src.push_str(&format!("object O{i} {{ Dot {{ v: 0 }} }}\n"));
    }
    src.push_str(
        r#"
@authority(server)
sys bump_dots() {
    for r in query(d: &mut Dot) {
        if r.d.v == 0_u32 {
            r.d.v = 7_u32;
        }
    }
}

schedule FixedUpdate { bump_dots }

net_sim_test "batch_65_all_converge"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 5) {
    clients(1);
    step_net(4);
    assert_converged();
    assert_eq(client_query(0, d: &Dot).on(O64).unwrap().d.v, 7_u32);
}
"#,
    );
    let p = tmp.path().join("batch_65.strata");
    fs::write(&p, src).unwrap();
    let (rc, out) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "batch_65 failed:\n{out}");
}

#[test]
fn net_sim_server_authoritative_quantized_not_overwritten_by_loopback() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    let preserve_p = tmp.path().join("loopback_preserve.strata");
    fs::write(
        &preserve_p,
        r#"
module test::loopback_preserve @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
component Q8 {
    @quantize(min = 0.0, max = 25.5, bits = 8)
    x: f32 = 0.0,
    did_set: bool = false,
}

object Anchor { Q8 { x: 0.0, did_set: false } }

@authority(server)
sys set_once() {
    for r in query(q: &mut Q8) {
        if !r.q.did_set {
            r.q.x = 1.04;
            r.q.did_set = true;
        }
    }
}

schedule FixedUpdate { set_once }

net_sim_test "server_preserves_unquantized_precision_across_ticks"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 1) {
    clients(1);
    step_net(1);
    let sx1 = server_query(q: &Q8).on(Anchor).unwrap().q.x;
    assert(sx1 > 1.03);
    step_net(3);
    let sx2 = server_query(q: &Q8).on(Anchor).unwrap().q.x;
    assert(sx2 > 1.03);
    assert_converged();
}
"#,
    )
    .unwrap();
    let (rc_ok, out_ok) = cmd_test(&preserve_p, OutputFormat::Json);
    assert_eq!(
        rc_ok, EXIT_OK,
        "server precision preserve failed:\n{out_ok}"
    );

    // Tight explicit tolerance (0.001 < 0.04 quantization error) MUST fail assert_converged(0, 0.001)
    let tight_p = tmp.path().join("loopback_tight_tol.strata");
    fs::write(
        &tight_p,
        r#"
module test::loopback_tight @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
component Q8 {
    @quantize(min = 0.0, max = 25.5, bits = 8)
    x: f32 = 0.0,
    did_set: bool = false,
}

object Anchor { Q8 { x: 0.0, did_set: false } }

@authority(server)
sys set_once() {
    for r in query(q: &mut Q8) {
        if !r.q.did_set {
            r.q.x = 1.04;
            r.q.did_set = true;
        }
    }
}

schedule FixedUpdate { set_once }

net_sim_test "tight_tol_rejects_quantization_delta"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 1) {
    clients(1);
    step_net(3);
    assert_converged(0, 0.001);
}
"#,
    )
    .unwrap();
    let (rc_tight, out_tight) = cmd_test(&tight_p, OutputFormat::Json);
    assert_eq!(
        rc_tight, EXIT_SIM_TEST_FAILED,
        "tight tolerance (0.001) must fail against 0.04 quantization error:\n{out_tight}"
    );
}

#[test]
fn net_sim_sparse_net_component_with_selective_write_replicates() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("sparse_selective.strata");
    fs::write(
        &p,
        r#"
module test::sparse_net_sel @version(1.0.0);

@sparse
@net(reliable, channel = 0)
@authority(server)
component SparseNet {
    val: u32 = 0,
}

object Marker { SparseNet { val: 0 } }

@authority(server)
sys bump_sparse() {
    for row in query(s: &mut? SparseNet) {
        if row.s.val == 0_u32 {
            row.s.val = 77_u32;
        }
    }
}

schedule FixedUpdate { bump_sparse }

net_sim_test "sparse_selective_replicates"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 9) {
    clients(1);
    step_net(4);
    assert_converged();
    assert_eq(client_query(0, s: &SparseNet).on(Marker).unwrap().s.val, 77_u32);
}
"#,
    )
    .unwrap();
    let (rc, out) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "sparse @net + &mut? failed:\n{out}");
}

#[test]
fn sim_and_net_mod_resource_ivec_uvec_bit_preserving_and_mismatch() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    let ok_p = tmp.path().join("res_ivec_ok.strata");
    fs::write(
        &ok_p,
        r#"
module test::res_ivec_ok @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
resource IntVecRes {
    iv: ivec2 = ivec2(0, 0),
    iv3: ivec3 = ivec3(0, 0, 0),
    uv: uvec2 = uvec2(0_u32, 0_u32),
    fv2: vec2 = vec2(0.0, 0.0),
    fv3: vec3 = vec3(0.0, 0.0, 0.0),
    fv4: vec4 = vec4(0.0, 0.0, 0.0, 0.0),
}

@authority(client)
@net(reliable, channel = 0)
resource ClientIntVecRes {
    iv: ivec2 = ivec2(0, 0),
    iv3: ivec3 = ivec3(0, 0, 0),
    uv: uvec2 = uvec2(0_u32, 0_u32),
}

@authority(server)
sys noop_srv() {}

schedule FixedUpdate { noop_srv }

sim_test "sim_res_mut_ivec_uvec_and_float_vecs" {
    res_mut<IntVecRes>().iv = ivec2(-9, 1065353216);
    res_mut<IntVecRes>().iv3 = ivec3(-1, 2, -3);
    res_mut<IntVecRes>().uv = uvec2(3000000000_u32, 200_u32);
    res_mut<IntVecRes>().fv2 = vec2(1.5, -2.25);
    res_mut<IntVecRes>().fv3 = vec3(3.0, -4.5, 6.25);
    res_mut<IntVecRes>().fv4 = vec4(-1.0, 2.0, -3.0, 4.0);
    assert_eq(res<IntVecRes>().iv, ivec2(-9, 1065353216));
    assert_eq(res<IntVecRes>().iv3, ivec3(-1, 2, -3));
    assert_eq(res<IntVecRes>().uv, uvec2(3000000000_u32, 200_u32));
    assert_eq(res<IntVecRes>().fv2, vec2(1.5, -2.25));
    assert_eq(res<IntVecRes>().fv3, vec3(3.0, -4.5, 6.25));
    assert_eq(res<IntVecRes>().fv4, vec4(-1.0, 2.0, -3.0, 4.0));

    // Single-lane writes must also preserve integer bit patterns.
    res_mut<IntVecRes>().iv.x = -42;
    res_mut<IntVecRes>().uv.y = 777_u32;
    assert_eq(res<IntVecRes>().iv, ivec2(-42, 1065353216));
    assert_eq(res<IntVecRes>().uv, uvec2(3000000000_u32, 777_u32));
}

net_sim_test "net_res_ivec_uvec_replicates"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 42) {
    clients(1);
    server_res<IntVecRes>().iv = ivec2(-9, 1065353216);
    server_res<IntVecRes>().iv3 = ivec3(-1, 2, -3);
    server_res<IntVecRes>().uv = uvec2(3000000000_u32, 200_u32);
    server_res<IntVecRes>().fv2 = vec2(1.5, -2.25);
    server_res<IntVecRes>().fv3 = vec3(3.0, -4.5, 6.25);
    server_res<IntVecRes>().fv4 = vec4(-1.0, 2.0, -3.0, 4.0);

    client_res<ClientIntVecRes>(0).iv = ivec2(-17, 1065353216);
    client_res<ClientIntVecRes>(0).iv3 = ivec3(4, -5, 6);
    client_res<ClientIntVecRes>(0).uv = uvec2(3000000000_u32, 200_u32);
    client_res<ClientIntVecRes>(0).iv.x = -19;

    step_net(3);
    assert_converged();
    assert_eq(client_res<IntVecRes>(0).iv, ivec2(-9, 1065353216));
    assert_eq(client_res<IntVecRes>(0).iv3, ivec3(-1, 2, -3));
    assert_eq(client_res<IntVecRes>(0).uv, uvec2(3000000000_u32, 200_u32));
    assert_eq(client_res<IntVecRes>(0).fv2, vec2(1.5, -2.25));
    assert_eq(client_res<IntVecRes>(0).fv3, vec3(3.0, -4.5, 6.25));
    assert_eq(client_res<IntVecRes>(0).fv4, vec4(-1.0, 2.0, -3.0, 4.0));
    assert_eq(server_res<ClientIntVecRes>().iv, ivec2(-19, 1065353216));
    assert_eq(server_res<ClientIntVecRes>().iv3, ivec3(4, -5, 6));
    assert_eq(server_res<ClientIntVecRes>().uv, uvec2(3000000000_u32, 200_u32));
}
"#,
    )
    .unwrap();
    let (rc_ok, out_ok) = cmd_test(&ok_p, OutputFormat::Json);
    assert_eq!(
        rc_ok, EXIT_OK,
        "mod-local resource ivec/uvec test failed:\n{out_ok}"
    );
    let rep_ok: serde_json::Value = serde_json::from_str(&out_ok).unwrap();
    assert_eq!(rep_ok["all_passed"], true);
    assert_eq!(rep_ok["tests"][0]["passed"], true);
    assert_eq!(rep_ok["tests"][1]["passed"], true);

    // Negative mismatch check: with 100ms latency, step_net(1) must NOT vacuously pass assert_converged().
    let bad_p = tmp.path().join("res_ivec_mismatch.strata");
    fs::write(
        &bad_p,
        r#"
module test::res_ivec_bad @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
resource IntVecRes {
    iv: ivec2 = ivec2(0, 0),
    iv3: ivec3 = ivec3(0, 0, 0),
    uv: uvec2 = uvec2(0_u32, 0_u32),
}

@authority(server)
sys noop_srv() {}

schedule FixedUpdate { noop_srv }

net_sim_test "net_res_ivec_mismatch_detected"(latency: 100ms, jitter: 0ms, loss: 0.0, seed: 42) {
    clients(1);
    server_res<IntVecRes>().iv = ivec2(-9, 1065353216);
    server_res<IntVecRes>().iv3 = ivec3(-1, 2, -3);
    server_res<IntVecRes>().uv = uvec2(3000000000_u32, 200_u32);
    step_net(1);
    assert_converged();
}
"#,
    )
    .unwrap();
    let (rc_bad, out_bad) = cmd_test(&bad_p, OutputFormat::Json);
    assert_eq!(
        rc_bad, EXIT_SIM_TEST_FAILED,
        "mod-local resource ivec/uvec mismatch must fail:\n{out_bad}"
    );
    let rep_bad: serde_json::Value = serde_json::from_str(&out_bad).unwrap();
    assert_eq!(rep_bad["all_passed"], false);
    assert_eq!(rep_bad["tests"][0]["passed"], false);
    let detail = rep_bad["tests"][0]["detail"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(
        detail.contains("intvecres") && detail.contains("mismatch"),
        "expected IntVecRes mismatch detail, got: {detail}"
    );
}

#[test]
fn rust_guest_130_entities_multi_batch_pod_messages_conserved() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("rg_batch_130.strata");
    fs::write(
        &src_path,
        r#"
module test::rg_batch_130 @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
component Dot {
    v: u32 = 0,
}

sys seed_dots() effects(spawns: [Dot]) {
    spawn_batch(130) |i| {
        {
            Dot { v: 0_u32 },
        }
    };
}

sys noop_tick() {}

schedule Startup { seed_dots }
schedule FixedUpdate { noop_tick }
"#,
    )
    .unwrap();

    let out_dir = tmp.path().join("rg_out");
    let (code, msg) = cmd_build(
        &src_path,
        true,
        BuildTarget::RustGuest,
        Some(&out_dir),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(code, EXIT_OK, "RustGuest build failed:\n{msg}");
    let rep: serde_json::Value = serde_json::from_str(&msg).unwrap();
    let dylib_path = PathBuf::from(rep["binary_path"].as_str().unwrap());

    let spawn_world = |dylib: &PathBuf| -> App {
        let mut app = App::new();
        app.init_schedule(Startup);
        app.init_schedule(PostStartup);
        app.init_schedule(FixedUpdate);
        app.edit_schedule(FixedUpdate, |s| {
            s.set_executor(SingleThreadedExecutor::new());
        });
        app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
        app.register_strata_net_transport()
            .expect("register strata net transport");
        app.world_mut()
            .load_mod_with(dylib, LoadOptions::default())
            .expect("load RustGuest dylib");
        app.world_mut().run_schedule(Startup);
        app.world_mut().run_schedule(PostStartup);
        if let Some(mut msgs) = app
            .world_mut()
            .get_resource_mut::<Messages<StrataNetPacket>>()
        {
            msgs.clear();
        }
        app
    };

    let mut srv = spawn_world(&dylib_path);
    let mut cli = spawn_world(&dylib_path);

    let find_dot = |app: &App| {
        let reg = app.world().resource::<ModRegistry>();
        reg.get_by_name("test::rg_batch_130::Dot")
            .cloned()
            .expect("Dot registered in ModRegistry")
    };
    let srv_dot = find_dot(&srv);
    let cli_dot = find_dot(&cli);

    let collect_entities = |app: &mut App, comp_id| -> Vec<bevy_ecs::entity::Entity> {
        let mut q = bevy_ecs::query::QueryBuilder::<bevy_ecs::entity::Entity>::new(app.world_mut());
        q.with_id(comp_id);
        let mut qs = q.build();
        let mut ents: Vec<_> = qs.iter(app.world()).collect();
        ents.sort_by_key(|e| e.to_bits());
        ents
    };

    let srv_ents = collect_entities(&mut srv, srv_dot.component_id);
    let cli_ents = collect_entities(&mut cli, cli_dot.component_id);
    assert_eq!(srv_ents.len(), 130, "expected 130 spawned server entities");
    assert_eq!(cli_ents.len(), 130, "expected 130 spawned client entities");

    // Advance one baseline tick on both worlds so change detection clears startup insertions.
    srv.world_mut().run_schedule(FixedUpdate);
    cli.world_mut().run_schedule(FixedUpdate);
    srv.world_mut()
        .resource_mut::<Messages<StrataNetPacket>>()
        .clear();
    cli.world_mut()
        .resource_mut::<Messages<StrataNetPacket>>()
        .clear();

    // Mutate all 130 server entities to unique non-zero values (crossing TWO 64-message boundaries).
    for (i, &ent) in srv_ents.iter().enumerate() {
        let val = 1000u32 + (i as u32);
        write_entity_pod_bytes(srv.world_mut(), ent, srv_dot.handle, &val.to_le_bytes())
            .expect("write server Dot value");
    }

    let mut tx_cursor: MessageCursor<StrataNetPacket> = MessageCursor::default();
    {
        let msgs = srv.world().resource::<Messages<StrataNetPacket>>();
        let _ = tx_cursor.read(msgs).count();
    }

    srv.world_mut().run_schedule(FixedUpdate);
    let outbound: Vec<StrataNetPacket> = {
        let msgs = srv.world().resource::<Messages<StrataNetPacket>>();
        tx_cursor.read(msgs).copied().collect()
    };
    assert_eq!(
        outbound.len(),
        130,
        "expected RustGuest server TX to emit all 130 delta packets"
    );

    let ent_map: HashMap<u64, u64> = srv_ents
        .iter()
        .zip(cli_ents.iter())
        .map(|(s, c)| (s.to_bits(), c.to_bits()))
        .collect();

    {
        let mut cli_msgs = cli.world_mut().resource_mut::<Messages<StrataNetPacket>>();
        for mut pkt in outbound {
            pkt.entity_bits = *ent_map
                .get(&pkt.entity_bits)
                .expect("server entity mapped to client entity");
            cli_msgs.write(pkt);
        }
    }

    // Run ONE FixedUpdate tick on the RustGuest client so `drain_messages_checked` (BATCH_SIZE = 64)
    // executes 3 consecutive `msg_read_batch` calls (64 + 64 + 2 = 130) against bamabi-core.
    cli.world_mut().run_schedule(FixedUpdate);

    for (i, &ent) in cli_ents.iter().enumerate() {
        let bytes =
            read_entity_pod_bytes(cli.world(), ent, cli_dot.handle).expect("read client Dot value");
        assert_eq!(bytes.len(), 4);
        let got = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let expected = 1000u32 + (i as u32);
        assert_eq!(
            got, expected,
            "RustGuest client entity #{i} dropped or corrupted across 64-message batch boundary"
        );
    }
}

#[test]
fn nt_02_role_filters_obs_task_fsm_timeline_and_blocks_client_server_overwrite() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("nt02_roles.strata");
    fs::write(
        &p,
        r#"
module test::nt02_roles @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
resource SrvVault {
    gold: u32 = 100,
    obs_hits: u32 = 0,
}

@authority(server)
@net(reliable, channel = 0)
component RoleState {
    fsm_ticks: u32 = 0,
    task_hits: u32 = 0,
    tl_hits: u32 = 0,
}

event SrvPing { val: u32 }

obs on_srv_ping(trg: &Trigger<SrvPing>, vault: &mut res SrvVault) {
    let ev = trg.payload;
    vault.obs_hits += ev.val;
}

@sparse
timeline SrvTl @rate(60_hz) @duration(4_f) {
    at 1_f => trigger(self, SrvPing { val: 5_u32 });
}

fsm SrvFsm @require(RoleState) {
    initial Active;
    state Active {
        on_tick {
            for r in query(rs: &mut RoleState) {
                r.rs.fsm_ticks += 1_u32;
            }
        }
        to Active when false;
    }
}

@sparse
task SrvTask()
on (rs: &mut RoleState) {
    rs.task_hits += 1_u32;
    yield_tick;
    rs.task_hits += 1_u32;
}

object Hero {
    RoleState { fsm_ticks: 0, task_hits: 0, tl_hits: 0 },
}

@authority(server)
sys kick_srv() {
    for e in query(rs: &mut RoleState) {
        if e.rs.tl_hits == 0_u32 {
            e.rs.tl_hits = 1_u32;
            insert @if_new(e.id, SrvTask::start());
            insert @if_new(e.id, SrvTl::start());
            insert @if_new(e.id, SrvFsm::start());
        }
    }
}

schedule FixedUpdate { kick_srv }

net_sim_test "server_only_obs_fsm_task_tl_and_srv_res_not_overwritten"(latency: 16ms, jitter: 0ms, loss: 0.0, seed: 3, clients: 1) {
    // Stepping client alone must NOT execute server-only fsm/obs/task/timeline.
    client_step(0, 4);
    let cli_rs0 = client_query(0, rs: &RoleState).on(Hero).unwrap().rs;
    assert_eq(cli_rs0.fsm_ticks, 0_u32);
    assert_eq(cli_rs0.task_hits, 0_u32);
    assert_eq(client_res<SrvVault>(0).obs_hits, 0_u32);

    // Client tampering `@authority(server)` resource must NOT overwrite server authority.
    client_res<SrvVault>(0).gold = 9999_u32;
    step_net(6);
    assert_eq(server_res<SrvVault>().gold, 100_u32);
    assert(server_query(rs: &RoleState).on(Hero).unwrap().rs.fsm_ticks >= 4_u32);
    assert_eq(server_query(rs: &RoleState).on(Hero).unwrap().rs.task_hits, 2_u32);
    assert_eq(server_res<SrvVault>().obs_hits, 5_u32);
    assert_converged();
    assert_eq(client_res<SrvVault>(0).gold, 100_u32);
}
"#,
    )
    .unwrap();

    let (rc, out) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "NT-02 test failed:\n{out}");
}

#[test]
fn nt_07_unreliable_monotonicity_dynamic_replication_and_late_join_baseline() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    // 1. Positive path: unreliable snapshot monotonicity under jitter + dynamic spawn/remove + late join baseline.
    let ok_path = tmp.path().join("nt07_ok.strata");
    fs::write(
        &ok_path,
        r#"
module test::nt07_ok @version(1.0.0);

@authority(server)
@net(unreliable, rate = 60Hz, channel = 1)
component Snap {
    seq: u32 = 0,
}

@authority(server)
@net(reliable, channel = 0)
component DynBadge {
    score: u32 = 0,
}

resource SpawnerCtl {
    remove_now: bool = false,
}

object Anchor {
    Snap { seq: 0 },
}

@authority(server)
sys tick_snap(ctl: &res SpawnerCtl) {
    for s in query(sn: &mut Snap) {
        if s.sn.seq < 20_u32 {
            s.sn.seq += 1_u32;
        }
    }
    if ctl.remove_now {
        for d in query(b: &DynBadge) {
            despawn(d.id);
        }
    }
}

schedule FixedUpdate { tick_snap }

net_sim_test "unreliable_monotonic_and_late_join_and_dynamic_cleanup"(latency: 30ms, jitter: 25ms, loss: 0.2, seed: 7, clients: 1) {
    let mut prev: u32 = 0_u32;
    let mut i: i32 = 0;
    while i < 20 {
        step_net(1);
        let cur = client_query(0, sn: &Snap).on(Anchor).unwrap().sn.seq;
        assert(cur >= prev);
        prev = cur;
        i += 1;
    }

    // Dynamic server spawn replicates to clients after channel drains.
    let _dyn_ent = server_spawn(DynBadge { score: 77_u32 });
    step_net(10);
    assert_converged();

    // Late-joining client 1 receives baseline state snapshot cleanly.
    spawn_client(1);
    step_net(10);
    assert_converged(1);

    // Dynamic despawn on server replicates removal to all clients.
    server_res<SpawnerCtl>().remove_now = true;
    step_net(12);
    assert_converged();
}
"#,
    )
    .unwrap();

    let (rc_ok, out_ok) = cmd_test(&ok_path, OutputFormat::Json);
    assert_eq!(rc_ok, EXIT_OK, "NT-07 positive test failed:\n{out_ok}");

    // 2. Negative path: un-replicated dynamic spawn before latency must fail `assert_converged()`.
    let fail_path = tmp.path().join("nt07_missing_dyn.strata");
    fs::write(
        &fail_path,
        r#"
module test::nt07_fail @version(1.0.0);

@authority(server)
@net(reliable, channel = 0)
component DynOnly {
    v: u32 = 0,
}

net_sim_test "unreplicated_dynamic_spawn_detected"(latency: 60ms, jitter: 0ms, loss: 0.0, seed: 1, clients: 1) {
    let _e = server_spawn(DynOnly { v: 12_u32 });
    step_net(1);
    assert_converged();
}
"#,
    )
    .unwrap();
    let (rc_fail, out_fail) = cmd_test(&fail_path, OutputFormat::Json);
    assert_eq!(
        rc_fail, EXIT_SIM_TEST_FAILED,
        "expected unreplicated dynamic spawn to fail assert_converged: {out_fail}"
    );
}

#[test]
fn nt_09_wide_quantize_bounds_converge_headlessly() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();

    // 1. Overflow-safe `send_rpc` wide quantize/dequantize with [-1e308, 1e308].
    let rpc_wide_path = tmp.path().join("nt09_rpc_wide.strata");
    fs::write(
        &rpc_wide_path,
        r#"
module test::nt09_rpc_wide @version(1.0.0);

@authority(server)
resource WideRpcOut {
    got_val: f64 = -1.0,
    calls: u32 = 0,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc WideRpc {
    @quantize(min = -1.0e308, max = 1.0e308, bits = 16)
    val: f64,
}

obs on_wide_rpc(trg: &Trigger<WideRpc>, out: &mut res WideRpcOut) {
    let p = trg.payload;
    out.got_val = p.val;
    out.calls += 1_u32;
}

net_sim_test "wide_quantize_rpc_remains_finite_and_accurate"(latency: 16ms, jitter: 0ms, loss: 0.0, seed: 1, clients: 1) {
    send_rpc(0, WideRpc { val: 1.0e307_f64 });
    step_net(5);
    assert_eq(server_res<WideRpcOut>().calls, 1_u32);
    let got = server_res<WideRpcOut>().got_val;
    assert(got == got);
}
"#,
    )
    .unwrap();
    let (rc_ok, out_ok) = cmd_test(&rpc_wide_path, OutputFormat::Json);
    assert_eq!(rc_ok, EXIT_OK, "NT-09 wide RPC quantize failed:\n{out_ok}");

    // 2. Non-finite 1-bit step tolerance on [-1e308, 1e308] must fail mismatch instead of passing `+Inf`.
    let mismatch_path = tmp.path().join("nt09_inf_tol.strata");
    fs::write(
        &mismatch_path,
        r#"
module test::nt09_inf_tol @version(1.0.0);

@authority(server)
@net(unreliable, channel = 0)
component WideOneBit {
    @quantize(min = -1.0e308, max = 1.0e308, bits = 1)
    val: f64 = 0.0,
}

object Anchor {
    WideOneBit { val: 0.0 },
}

@authority(server)
sys mutate_wide() {
    for w in query(wb: &mut WideOneBit) {
        w.wb.val = 1234.5;
    }
}

schedule FixedUpdate { mutate_wide }

net_sim_test "infinite_step_tol_must_not_mask_mismatch"(latency: 0ms, jitter: 0ms, loss: 1.0, seed: 1, clients: 1) {
    step_net(2);
    assert_converged();
}
"#,
    )
    .unwrap();
    let (rc_fail, out_fail) = cmd_test(&mismatch_path, OutputFormat::Json);
    assert_eq!(
        rc_fail, EXIT_SIM_TEST_FAILED,
        "non-finite effective_step tolerance must not pass mismatched assert_converged: {out_fail}"
    );
}

#[test]
fn nt_10_composite_rpc_and_packet_kind_rpc_runtime_dispatch() {
    let _test_guard = NET_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("nt10_rpc.strata");
    fs::write(
        &p,
        r#"
module test::nt10_rpc @version(1.0.0);

struct PayloadMeta {
    tier: u32 = 0,
    label: InlineStr<16> = "init",
}

@authority(server)
@net(reliable, channel = 0)
resource RpcAudit {
    calls: u32 = 0,
    last_val: u32 = 0,
}

@authority(server)
@net(reliable, channel = 0)
component ActorState {
    meta: PayloadMeta = PayloadMeta { tier: 0, label: "init" },
    codes: [u32; 3] = [0, 0, 0],
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc PingRpc {
    val: u32,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc ComplexCmd {
    meta: PayloadMeta,
    codes: [u32; 3],
}

object Hero {
    ActorState {
        meta: PayloadMeta { tier: 0, label: "init" },
        codes: [0, 0, 0],
    },
}

obs on_ping_rpc(trg: &Trigger<PingRpc>, audit: &mut res RpcAudit) {
    let p = trg.payload;
    audit.calls += 1_u32;
    audit.last_val = p.val;
    for a in query(st: &mut ActorState) {
        a.st.meta.tier = p.val;
    }
}

net_sim_test "composite_rpc_dispatches_to_obs_and_converges"(latency: 16ms, jitter: 0ms, loss: 0.0, seed: 9, clients: 1) {
    send_rpc(0, PingRpc { val: 42_u32 });
    send_rpc(0, ComplexCmd {
        meta: PayloadMeta { tier: 7_u32, label: "alpha" },
        codes: [10_u32, 20_u32, 30_u32],
    });
    let dyn_hero = server_spawn(ActorState {
        meta: PayloadMeta { tier: 7_u32, label: "alpha" },
        codes: [10_u32, 20_u32, 30_u32],
    });
    if let Some(h) = server_query(st: &mut ActorState).on(Hero) {
        h.st.meta = PayloadMeta { tier: 3_u32, label: "bravo" };
        h.st.codes = [1_u32, 2_u32, 3_u32];
    }
    step_net(6);
    assert_eq(server_res<RpcAudit>().calls, 1_u32);
    assert_eq(server_res<RpcAudit>().last_val, 42_u32);
    assert_converged();
    let cli_hero = client_query(0, st: &ActorState).on(Hero).unwrap().st;
    assert_eq(cli_hero.meta.tier, 42_u32);
    assert_eq(cli_hero.meta.label, "bravo");
    assert_eq(cli_hero.codes[2], 3_u32);
    let cli_dyn = client_query(0, st: &ActorState).on(dyn_hero);
    assert(cli_dyn.is_none() == false);
    assert_eq(cli_dyn.unwrap().st.meta.label, "alpha");
    assert_eq(cli_dyn.unwrap().st.codes[1], 20_u32);
}
"#,
    )
    .unwrap();

    let (rc, out) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "NT-10a/c test failed:\n{out}");
}
