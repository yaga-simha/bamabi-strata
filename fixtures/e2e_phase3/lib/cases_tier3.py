"""Tier 3 (Cross-Feature Pairwise, 10 tests: T3-01 .. T3-10) opaque-box E2E tests."""

from __future__ import annotations

import copy
import json

from . import strata_templates as tpl
from .cli_driver import (
    CaseFailure,
    TestCase,
    TestContext,
    extract_c99_fingerprints,
    extract_layout_fingerprints,
    extract_rust_fingerprints,
    replace_json_scalar,
    verify_c99_syntax_strict,
)
from .lsp_client import LspClient, build_telemetry_digest64, extract_telemetry_node


def t3_01(ctx: TestContext) -> None:
    src = """module e2e::t3_01 @version(1.0.0);

@node_group("AI/Phase1")
component PhaseState { mult: f32 = 1.5 }

@node_group("AI/Phase1")
@node_pure
fn compute_score(base: f32) -> f32 {
    base * 2.0
}
"""
    p = ctx.write_file("t3_01.strata", src)
    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export failed: {ir}")
    nodes = ir.get("nodes", [])
    pure_nodes = [n for n in nodes if n.get("kind") == "node_pure_fn"]
    if not pure_nodes or pure_nodes[0].get("group") != "AI/Phase1":
        raise CaseFailure(f"Expected node_pure_fn with group 'AI/Phase1', got {nodes}")

    patch = tpl.build_payload_patch(ir, "e2e::t3_01::PhaseState", 1.5, 3.25)
    patch_p = ctx.write_file("t3_01_patch.json", tpl.dumps_json(patch))
    ap = ctx.stratac.graph_apply(p, patch_p)
    if ap.returncode != 0:
        raise CaseFailure(f"graph apply failed: {ap.stderr.strip()}")
    text = p.read_text(encoding="utf-8")
    if "@node_pure" not in text or '@node_group("AI/Phase1")' not in text or "3.25" not in text:
        raise CaseFailure("graph apply failed to preserve @node_pure/@node_group or update default")
    chk_res, rep = ctx.stratac.check_json(p)
    if chk_res.returncode != 0 or not rep.get("ok"):
        raise CaseFailure(f"check failed after roundtrip: {rep}")


def t3_02(ctx: TestContext) -> None:
    p = ctx.write_file("t3_02.strata", tpl.doc_all_eight_graph_kinds("e2e::mixed"))
    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export failed: {ir}")

    mixed = copy.deepcopy(ir)
    moved_ids = ("e2e::mixed::BossPhaseFsm", "e2e::mixed::BossRegenTask")
    for n in mixed.get("nodes", []):
        if n.get("id") == "e2e::mixed::BossHealth":
            new_pl, cnt = replace_json_scalar(n.get("payload"), 100.0, 222.0)
            if cnt == 0:
                raise CaseFailure(f"Failed to patch BossHealth payload: {n}")
            n["payload"] = new_pl
        if n.get("id") == moved_ids[0]:
            n["position"] = {"x": 111.0, "y": 222.0}
        if n.get("id") == moved_ids[1]:
            n["position"] = {"x": 333.0, "y": 444.0}

    patch_p = ctx.write_file("mixed_patch.json", tpl.dumps_json(mixed))
    ap = ctx.stratac.graph_apply(p, patch_p)
    if ap.returncode != 0:
        raise CaseFailure(f"graph apply failed: {ap.stderr.strip()}")
    text = p.read_text(encoding="utf-8")
    if "222.0" not in text or "// Untouched fsm comment" not in text:
        raise CaseFailure("Mixed patch did not preserve comments or update structural value")
    sc = json.loads((ctx.tmp_dir / "t3_02.strata.graph.json").read_text(encoding="utf-8"))
    if sc.get("nodes", {}).get(moved_ids[0], {}).get("x") != 111.0:
        raise CaseFailure(f"Sidecar missing moved position: {sc}")
    _, ir2 = ctx.stratac.graph_export_json(p)
    pos_map = {n["id"]: n["position"] for n in ir2.get("nodes", [])}
    if pos_map.get(moved_ids[1]) != {"x": 333.0, "y": 444.0}:
        raise CaseFailure(f"Re-exported Graph IR missing moved position: {pos_map}")


def t3_03(ctx: TestContext) -> None:
    p = ctx.write_file("t3_03.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    _, l1 = ctx.stratac.layout_json(p)
    fp1 = extract_layout_fingerprints(l1)
    sidecar = {
        "layout_version": "1.0",
        "nodes": {"demo::boss::sys_a": {"x": 777.0, "y": -125.0}},
    }
    ctx.write_file("t3_03.strata.graph.json", tpl.dumps_json(sidecar))
    _, l2 = ctx.stratac.layout_json(p)
    if extract_layout_fingerprints(l2) != fp1:
        raise CaseFailure("Layout fingerprint changed with sidecar")

    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export failed: {ir}")

    frame = build_telemetry_digest64("demo::boss::sys_a", frame_seq=17, p50_us=3456, matched_entities=99)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(frame)],
        )
        entry = extract_telemetry_node(resp.get("result"), "demo::boss::sys_a")
        if "error" in resp or not entry or entry.get("p50_us") != 3456:
            raise CaseFailure(f"LSP telemetry failed for moved sidecar node: {resp}")


def t3_04(ctx: TestContext) -> None:
    good_src = """module e2e::t3_04 @version(1.0.0);

@node_group("Net/Rep")
@authority(server)
@net(reliable, rate = 20Hz)
component RepHp { hp: f32 = 100.0 }

@node_group("Net/Rep")
@authority(server)
sys heal_server() {
    for r in query(h: &mut RepHp) {
        r.h.hp += 1.0;
    }
}
"""
    p_good = ctx.write_file("t3_04_good.strata", good_src)
    r_ok, rep_ok = ctx.stratac.check_json(p_good)
    if r_ok.returncode != 0 or not rep_ok.get("ok"):
        raise CaseFailure(f"Valid grouped @authority(server) check failed: {rep_ok}")

    bad_src = good_src + """
@node_group("Net/Rep")
@authority(client)
sys illegal_grouped_client() {
    for r in query(h: &mut RepHp) {
        r.h.hp = 999.0;
    }
}
"""
    p_bad = ctx.write_file("t3_04_bad.strata", bad_src)
    r_bad, rep_bad = ctx.stratac.check_json(p_bad)
    codes = [d.get("code") for d in rep_bad.get("diagnostics", [])]
    if r_bad.returncode != 1 or "E0501_AUTHORITY_VIOLATION" not in codes:
        raise CaseFailure(f"Expected E0501_AUTHORITY_VIOLATION on grouped client write, got rc={r_bad.returncode}, codes={codes}")


def t3_05(ctx: TestContext) -> None:
    valid_src = """module e2e::t3_05 @version(1.0.0);

@authority(server)
@net(reliable, rate = 30Hz)
component ServerPos { x: f32 = 0.0 }

@net_rpc(direction = client_to_server, reliability = reliable)
rpc MoveInput { dx: f32, dy: f32 }

@authority(server)
sys server_apply() {
    for p in query(s: &mut ServerPos) {
        p.s.x += 1.0;
    }
}

@authority(client)
sys client_sample() {
    for p in query(s: &ServerPos) {
        let _x = p.s.x;
    }
}
"""
    p = ctx.write_file("t3_05.strata", valid_src)
    res, rep = ctx.stratac.check_json(p)
    if res.returncode != 0 or not rep.get("ok"):
        raise CaseFailure(f"Valid RPC/authority check failed: {rep}")
    ctx.stratac.fmt(p, check=False)
    if ctx.stratac.fmt(p, check=True).returncode != 0:
        raise CaseFailure("fmt --check failed on valid RPC/authority doc")

    bad_src = valid_src + """
@authority(client)
sys client_cheat() {
    for p in query(s: &mut ServerPos) {
        p.s.x = 500.0;
    }
}
"""
    p_bad = ctx.write_file("t3_05_bad.strata", bad_src)
    r_bad, rep_bad = ctx.stratac.check_json(p_bad)
    codes = [d.get("code") for d in rep_bad.get("diagnostics", [])]
    if r_bad.returncode != 1 or "E0501_AUTHORITY_VIOLATION" not in codes:
        raise CaseFailure(f"Expected E0501_AUTHORITY_VIOLATION, got {codes}")


def t3_06(ctx: TestContext) -> None:
    src = """module e2e::t3_06 @version(1.0.0);

@authority(server)
@net(unreliable, rate = 30Hz, channel = 1)
component SyncState {
    @quantize(min = -256.0, max = 256.0, bits = 16)
    x: f32 = 0.0,
    dirty_flag: u32 = 0,
}

@authority(server)
sys sync_step() {
    for s in query(st: &mut? SyncState) {
        if s.st.dirty_flag != 0 {
            s.st.x += 0.5;
        }
    }
}
"""
    p = ctx.write_file("t3_06.strata", src)
    l_r, l_rep = ctx.stratac.layout_json(p)
    if l_r.returncode != 0 or not isinstance(l_rep, dict):
        raise CaseFailure(f"t3_06 layout failed: {l_rep}")
    layout_fps = set(extract_layout_fingerprints(l_rep).values())
    if not layout_fps:
        raise CaseFailure("No layout fingerprints extracted")

    c_dir = ctx.tmp_dir / "c99"
    rg_dir = ctx.tmp_dir / "rg"
    bn_dir = ctx.tmp_dir / "bn"
    c_res, c_rep = ctx.stratac.build_json(p, "c99", c_dir)
    if c_res.returncode != 0:
        raise CaseFailure(f"C99 build failed: {c_rep}")
    if verify_c99_syntax_strict(c_dir, c_rep.get("module_stem", "t3_06")).returncode != 0:
        raise CaseFailure("C99 strict syntax check failed")
    rg_res, rg_rep = ctx.stratac.build_json(p, "rust-guest", rg_dir)
    if rg_res.returncode != 0:
        raise CaseFailure(f"Rust Guest build failed: {rg_rep}")
    bn_res, bn_rep = ctx.stratac.onboard_check_json(p, bn_dir)
    if bn_res.returncode != 0 or not bn_rep.get("cargo_checked"):
        raise CaseFailure(f"Bevy Native check failed: {bn_rep}")

    c_fps = extract_c99_fingerprints(next(c_dir.glob("*.c")).read_text(encoding="utf-8"))
    rg_fps = extract_rust_fingerprints((rg_dir / "rust_guest_crate" / "src" / "lib.rs").read_text(encoding="utf-8"))
    bn_fps = extract_rust_fingerprints((bn_dir / "src" / "lib.rs").read_text(encoding="utf-8"))
    for name, fps in (("C99", c_fps), ("Rust Guest", rg_fps), ("Bevy Native", bn_fps)):
        if layout_fps - fps:
            raise CaseFailure(f"{name} fingerprint mismatch: expected {layout_fps}, got {fps}")


def t3_07(ctx: TestContext) -> None:
    src = """module e2e::t3_07 @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component QuantPos {
    @quantize(min = -100.0, max = 100.0, bits = 16)
    x: f32 = 0.0,
}

object Marker { QuantPos { x: 0.0 }, }

@authority(server)
sys set_target() {
    for q in query(p: &mut QuantPos) {
        q.p.x = 37.25;
    }
}

schedule FixedUpdate { set_target }

net_sim_test "quantized_replication_tolerance"(latency: 16ms, jitter: 0ms, loss: 0.0, seed: 12) {
    clients(1);
    step_net(5);
    assert_converged();
    let cx = client_query(0, p: &QuantPos).on(Marker).unwrap().p.x;
    let diff = cx - 37.25;
    assert(diff < 0.01 && diff > -0.01);
}
"""
    p = ctx.write_file("t3_07.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"Quantized net_sim_test failed: {report}")


def t3_08(ctx: TestContext) -> None:
    src = """module e2e::t3_08 @version(1.0.0);

component BossHp { hp: f32 = 100.0 }

@net_rpc(direction = client_to_server, reliability = reliable)
rpc TauntBoss { intensity: u32 }

fsm BossState {
    initial Calm;
    state Calm { to Angry when false; }
    state Angry { on_tick { } }
}

sys boss_noop() { }

schedule FixedUpdate {
    set Main { boss_noop, BossState }
}

net_sim_test "preserved_net_block"(latency: 10ms, jitter: 0ms, loss: 0.0, seed: 4) {
    clients(1);
    step_net(2);
    assert_converged();
}
"""
    p = ctx.write_file("t3_08.strata", src)
    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export failed: {ir}")
    patch = tpl.build_payload_patch(ir, "e2e::t3_08::BossHp", 100.0, 200.0)
    patch_p = ctx.write_file("t3_08_patch.json", tpl.dumps_json(patch))
    ap = ctx.stratac.graph_apply(p, patch_p)
    if ap.returncode != 0:
        raise CaseFailure(f"graph apply failed: {ap.stderr.strip()}")
    updated = p.read_text(encoding="utf-8")
    if "rpc TauntBoss { intensity: u32 }" not in updated or 'net_sim_test "preserved_net_block"' not in updated:
        raise CaseFailure("graph apply corrupted rpc or net_sim_test blocks")
    t_res, t_rep = ctx.stratac.test_json(p)
    if t_res.returncode != 0 or not isinstance(t_rep, dict) or not t_rep.get("all_passed"):
        raise CaseFailure(f"stratac test failed after graph apply: {t_rep}")


def t3_09(ctx: TestContext) -> None:
    cb = ctx.repo_root / "fixtures" / "cookbooks" / "07_visual_boss_graph.strata"
    if not cb.is_file():
        raise CaseFailure(f"Missing cookbook: {cb}")
    res, ir = ctx.stratac.graph_export_json(cb)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"07 graph export failed: {ir}")
    nodes = ir.get("nodes", [])
    if not nodes:
        raise CaseFailure("07 graph export returned zero nodes")
    target_id = nodes[0]["id"]
    frame = build_telemetry_digest64(target_id, frame_seq=42, p50_us=2026, matched_entities=16)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(cb)
        resp = lsp.graph_telemetry(
            cb.as_uri(),
            node_ids=[target_id],
            frames=[list(frame)],
        )
        entry = extract_telemetry_node(resp.get("result"), target_id)
        if "error" in resp or not entry or entry.get("p50_us") != 2026:
            raise CaseFailure(f"07 LSP graphTelemetry failed for {target_id}: {resp}")


def t3_10(ctx: TestContext) -> None:
    cb = ctx.repo_root / "fixtures" / "cookbooks" / "08_authoritative_multiplayer.strata"
    if not cb.is_file():
        raise CaseFailure(f"Missing cookbook: {cb}")
    _, l_rep = ctx.stratac.layout_json(cb)
    if not isinstance(l_rep, dict):
        raise CaseFailure(f"08 layout failed: {l_rep}")
    layout_fps = set(extract_layout_fingerprints(l_rep).values())
    if not layout_fps:
        raise CaseFailure("08 layout returned 0 fingerprints")

    c_dir = ctx.tmp_dir / "08_c99"
    rg_dir = ctx.tmp_dir / "08_rg"
    bn_dir = ctx.tmp_dir / "08_bn"
    c_res, _ = ctx.stratac.build_json(cb, "c99", c_dir)
    rg_res, _ = ctx.stratac.build_json(cb, "rust-guest", rg_dir)
    bn_res, bn_rep = ctx.stratac.onboard_check_json(cb, bn_dir)
    if c_res.returncode != 0 or rg_res.returncode != 0 or bn_res.returncode != 0 or not bn_rep.get("cargo_checked"):
        raise CaseFailure(f"08 backend build failed: c99={c_res.returncode}, rg={rg_res.returncode}, bn={bn_res.returncode}")

    c_fps = extract_c99_fingerprints(next(c_dir.glob("*.c")).read_text(encoding="utf-8"))
    rg_fps = extract_rust_fingerprints((rg_dir / "rust_guest_crate" / "src" / "lib.rs").read_text(encoding="utf-8"))
    bn_fps = extract_rust_fingerprints((bn_dir / "src" / "lib.rs").read_text(encoding="utf-8"))
    for label, fps in (("C99", c_fps), ("Rust Guest", rg_fps), ("Bevy Native", bn_fps)):
        if layout_fps - fps:
            raise CaseFailure(f"08 {label} missing SCHEMA_FINGERPRINT(s): {layout_fps - fps}")


CASES_TIER3: list[TestCase] = [
    TestCase("T3-01", 3, ("F1", "F2"), "node_pure_and_group_roundtrip_through_graph_ir", t3_01),
    TestCase("T3-02", 3, ("F2", "F3"), "mixed_structural_and_position_patch_isolates_diffs", t3_02),
    TestCase("T3-03", 3, ("F3", "F4"), "moved_sidecar_node_resolves_lsp_graph_telemetry", t3_03),
    TestCase("T3-04", 3, ("F1", "F6"), "node_group_combined_with_authority_and_net_attributes", t3_04),
    TestCase("T3-05", 3, ("F5", "F6"), "rpc_decl_authority_and_net_rpc_semantics", t3_05),
    TestCase("T3-06", 3, ("F6", "F7"), "quantize_and_selective_mut_lowered_across_three_backends", t3_06),
    TestCase("T3-07", 3, ("F7", "F8"), "quantized_delta_replication_executes_in_net_sim_test", t3_07),
    TestCase("T3-08", 3, ("F2", "F5"), "graph_export_apply_preserves_rpc_and_net_sim_test_blocks", t3_08),
    TestCase("T3-09", 3, ("F4", "F9"), "lsp_graph_telemetry_serves_cookbook_07_nodes", t3_09),
    TestCase("T3-10", 3, ("F7", "F9"), "cookbook_08_compiles_and_verifies_across_c99_rust_guest_bevy_native", t3_10),
]
