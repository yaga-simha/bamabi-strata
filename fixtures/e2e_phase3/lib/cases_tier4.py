"""Tier 4 (Real-World Multi-Feature E2E Workloads, 5 tests: T4-01 .. T4-05) opaque-box tests."""

from __future__ import annotations

import json

from . import strata_templates as tpl
from .cli_driver import (
    CaseFailure,
    TestCase,
    TestContext,
    extract_c99_fingerprints,
    extract_layout_fingerprints,
    extract_rust_fingerprints,
    has_fingerprint_handshake_check,
    sha256_file,
    verify_c99_syntax_strict,
)
from .lsp_client import LspClient, build_telemetry_digest64, extract_telemetry_node


def t4_01(ctx: TestContext) -> None:
    """Boss AI visual graph authoring lifecycle (F1, F2, F3, F4)."""
    src = tpl.doc_all_eight_graph_kinds("e2e::boss_ai") + """
object BossActor {
    BossHealth { hp: 100.0, armor: 12.0 },
}

sim_test "boss_ai_smoke" {
    step_fixed(2);
    let hp = query_one(h: &BossHealth).on(BossActor).unwrap().h.hp;
    assert(hp > 0.0);
}
"""
    p = ctx.write_file("boss_ai.strata", src)
    chk_res, chk_rep = ctx.stratac.check_json(p)
    if chk_res.returncode != 0 or not chk_rep.get("ok"):
        raise CaseFailure(f"Initial check failed: {chk_rep}")
    if ctx.stratac.fmt(p, check=False).returncode != 0 or ctx.stratac.fmt(p, check=True).returncode != 0:
        raise CaseFailure("Format / idempotent fmt --check failed")

    _, l0 = ctx.stratac.layout_json(p)
    fp0 = extract_layout_fingerprints(l0)

    g_res, ir = ctx.stratac.graph_export_json(p)
    if g_res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export failed: {ir}")
    kinds = {n.get("kind") for n in ir.get("nodes", [])}
    if len(kinds) < 8:
        raise CaseFailure(f"Expected all 8 graph node kinds, got {sorted(kinds)}")

    # Position-only patch: 0 .strata diff, same SCHEMA_FINGERPRINT
    h0 = sha256_file(p)
    pos_patch = tpl.build_position_patch(ir, {"e2e::boss_ai::BossHealth": (240.0, -80.0)})
    pos_patch_p = ctx.write_file("pos_patch.json", tpl.dumps_json(pos_patch))
    if ctx.stratac.graph_apply(p, pos_patch_p).returncode != 0:
        raise CaseFailure("Position-only graph apply failed")
    if sha256_file(p) != h0:
        raise CaseFailure("Position-only patch modified .strata")
    _, l1 = ctx.stratac.layout_json(p)
    if extract_layout_fingerprints(l1) != fp0:
        raise CaseFailure("Position-only patch changed SCHEMA_FINGERPRINT")

    # Structural patch: update BossHealth hp default to 300.0
    struct_patch = tpl.build_payload_patch(ir, "e2e::boss_ai::BossHealth", 100.0, 300.0)
    struct_patch_p = ctx.write_file("struct_patch.json", tpl.dumps_json(struct_patch))
    if ctx.stratac.graph_apply(p, struct_patch_p).returncode != 0:
        raise CaseFailure("Structural graph apply failed")
    updated = p.read_text(encoding="utf-8")
    if "300.0" not in updated or "// Header banner comment preserved across Graph IR edits" not in updated:
        raise CaseFailure("Structural patch did not apply cleanly or lost comments")
    t_res, t_rep = ctx.stratac.test_json(p)
    if t_res.returncode != 0 or not isinstance(t_rep, dict) or not t_rep.get("all_passed"):
        raise CaseFailure(f"sim_test failed after structural patch: {t_rep}")

    # Live LSP telemetry
    frame = build_telemetry_digest64("e2e::boss_ai::boss_update", frame_seq=50, p50_us=5120, matched_entities=1)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["e2e::boss_ai::boss_update"],
            frames=[list(frame)],
        )
        entry = extract_telemetry_node(resp.get("result"), "e2e::boss_ai::boss_update")
        if "error" in resp or not entry or entry.get("p50_us") != 5120:
            raise CaseFailure(f"LSP graphTelemetry failed: {resp}")


def t4_02(ctx: TestContext) -> None:
    """Authoritative multiplayer combat under loss and jitter (F5, F6, F7, F8)."""
    src = """module e2e::arena_combat @version(1.0.0);

@authority(server)
@net(unreliable, rate = 30Hz, channel = 1)
component FighterPos {
    @quantize(min = -256.0, max = 256.0, bits = 16)
    x: f32 = 0.0,
    @quantize(min = -256.0, max = 256.0, bits = 16)
    y: f32 = 0.0,
}

@authority(server)
@net(reliable, rate = 20Hz, channel = 0)
component FighterHealth {
    hp: f32 = 100.0,
    hit_pending: u32 = 0,
}

object ArenaFighter {
    FighterPos { x: 0.0, y: 0.0 },
    FighterHealth { hp: 100.0, hit_pending: 0 },
}

@net_rpc(direction = client_to_server, reliability = reliable)
rpc FireBolt {
    aim_x: f32,
    aim_y: f32,
    seq: u32,
}

@authority(server)
sys resolve_damage() {
    for f in query(h: &mut? FighterHealth) {
        if f.h.hit_pending != 0 {
            f.h.hp -= 25.0;
            f.h.hit_pending = 0;
        }
    }
}

schedule FixedUpdate { resolve_damage }

net_sim_test "combat_under_packet_loss"(latency: 60ms, jitter: 20ms, loss: 0.10, seed: 777) {
    clients(2);
    send_rpc(0, FireBolt { aim_x: 1.0, aim_y: 0.0, seq: 1 });
    step_net(35);
    assert_converged();
}
"""
    p = ctx.write_file("arena_combat.strata", src)
    ctx.stratac.fmt(p, check=False)
    if ctx.stratac.fmt(p, check=True).returncode != 0:
        raise CaseFailure("arena_combat fmt --check failed")
    chk_res, chk_rep = ctx.stratac.check_json(p)
    if chk_res.returncode != 0 or not chk_rep.get("ok"):
        raise CaseFailure(f"arena_combat check failed: {chk_rep}")

    l_r, l_rep = ctx.stratac.layout_json(p)
    if l_r.returncode != 0 or not isinstance(l_rep, dict):
        raise CaseFailure(f"arena_combat layout failed: {l_rep}")
    layout_fps = set(extract_layout_fingerprints(l_rep).values())
    if not layout_fps:
        raise CaseFailure("arena_combat layout returned 0 fingerprints")

    c_dir = ctx.tmp_dir / "c99"
    rg_dir = ctx.tmp_dir / "rg"
    bn_dir = ctx.tmp_dir / "bn"
    c_res, c_rep = ctx.stratac.build_json(p, "c99", c_dir)
    rg_res, rg_rep = ctx.stratac.build_json(p, "rust-guest", rg_dir)
    bn_res, bn_rep = ctx.stratac.onboard_check_json(p, bn_dir)
    if c_res.returncode != 0 or rg_res.returncode != 0 or bn_res.returncode != 0 or not bn_rep.get("cargo_checked"):
        raise CaseFailure(f"3-backend build failed: c99={c_res.returncode}, rg={rg_res.returncode}, bn={bn_res.returncode}")
    if verify_c99_syntax_strict(c_dir, c_rep.get("module_stem", "arena_combat")).returncode != 0:
        raise CaseFailure("C99 strict check failed")

    c_fps = extract_c99_fingerprints(next(c_dir.glob("*.c")).read_text(encoding="utf-8"))
    rg_fps = extract_rust_fingerprints((rg_dir / "rust_guest_crate" / "src" / "lib.rs").read_text(encoding="utf-8"))
    bn_fps = extract_rust_fingerprints((bn_dir / "src" / "lib.rs").read_text(encoding="utf-8"))
    for label, fps in (("C99", c_fps), ("Rust Guest", rg_fps), ("Bevy Native", bn_fps)):
        if layout_fps - fps:
            raise CaseFailure(f"{label} missing SCHEMA_FINGERPRINT(s): {layout_fps - fps}")

    t_res, t_rep = ctx.stratac.test_json(p)
    if t_res.returncode != 0 or not isinstance(t_rep, dict) or not t_rep.get("all_passed"):
        raise CaseFailure(f"arena_combat net_sim_test failed: {t_rep}")


def t4_03(ctx: TestContext) -> None:
    """Client prediction & server reconciliation with authority guard (F5, F6, F8)."""
    bad_src = """module e2e::pred_bad @version(1.0.0);

@authority(server)
@net(reliable, rate = 30Hz)
component AuthPos { x: f32 = 0.0 }

@authority(client)
sys naive_client_move() {
    for a in query(p: &mut AuthPos) {
        a.p.x += 1.0;
    }
}
"""
    p_bad = ctx.write_file("pred_bad.strata", bad_src)
    r_bad, rep_bad = ctx.stratac.check_json(p_bad)
    codes = [d.get("code") for d in rep_bad.get("diagnostics", [])]
    if r_bad.returncode != 1 or "E0501_AUTHORITY_VIOLATION" not in codes:
        raise CaseFailure(f"Expected E0501_AUTHORITY_VIOLATION on naive client write, got rc={r_bad.returncode}, codes={codes}")

    good_src = """module e2e::pred_reconcile @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component AuthPos { x: f32 = 0.0 }

@predicted
component ClientPredPos { x: f32 = 0.0 }

object PlayerEntity {
    AuthPos { x: 0.0 },
    ClientPredPos { x: 0.0 },
}

@net_rpc(direction = client_to_server, reliability = reliable)
rpc InputCmd { dx: f32, seq: u32 }

@predicted
sys predict_local() {
    for p in query(c: &mut ClientPredPos) {
        p.c.x += 0.0;
    }
}

@authority(client)
sys reconcile_to_auth() {
    for row in query(pred: &mut ClientPredPos, auth: &AuthPos) {
        row.pred.x = row.auth.x;
    }
}

schedule FixedUpdate { predict_local, reconcile_to_auth }

net_sim_test "predict_and_reconcile"(latency: 80ms, jitter: 15ms, loss: 0.05, seed: 2025) {
    clients(1);
    send_rpc(0, InputCmd { dx: 5.0, seq: 1 });
    step_net(30);
    assert_converged();
}
"""
    p_good = ctx.write_file("pred_good.strata", good_src)
    r_ok, rep_ok = ctx.stratac.check_json(p_good)
    if r_ok.returncode != 0 or not rep_ok.get("ok"):
        raise CaseFailure(f"Fixed predicted/reconcile check failed: {rep_ok}")
    t_res, t_rep = ctx.stratac.test_json(p_good)
    if t_res.returncode != 0 or not isinstance(t_rep, dict) or not t_rep.get("all_passed"):
        raise CaseFailure(f"Prediction net_sim_test failed: {t_rep}")


def t4_04(ctx: TestContext) -> None:
    """Schema version mismatch detection & handshake rejection (F3, F6, F7, F8)."""
    p1 = ctx.write_file("v1.strata", tpl.doc_net_v1_or_v2(False))
    p2 = ctx.write_file("v2.strata", tpl.doc_net_v1_or_v2(True))

    l1_r, l1 = ctx.stratac.layout_json(p1)
    l2_r, l2 = ctx.stratac.layout_json(p2)
    if l1_r.returncode != 0 or not isinstance(l1, dict):
        raise CaseFailure(f"v1 layout failed: {l1}")
    if l2_r.returncode != 0 or not isinstance(l2, dict):
        raise CaseFailure(f"v2 layout failed: {l2}")
    fp1 = next((v for k, v in extract_layout_fingerprints(l1).items() if k.endswith("::WirePose")), None)
    fp2 = next((v for k, v in extract_layout_fingerprints(l2).items() if k.endswith("::WirePose")), None)
    if not fp1 or not fp2 or fp1 == fp2:
        raise CaseFailure(f"Expected distinct v1 vs v2 fingerprints: {fp1} vs {fp2}")

    # Sidecar layout move on v1 preserves fp1
    g1_res, ir1 = ctx.stratac.graph_export_json(p1)
    if g1_res.returncode != 0 or not isinstance(ir1, dict):
        raise CaseFailure(f"v1 graph export failed: {ir1}")
    move_patch = tpl.build_position_patch(ir1, {"e2e::handshake_v1::WirePose": (450.0, -120.0)})
    move_p = ctx.write_file("v1_move.json", tpl.dumps_json(move_patch))
    if ctx.stratac.graph_apply(p1, move_p).returncode != 0:
        raise CaseFailure("v1 sidecar graph apply failed")
    _, l1_after = ctx.stratac.layout_json(p1)
    fp1_after = next((v for k, v in extract_layout_fingerprints(l1_after).items() if k.endswith("::WirePose")), None)
    if fp1_after != fp1:
        raise CaseFailure(f"v1 fingerprint mutated after sidecar position change: {fp1} -> {fp1_after}")

    # Build both across C99, Rust Guest, Bevy Native & verify distinct fingerprints + handshake checks
    for tag, src_p, expected_fp in (("v1", p1, fp1), ("v2", p2, fp2)):
        c_dir = ctx.tmp_dir / f"{tag}_c99"
        rg_dir = ctx.tmp_dir / f"{tag}_rg"
        bn_dir = ctx.tmp_dir / f"{tag}_bn"
        if ctx.stratac.build_json(src_p, "c99", c_dir)[0].returncode != 0:
            raise CaseFailure(f"{tag} C99 build failed")
        if ctx.stratac.build_json(src_p, "rust-guest", rg_dir)[0].returncode != 0:
            raise CaseFailure(f"{tag} Rust Guest build failed")
        bn_r, bn_rep = ctx.stratac.onboard_check_json(src_p, bn_dir)
        if bn_r.returncode != 0 or not bn_rep.get("cargo_checked"):
            raise CaseFailure(f"{tag} Bevy Native check failed")

        c_text = next(c_dir.glob("*.c")).read_text(encoding="utf-8")
        rs_text = (rg_dir / "rust_guest_crate" / "src" / "lib.rs").read_text(encoding="utf-8")
        bn_text = (bn_dir / "src" / "lib.rs").read_text(encoding="utf-8")
        if expected_fp not in extract_c99_fingerprints(c_text):
            raise CaseFailure(f"{tag} C99 missing expected fingerprint {expected_fp}")
        if expected_fp not in extract_rust_fingerprints(rs_text):
            raise CaseFailure(f"{tag} Rust Guest missing expected fingerprint {expected_fp}")
        if expected_fp not in extract_rust_fingerprints(bn_text):
            raise CaseFailure(f"{tag} Bevy Native missing expected fingerprint {expected_fp}")
        if not has_fingerprint_handshake_check(c_text, {expected_fp}):
            raise CaseFailure(f"{tag} C99 missing schema_fingerprint mismatch rejection check")
        if not has_fingerprint_handshake_check(rs_text, {expected_fp}):
            raise CaseFailure(f"{tag} Rust Guest missing schema_fingerprint mismatch rejection check")


def t4_05(ctx: TestContext) -> None:
    """Phase 3 cookbook 07 & 08 full production signoff (F1..F9)."""
    cb07 = ctx.copy_cookbook("07_visual_boss_graph.strata")
    cb08 = ctx.copy_cookbook("08_authoritative_multiplayer.strata")

    for cb in (cb07, cb08):
        if ctx.stratac.fmt(cb, check=True).returncode != 0:
            raise CaseFailure(f"{cb.name} fmt --check failed")
        chk_r, chk_rep = ctx.stratac.check_json(cb)
        if chk_r.returncode != 0 or not chk_rep.get("ok"):
            raise CaseFailure(f"{cb.name} check failed: {chk_rep}")
        l_r, l_rep = ctx.stratac.layout_json(cb)
        if l_r.returncode != 0 or not isinstance(l_rep, dict) or not l_rep.get("layouts"):
            raise CaseFailure(f"{cb.name} layout failed: {l_rep}")
        e_r, e_rep = ctx.stratac.explain_par_json(cb)
        if e_r.returncode != 0 or not isinstance(e_rep, dict):
            raise CaseFailure(f"{cb.name} explain-par failed: {e_rep}")
        t_r, t_rep = ctx.stratac.test_json(cb)
        if t_r.returncode != 0 or not isinstance(t_rep, dict) or not t_rep.get("all_passed"):
            raise CaseFailure(f"{cb.name} stratac test failed: {t_rep}")

    # 07: Graph export + isolated position patch + LSP telemetry
    h07 = sha256_file(cb07)
    g07_r, ir07 = ctx.stratac.graph_export_json(cb07)
    if g07_r.returncode != 0 or not isinstance(ir07, dict) or not ir07.get("nodes"):
        raise CaseFailure(f"07 graph export failed: {ir07}")
    first_id = ir07["nodes"][0]["id"]
    pos_patch = tpl.build_position_patch(ir07, {first_id: (123.0, 456.0)})
    patch_p = ctx.write_file("07_signoff_pos.json", tpl.dumps_json(pos_patch))
    if ctx.stratac.graph_apply(cb07, patch_p).returncode != 0:
        raise CaseFailure("07 graph apply position patch failed")
    if sha256_file(cb07) != h07:
        raise CaseFailure("07 position patch dirtied .strata")

    frame07 = build_telemetry_digest64(first_id, frame_seq=100, p50_us=1234, matched_entities=32)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(cb07)
        resp = lsp.graph_telemetry(cb07.as_uri(), node_ids=[first_id], frames=[list(frame07)])
        entry = extract_telemetry_node(resp.get("result"), first_id)
        if "error" in resp or not entry or entry.get("p50_us") != 1234:
            raise CaseFailure(f"07 LSP graphTelemetry failed: {resp}")

    # 08: All 4 targets (jit, c99, rust-guest, bevy-native)
    for target in ("jit", "c99", "rust-guest"):
        b_r, b_rep = ctx.stratac.build_json(cb08, target, ctx.tmp_dir / f"08_{target}")
        if b_r.returncode != 0:
            raise CaseFailure(f"08 build --target {target} failed: {b_rep}")
    bn_r, bn_rep = ctx.stratac.onboard_check_json(cb08, ctx.tmp_dir / "08_bn")
    if bn_r.returncode != 0 or not bn_rep.get("cargo_checked"):
        raise CaseFailure(f"08 onboard --target bevy-native --check failed: {bn_rep}")


CASES_TIER4: list[TestCase] = [
    TestCase("T4-01", 4, ("F1", "F2", "F3", "F4"), "boss_ai_visual_graph_authoring_lifecycle", t4_01),
    TestCase("T4-02", 4, ("F5", "F6", "F7", "F8"), "authoritative_multiplayer_combat_under_loss_and_jitter", t4_02),
    TestCase("T4-03", 4, ("F5", "F6", "F8"), "client_prediction_and_server_reconciliation_with_authority_guard", t4_03),
    TestCase("T4-04", 4, ("F3", "F6", "F7", "F8"), "schema_version_mismatch_detection_and_handshake_rejection", t4_04),
    TestCase("T4-05", 4, ("F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9"), "phase3_cookbook_07_and_08_full_production_signoff", t4_05),
]
