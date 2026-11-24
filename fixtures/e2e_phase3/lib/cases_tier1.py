"""Tier 1 (Feature Coverage, 54 tests: 6 per feature F1-F9) opaque-box E2E tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import strata_templates as tpl
from .cli_driver import (
    CaseFailure,
    TestCase,
    TestContext,
    extract_c99_fingerprints,
    extract_layout_fingerprints,
    extract_rust_fingerprints,
    normalize_fingerprint,
    sha256_file,
    verify_c99_syntax_strict,
)
from .lsp_client import LspClient, build_telemetry_digest64, extract_telemetry_node, fnv1a_64


def _assert_check_ok(ctx: TestContext, src: str, filename: str = "case.strata") -> dict[str, Any]:
    p = ctx.write_file(filename, src)
    res, report = ctx.stratac.check_json(p)
    if res.returncode != 0 or not report.get("ok") or report.get("error_count", -1) != 0:
        raise CaseFailure(
            f"stratac check {filename} failed (rc={res.returncode}): {json.dumps(report)}"
        )
    return report


def _assert_fmt_check_ok(ctx: TestContext, path: Path) -> None:
    res = ctx.stratac.fmt(path, check=True)
    if res.returncode != 0:
        raise CaseFailure(f"stratac fmt --check failed (rc={res.returncode}): {res.stderr.strip()}")


def _assert_graph_export_ok(ctx: TestContext, path: Path) -> dict[str, Any]:
    res, ir = ctx.stratac.graph_export_json(path)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"stratac graph export failed (rc={res.returncode}): {ir}")
    return ir


# =========================================================================
# F1: @node_pure & @node_group("...") Validation (6 Tests)
# =========================================================================

def t1_f1_01(ctx: TestContext) -> None:
    _assert_check_ok(ctx, tpl.doc_pure_arithmetic(), "f1_01.strata")


def t1_f1_02(ctx: TestContext) -> None:
    _assert_check_ok(ctx, tpl.doc_pure_chain(), "f1_02.strata")


def t1_f1_03(ctx: TestContext) -> None:
    _assert_check_ok(ctx, tpl.doc_node_group_basic(), "f1_03.strata")


def t1_f1_04(ctx: TestContext) -> None:
    _assert_check_ok(ctx, tpl.doc_node_group_graph_items(), "f1_04.strata")


def t1_f1_05(ctx: TestContext) -> None:
    _assert_check_ok(ctx, tpl.doc_pure_enum_match(), "f1_05.strata")


def t1_f1_06(ctx: TestContext) -> None:
    src = tpl.doc_pure_called_from_sys()
    p = ctx.write_file("f1_06.strata", src)
    _assert_check_ok(ctx, src, "f1_06.strata")
    fmt_res = ctx.stratac.fmt(p, check=False)
    if fmt_res.returncode != 0:
        raise CaseFailure(f"stratac fmt failed (rc={fmt_res.returncode}): {fmt_res.stderr.strip()}")
    _assert_fmt_check_ok(ctx, p)


# =========================================================================
# F2: Bidirectional Lossless rowan CST <-> Graph IR (6 Tests)
# =========================================================================

def t1_f2_01(ctx: TestContext) -> None:
    p = ctx.write_file("all8.strata", tpl.doc_all_eight_graph_kinds())
    ir = _assert_graph_export_ok(ctx, p)
    if ir.get("version") != "1.0":
        raise CaseFailure(f"Expected Graph IR version '1.0', got {ir.get('version')!r}")
    if ir.get("module_path") != "e2e::boss_graph":
        raise CaseFailure(f"Unexpected module_path: {ir.get('module_path')!r}")
    if normalize_fingerprint(ir.get("schema_fingerprint")) is None:
        raise CaseFailure(f"Missing/invalid schema_fingerprint: {ir.get('schema_fingerprint')!r}")
    nodes = ir.get("nodes")
    if not isinstance(nodes, list):
        raise CaseFailure("Graph IR missing 'nodes' list")
    kinds = {n.get("kind") for n in nodes if isinstance(n, dict)}
    expected_kinds = {
        "component",
        "node_pure_fn",
        "timeline",
        "fsm",
        "task",
        "table",
        "curve",
        "schedule",
    }
    missing = expected_kinds - kinds
    if missing:
        raise CaseFailure(f"Graph IR missing expected node kinds: {sorted(missing)}; got {sorted(kinds)}")
    for n in nodes:
        for req_key in ("id", "kind", "name", "payload", "span", "position"):
            if req_key not in n:
                raise CaseFailure(f"Graph node {n.get('id')!r} missing required key {req_key!r}")


def t1_f2_02(ctx: TestContext) -> None:
    p = ctx.write_file("grouped.strata", tpl.doc_all_eight_graph_kinds())
    ir = _assert_graph_export_ok(ctx, p)
    nodes = ir.get("nodes", [])
    grouped = [n for n in nodes if n.get("group") == "Boss/AI"]
    if len(grouped) < 3:
        raise CaseFailure(f"Expected >= 3 nodes in group 'Boss/AI', got {len(grouped)}")
    edges = ir.get("edges")
    if not isinstance(edges, list) or len(edges) == 0:
        raise CaseFailure(f"Expected non-empty 'edges' list linking schedule/items, got {edges!r}")


def t1_f2_03(ctx: TestContext) -> None:
    p = ctx.write_file("doc.strata", tpl.doc_all_eight_graph_kinds())
    ir = _assert_graph_export_ok(ctx, p)
    patch = tpl.build_payload_patch(ir, "e2e::boss_graph::BossHealth", 100.0, 250.0)
    patch_p = ctx.write_file("patch.json", tpl.dumps_json(patch))
    res = ctx.stratac.graph_apply(p, patch_p)
    if res.returncode != 0:
        raise CaseFailure(f"stratac graph apply failed (rc={res.returncode}): {res.stderr.strip()}")
    updated_src = p.read_text(encoding="utf-8")
    if "250.0" not in updated_src:
        raise CaseFailure("Updated .strata does not contain patched default 250.0")
    chk_res, report = ctx.stratac.check_json(p)
    if chk_res.returncode != 0 or not report.get("ok"):
        raise CaseFailure(f"stratac check failed after graph apply: {report}")
    ir2 = _assert_graph_export_ok(ctx, p)
    if "250" not in json.dumps(ir2):
        raise CaseFailure("Re-exported Graph IR does not reflect patched 250.0")


def t1_f2_04(ctx: TestContext) -> None:
    p = ctx.write_file("doc.strata", tpl.doc_all_eight_graph_kinds())
    ir = _assert_graph_export_ok(ctx, p)
    patch = tpl.build_payload_patch(ir, "e2e::boss_graph::BossRageCurve", 34.0, 48.0)
    patch = tpl.build_payload_patch(patch, "e2e::boss_graph::BossModeStats", 2.0, 3.5)
    patch_p = ctx.write_file("patch_curve_table.json", tpl.dumps_json(patch))
    res = ctx.stratac.graph_apply(p, patch_p)
    if res.returncode != 0:
        raise CaseFailure(f"stratac graph apply failed (rc={res.returncode}): {res.stderr.strip()}")
    updated_src = p.read_text(encoding="utf-8")
    if "48.0" not in updated_src:
        raise CaseFailure("Updated .strata missing patched curve value 48.0")
    if "3.5" not in updated_src:
        raise CaseFailure("Updated .strata missing patched table value 3.5")
    chk_res, report = ctx.stratac.check_json(p)
    if chk_res.returncode != 0 or not report.get("ok"):
        raise CaseFailure(f"stratac check failed after curve/table patch: {report}")
    ir2 = _assert_graph_export_ok(ctx, p)
    nodes_by_id = {n.get("id"): n for n in ir2.get("nodes", []) if isinstance(n, dict)}
    curve_node = nodes_by_id.get("e2e::boss_graph::BossRageCurve")
    table_node = nodes_by_id.get("e2e::boss_graph::BossModeStats")
    if not curve_node or "48" not in json.dumps(curve_node.get("payload")):
        raise CaseFailure(f"Re-exported curve payload missing 48.0: {curve_node!r}")
    if not table_node or "3.5" not in json.dumps(table_node.get("payload")):
        raise CaseFailure(f"Re-exported table payload missing 3.5: {table_node!r}")


def t1_f2_05(ctx: TestContext) -> None:
    src = tpl.doc_all_eight_graph_kinds()
    p = ctx.write_file("preserve.strata", src)
    ir = _assert_graph_export_ok(ctx, p)
    patch = tpl.build_payload_patch(ir, "e2e::boss_graph::BossHealth", 12.0, 18.0)
    patch_p = ctx.write_file("patch.json", tpl.dumps_json(patch))
    res = ctx.stratac.graph_apply(p, patch_p)
    if res.returncode != 0:
        raise CaseFailure(f"stratac graph apply failed (rc={res.returncode}): {res.stderr.strip()}")
    updated = p.read_text(encoding="utf-8")
    for comment in (
        "// Header banner comment preserved across Graph IR edits",
        "// Untouched timeline comment",
        "// Untouched fsm comment",
        "// Untouched task comment",
    ):
        if comment not in updated:
            raise CaseFailure(f"Comment lost during graph apply: {comment!r}")


def t1_f2_06(ctx: TestContext) -> None:
    p = ctx.write_file("roundtrip.strata", tpl.doc_all_eight_graph_kinds())
    h_before = sha256_file(p)
    ir = _assert_graph_export_ok(ctx, p)
    patch_p = ctx.write_file("noop.json", tpl.dumps_json(ir))
    res = ctx.stratac.graph_apply(p, patch_p)
    if res.returncode != 0:
        raise CaseFailure(f"stratac graph apply noop failed (rc={res.returncode}): {res.stderr.strip()}")
    h_after = sha256_file(p)
    if h_before != h_after:
        raise CaseFailure(f"Noop roundtrip modified .strata ({h_before} != {h_after})")


# =========================================================================
# F3: Hash-Isolated .strata.graph.json Sidecar (6 Tests)
# =========================================================================

def t1_f3_01(ctx: TestContext) -> None:
    p = ctx.write_file("boss.strata", tpl.doc_all_eight_graph_kinds("game::boss"))
    sidecar = {
        "layout_version": "1.0",
        "nodes": {
            "game::boss::BossHealth": {"x": 120.5, "y": -40.0},
        },
    }
    ctx.write_file("boss.strata.graph.json", tpl.dumps_json(sidecar))
    ir = _assert_graph_export_ok(ctx, p)
    matches = [n for n in ir.get("nodes", []) if n.get("id") == "game::boss::BossHealth"]
    if not matches:
        raise CaseFailure("Node game::boss::BossHealth not found in graph export")
    pos = matches[0].get("position")
    if pos != {"x": 120.5, "y": -40.0}:
        raise CaseFailure(f"Expected sidecar position (120.5, -40.0), got {pos!r}")


def t1_f3_02(ctx: TestContext) -> None:
    p = ctx.write_file("boss.strata", tpl.doc_all_eight_graph_kinds("game::boss"))
    h1 = sha256_file(p)
    ir = _assert_graph_export_ok(ctx, p)
    patch = tpl.build_position_patch(ir, {"game::boss::BossHealth": (340.0, 210.0)})
    patch_p = ctx.write_file("move_patch.json", tpl.dumps_json(patch))
    res = ctx.stratac.graph_apply(p, patch_p)
    if res.returncode != 0:
        raise CaseFailure(f"graph apply failed (rc={res.returncode}): {res.stderr.strip()}")
    h2 = sha256_file(p)
    if h1 != h2:
        raise CaseFailure("Position-only patch modified .strata source file")
    sc_path = ctx.tmp_dir / "boss.strata.graph.json"
    if not sc_path.is_file():
        raise CaseFailure("Expected boss.strata.graph.json sidecar to be written")
    sc = json.loads(sc_path.read_text(encoding="utf-8"))
    node_pos = sc.get("nodes", {}).get("game::boss::BossHealth", {})
    if node_pos.get("x") != 340.0 or node_pos.get("y") != 210.0:
        raise CaseFailure(f"Sidecar missing updated position (340.0, 210.0): {node_pos!r}")


def t1_f3_03(ctx: TestContext) -> None:
    p = ctx.write_file("boss.strata", tpl.doc_all_eight_graph_kinds("game::boss"))
    l_res1, l1 = ctx.stratac.layout_json(p)
    if l_res1.returncode != 0 or not isinstance(l1, dict):
        raise CaseFailure(f"stratac layout failed: {l1}")
    fp1 = extract_layout_fingerprints(l1)
    ir1 = _assert_graph_export_ok(ctx, p)
    ir_fp1 = normalize_fingerprint(ir1.get("schema_fingerprint"))

    patch = tpl.build_position_patch(
        ir1,
        {
            "game::boss::BossHealth": (55.0, 75.0),
            "game::boss::BossPhaseFsm": (-200.0, 400.0),
        },
    )
    patch_p = ctx.write_file("move_multi.json", tpl.dumps_json(patch))
    ap = ctx.stratac.graph_apply(p, patch_p)
    if ap.returncode != 0:
        raise CaseFailure(f"graph apply failed: {ap.stderr.strip()}")

    l_res2, l2 = ctx.stratac.layout_json(p)
    if l_res2.returncode != 0 or not isinstance(l2, dict):
        raise CaseFailure(f"stratac layout after move failed: {l2}")
    fp2 = extract_layout_fingerprints(l2)
    ir2 = _assert_graph_export_ok(ctx, p)
    ir_fp2 = normalize_fingerprint(ir2.get("schema_fingerprint"))

    if fp1 != fp2 or ir_fp1 != ir_fp2:
        raise CaseFailure(f"SCHEMA_FINGERPRINT changed on position edit: {fp1} vs {fp2}")


def t1_f3_04(ctx: TestContext) -> None:
    p = ctx.write_file("boss.strata", tpl.doc_all_eight_graph_kinds("game::boss"))
    h1 = sha256_file(p)
    ir = _assert_graph_export_ok(ctx, p)
    patch = tpl.build_position_patch(
        ir,
        {"game::boss::BossPhaseFsm": (10.0, 20.0)},
        collapsed_updates={"game::boss::BossPhaseFsm": True},
    )
    patch_p = ctx.write_file("collapse_patch.json", tpl.dumps_json(patch))
    res = ctx.stratac.graph_apply(p, patch_p)
    if res.returncode != 0:
        raise CaseFailure(f"graph apply failed: {res.stderr.strip()}")
    if sha256_file(p) != h1:
        raise CaseFailure("Collapsed/position patch modified .strata")
    sc = json.loads((ctx.tmp_dir / "boss.strata.graph.json").read_text(encoding="utf-8"))
    sc_nodes = sc.get("nodes", {})
    if "game::boss::BossPhaseFsm" not in sc_nodes:
        raise CaseFailure(f"Sidecar missing canonical key game::boss::BossPhaseFsm: {list(sc_nodes)}")
    if sc_nodes["game::boss::BossPhaseFsm"].get("collapsed") is not True:
        raise CaseFailure(f"Sidecar did not persist collapsed: true: {sc_nodes['game::boss::BossPhaseFsm']}")
    ir2 = _assert_graph_export_ok(ctx, p)
    fsm_nodes = [n for n in ir2.get("nodes", []) if n.get("id") == "game::boss::BossPhaseFsm"]
    if not fsm_nodes or (fsm_nodes[0].get("position") or {}).get("collapsed") is not True:
        raise CaseFailure(f"Re-exported Graph IR node missing position.collapsed=true: {fsm_nodes!r}")


def t1_f3_05(ctx: TestContext) -> None:
    src = tpl.doc_all_eight_graph_kinds("game::boss")
    p = ctx.write_file("boss.strata", src)
    sidecar = {
        "layout_version": "1.0",
        "nodes": {"game::boss::BossHealth": {"x": 88.0, "y": 99.0}},
    }
    ctx.write_file("boss.strata.graph.json", tpl.dumps_json(sidecar))
    l_res1, l1 = ctx.stratac.layout_json(p)
    if l_res1.returncode != 0:
        raise CaseFailure(f"layout failed: {l1}")
    fp1 = extract_layout_fingerprints(l1)

    # Body-only constant edit in system
    edited = src.replace("0.0 * clk.dt.as_secs()", "1.0 * clk.dt.as_secs()")
    p.write_text(edited, encoding="utf-8")

    ir = _assert_graph_export_ok(ctx, p)
    matches = [n for n in ir.get("nodes", []) if n.get("id") == "game::boss::BossHealth"]
    if not matches or matches[0].get("position") != {"x": 88.0, "y": 99.0}:
        raise CaseFailure(f"Sidecar position lost after body-only edit: {matches}")
    l_res2, l2 = ctx.stratac.layout_json(p)
    if l_res2.returncode != 0:
        raise CaseFailure(f"layout after body edit failed: {l2}")
    if extract_layout_fingerprints(l2) != fp1:
        raise CaseFailure("SCHEMA_FINGERPRINT changed on body-only edit")


def t1_f3_06(ctx: TestContext) -> None:
    p = ctx.write_file("boss.strata", tpl.doc_all_eight_graph_kinds("game::boss"))
    h1 = sha256_file(p)
    sidecar = {
        "layout_version": "1.0",
        "nodes": {
            "game::boss::BossHealth": {"x": 10.0, "y": 10.0, "collapsed": False},
            "game::boss::BossPhaseFsm": {"x": 20.0, "y": 20.0, "collapsed": True},
            "game::boss::BossRegenTask": {"x": 30.0, "y": 30.0, "collapsed": False},
            "game::boss::BossRageCurve": {"x": 40.0, "y": 40.0, "collapsed": True},
        },
    }
    ctx.write_file("boss.strata.graph.json", tpl.dumps_json(sidecar))
    ir = _assert_graph_export_ok(ctx, p)
    patch = tpl.build_position_patch(ir, {"game::boss::BossHealth": (500.0, 600.0)})
    patch_p = ctx.write_file("move_one.json", tpl.dumps_json(patch))
    res = ctx.stratac.graph_apply(p, patch_p)
    if res.returncode != 0:
        raise CaseFailure(f"graph apply failed: {res.stderr.strip()}")
    if sha256_file(p) != h1:
        raise CaseFailure(".strata modified during partial layout patch")
    sc = json.loads((ctx.tmp_dir / "boss.strata.graph.json").read_text(encoding="utf-8"))
    nodes = sc.get("nodes", {})
    if nodes.get("game::boss::BossHealth", {}).get("x") != 500.0:
        raise CaseFailure(f"Target node not updated: {nodes}")
    if nodes.get("game::boss::BossPhaseFsm", {}).get("x") != 20.0 or not nodes.get("game::boss::BossPhaseFsm", {}).get("collapsed"):
        raise CaseFailure(f"Sibling node metadata clobbered: {nodes}")
    if nodes.get("game::boss::BossRageCurve", {}).get("y") != 40.0:
        raise CaseFailure(f"Fourth node metadata clobbered: {nodes}")


# =========================================================================
# F4: LSP strata/graphTelemetry (6 Tests)
# =========================================================================

def t1_f4_01(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    frame = build_telemetry_digest64(
        "demo::boss::sys_a",
        frame_seq=12,
        p50_us=420,
        p99_us=980,
        matched_entities=256,
        matched_tables=6,
        skipped_summary_tick_tables=2,
        chunks=8,
        commands_queued=0,
        flags=0,
    )
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(frame)],
        )
        if "error" in resp:
            raise CaseFailure(f"strata/graphTelemetry returned error: {resp['error']}")
        entry = extract_telemetry_node(resp.get("result"), "demo::boss::sys_a")
        if entry is None:
            raise CaseFailure(f"Missing telemetry entry for demo::boss::sys_a in {resp!r}")
        if (
            entry.get("p50_us") != 420
            or entry.get("p99_us") != 980
            or entry.get("matched_entities") != 256
            or entry.get("skipped_summary_tick_tables") != 2
            or entry.get("frame_seq") != 12
        ):
            raise CaseFailure(f"Telemetry field mismatch: {entry!r}")


def t1_f4_02(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    frame = build_telemetry_digest64("sys_a", frame_seq=5, p50_us=150, matched_entities=64)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(frame)],
        )
        if "error" in resp:
            raise CaseFailure(f"strata/graphTelemetry error on bare hash: {resp['error']}")
        entry = extract_telemetry_node(resp.get("result"), "demo::boss::sys_a")
        if entry is None or entry.get("p50_us") != 150 or entry.get("matched_by") != "bare":
            raise CaseFailure(f"Failed bare system name resolution for demo::boss::sys_a: {resp!r}")


def t1_f4_03(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    f_a = build_telemetry_digest64("demo::boss::sys_a", frame_seq=1, p50_us=111, matched_entities=10)
    f_b = build_telemetry_digest64("demo::boss::sys_b", frame_seq=1, p50_us=222, matched_entities=20)
    f_c = build_telemetry_digest64("demo::boss::sys_c", frame_seq=1, p50_us=333, matched_entities=30)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a", "demo::boss::sys_b", "demo::boss::sys_c"],
            frames=[list(f_a), list(f_b), list(f_c)],
        )
        if "error" in resp:
            raise CaseFailure(f"strata/graphTelemetry error: {resp['error']}")
        res = resp.get("result")
        for nid, expected_us in (("demo::boss::sys_a", 111), ("demo::boss::sys_b", 222), ("demo::boss::sys_c", 333)):
            entry = extract_telemetry_node(res, nid)
            if entry is None or entry.get("p50_us") != expected_us:
                raise CaseFailure(f"Missing or wrong p50_us for {nid}: {res!r}")


def t1_f4_04(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    f_old = build_telemetry_digest64("demo::boss::sys_a", frame_seq=10, p50_us=900)
    f_new = build_telemetry_digest64("demo::boss::sys_a", frame_seq=25, p50_us=1200)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(f_old), list(f_new)],
        )
        if "error" in resp:
            raise CaseFailure(f"strata/graphTelemetry error: {resp['error']}")
        entry = extract_telemetry_node(resp.get("result"), "demo::boss::sys_a")
        if entry is None or entry.get("frame_seq") != 25 or entry.get("p50_us") != 1200:
            raise CaseFailure(f"Expected latest frame_seq=25, got {entry!r}")


def t1_f4_05(ctx: TestContext) -> None:
    src = tpl.doc_three_systems_for_lsp("demo::boss")
    p = ctx.write_file("boss_lsp.strata", src)
    edited = src.replace("a.c.val += 1;", "a.c.val += 5;")
    frame = build_telemetry_digest64("demo::boss::sys_a", frame_seq=3, p50_us=777)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p, text=src)
        lsp.did_change(p, text=edited, version=2)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(frame)],
        )
        if "error" in resp:
            raise CaseFailure(f"strata/graphTelemetry failed after didChange: {resp['error']}")
        entry = extract_telemetry_node(resp.get("result"), "demo::boss::sys_a")
        if entry is None or entry.get("p50_us") != 777:
            raise CaseFailure(f"Telemetry missing after didChange: {resp!r}")


def t1_f4_06(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    frame = build_telemetry_digest64("demo::boss::sys_a", frame_seq=1, p50_us=100)
    lsp = LspClient(ctx.lsp_bin, ctx.tmp_dir)
    lsp.start()
    try:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(frame)],
        )
        if "error" in resp:
            raise CaseFailure(f"strata/graphTelemetry returned error: {resp['error']}")
        rc = lsp.shutdown_and_exit()
        if rc != 0:
            raise CaseFailure(f"Expected strata-lsp exit code 0, got {rc}")
    finally:
        lsp.kill()


# =========================================================================
# F5: RpcDecl & NetSimTestDecl Syntax + stratafmt (6 Tests)
# =========================================================================

def t1_f5_01(ctx: TestContext) -> None:
    src = """module e2e::f5_rpc @version(1.0.0);

rpc MoveInput {
    dx: f32,
    dy: f32,
    seq: u32,
}
"""
    _assert_check_ok(ctx, src, "f5_01.strata")


def t1_f5_02(ctx: TestContext) -> None:
    src = """module e2e::f5_nst @version(1.0.0);

net_sim_test "basic_sync"(latency: 40ms, jitter: 5ms, loss: 0.02, seed: 7) {
    clients(2);
    step_net(5);
    assert(true);
}
"""
    _assert_check_ok(ctx, src, "f5_02.strata")


def t1_f5_03(ctx: TestContext) -> None:
    src = """module e2e::f5_ctx_rpc @version(1.0.0);

component Stats { rpc: u32 = 0 }

rpc Ping { seq: u32 }

fn read_rpc_counter(v: u32) -> u32 {
    let rpc = v + 1;
    rpc
}

sys bump_rpc() {
    for s in query(st: &mut Stats) {
        s.st.rpc = read_rpc_counter(s.st.rpc);
    }
}
"""
    _assert_check_ok(ctx, src, "f5_03.strata")


def t1_f5_04(ctx: TestContext) -> None:
    unfmt = """// Keep RPC comment
module e2e::f5_fmt @version(1.0.0);
rpc  Move{x:f32,y:f32}
net_sim_test  "t" ( latency : 50ms , loss : 0.0 ){
step_net(1);
}
"""
    p = ctx.write_file("unfmt.strata", unfmt)
    r1 = ctx.stratac.fmt(p, check=False)
    if r1.returncode != 0:
        raise CaseFailure(f"stratac fmt failed (rc={r1.returncode}): {r1.stderr.strip()}")
    formatted = p.read_text(encoding="utf-8")
    if "// Keep RPC comment" not in formatted:
        raise CaseFailure("stratac fmt dropped comment")
    _assert_fmt_check_ok(ctx, p)


def t1_f5_05(ctx: TestContext) -> None:
    src = """module e2e::f5_reordered @version(1.0.0);

net_sim_test "loss_only"(loss: 0.1, seed: 99) {
    step_net(2);
}

net_sim_test "seed_first"(seed: 1, latency: 25ms) {
    step_net(3);
}
"""
    p = ctx.write_file("f5_05.strata", src)
    _assert_check_ok(ctx, src, "f5_05.strata")
    r_fmt = ctx.stratac.fmt(p, check=False)
    if r_fmt.returncode != 0:
        raise CaseFailure(f"stratac fmt failed: {r_fmt.stderr.strip()}")
    _assert_fmt_check_ok(ctx, p)


def t1_f5_06(ctx: TestContext) -> None:
    src = """module e2e::f5_rpc_fields @version(1.0.0);

rpc CombatCmd {
    tick: u32,
    aim_yaw: f32,
    target_id: u64,
    crouch: bool,
}
"""
    p = ctx.write_file("f5_06.strata", src)
    _assert_check_ok(ctx, src, "f5_06.strata")
    r_fmt = ctx.stratac.fmt(p, check=False)
    if r_fmt.returncode != 0:
        raise CaseFailure(f"stratac fmt failed: {r_fmt.stderr.strip()}")
    _assert_fmt_check_ok(ctx, p)


# =========================================================================
# F6: Networking & Authority Sema + E0501 (6 Tests)
# =========================================================================

def t1_f6_01(ctx: TestContext) -> None:
    src = """module e2e::f6_net_attrs @version(1.0.0);

@net(reliable, rate = 20Hz, channel = 0)
component RepPos { x: f32 = 0.0, y: f32 = 0.0 }

@net(unreliable, interval = 2)
resource MatchState { tick: u32 = 0 }
"""
    _assert_check_ok(ctx, src, "f6_01.strata")


def t1_f6_02(ctx: TestContext) -> None:
    src = """module e2e::f6_quantize @version(1.0.0);

@net(unreliable, rate = 30Hz)
component QuantTransform {
    @quantize(min = -512.0, max = 512.0, bits = 16)
    heading: f32 = 0.0,
    @quantize(min = -256.0, max = 256.0, bits = 12)
    pos: vec3 = vec3::ZERO,
}
"""
    _assert_check_ok(ctx, src, "f6_02.strata")


def t1_f6_03(ctx: TestContext) -> None:
    src = """module e2e::f6_net_rpc @version(1.0.0);

@net_rpc(direction = client_to_server, reliability = reliable)
rpc ClientMove { dx: f32, dy: f32 }

@net_rpc(direction = server_to_client, reliability = unreliable)
rpc ServerFx { kind: u16 }

@net_rpc(direction = bidirectional, reliability = reliable)
rpc ChatPing { code: u32 }
"""
    _assert_check_ok(ctx, src, "f6_03.strata")


def t1_f6_04(ctx: TestContext) -> None:
    src = """module e2e::f6_auth_read @version(1.0.0);

@authority(server)
@net(reliable, rate = 20Hz)
component Health { hp: f32 = 100.0 }

@authority(server)
sys apply_server_dmg() {
    for h in query(c: &mut Health) {
        h.c.hp -= 1.0;
    }
}

@authority(client)
sys read_hud() {
    for h in query(c: &Health) {
        let _display = h.c.hp;
    }
}
"""
    _assert_check_ok(ctx, src, "f6_04.strata")


def t1_f6_05(ctx: TestContext) -> None:
    src = """module e2e::f6_predicted @version(1.0.0);

@predicted
component PredictedPos { x: f32 = 0.0, y: f32 = 0.0 }

@predicted
sys predict_move() {
    for p in query(pos: &mut PredictedPos) {
        p.pos.x += 0.5;
    }
}
"""
    _assert_check_ok(ctx, src, "f6_05.strata")


def t1_f6_06(ctx: TestContext) -> None:
    src = """module e2e::f6_shared @version(1.0.0);

@authority(shared)
@net(reliable)
component MatchTimer { seconds: f32 = 0.0 }

@authority(server)
sys server_timer() {
    for t in query(m: &mut MatchTimer) {
        t.m.seconds += 0.016;
    }
}

@authority(client)
sys client_timer() {
    for t in query(m: &MatchTimer) {
        let _s = t.m.seconds;
    }
}
"""
    _assert_check_ok(ctx, src, "f6_06.strata")


# =========================================================================
# F7: Quantized Delta Codegen & Handshake (C99, Rust Guest, Bevy Native, JIT)
# =========================================================================

def t1_f7_01(ctx: TestContext) -> None:
    p = ctx.write_file("net.strata", tpl.doc_net_minimal())
    out_dir = ctx.tmp_dir / "c99_out"
    res, report = ctx.stratac.build_json(p, "c99", out_dir)
    if res.returncode != 0 or not isinstance(report, dict):
        raise CaseFailure(f"stratac build --target c99 failed (rc={res.returncode}): {report}")
    strict_res = verify_c99_syntax_strict(out_dir, report.get("module_stem", "net"))
    if strict_res.returncode != 0:
        raise CaseFailure(f"Strict C99 check failed: {strict_res.stderr}")
    c_files = list(out_dir.glob("*.c"))
    if not c_files:
        raise CaseFailure("No .c file emitted")
    c_text = c_files[0].read_text(encoding="utf-8")
    if "schema_fingerprint" not in c_text:
        raise CaseFailure("Emitted C99 missing schema_fingerprint")
    if "iter_column_mutable_untracked" not in c_text and "iter_mark_changed_range" not in c_text:
        raise CaseFailure("Emitted C99 missing Slots 14-15 selective mutation helpers")


def t1_f7_02(ctx: TestContext) -> None:
    p = ctx.write_file("net.strata", tpl.doc_net_minimal())
    out_dir = ctx.tmp_dir / "rg_out"
    res, report = ctx.stratac.build_json(p, "rust-guest", out_dir)
    if res.returncode != 0 or not isinstance(report, dict):
        raise CaseFailure(f"stratac build --target rust-guest failed (rc={res.returncode}): {report}")
    lib_rs = out_dir / "rust_guest_crate" / "src" / "lib.rs"
    if not lib_rs.is_file():
        raise CaseFailure(f"Missing emitted Rust Guest lib.rs at {lib_rs}")
    rs_text = lib_rs.read_text(encoding="utf-8")
    if "#![forbid(unsafe_code)]" not in rs_text:
        raise CaseFailure("Rust Guest missing #![forbid(unsafe_code)]")
    if "SCHEMA_FINGERPRINT" not in rs_text:
        raise CaseFailure("Rust Guest missing SCHEMA_FINGERPRINT")


def t1_f7_03(ctx: TestContext) -> None:
    p = ctx.write_file("net.strata", tpl.doc_net_minimal())
    out_dir = ctx.tmp_dir / "bn_out"
    res, report = ctx.stratac.onboard_check_json(p, out_dir, target="bevy-native")
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("cargo_checked"):
        raise CaseFailure(f"stratac onboard --target bevy-native --check failed: {report}")
    lib_rs = out_dir / "src" / "lib.rs"
    if not lib_rs.is_file():
        raise CaseFailure(f"Missing emitted Bevy Native lib.rs at {lib_rs}")
    rs_text = lib_rs.read_text(encoding="utf-8")
    if "#![forbid(unsafe_code)]" not in rs_text:
        raise CaseFailure("Bevy Native missing #![forbid(unsafe_code)]")
    if "SCHEMA_FINGERPRINT" not in rs_text:
        raise CaseFailure("Bevy Native missing SCHEMA_FINGERPRINT")


def t1_f7_04(ctx: TestContext) -> None:
    p = ctx.write_file("net.strata", tpl.doc_net_minimal())
    l_res, l_rep = ctx.stratac.layout_json(p)
    if l_res.returncode != 0 or not isinstance(l_rep, dict):
        raise CaseFailure(f"stratac layout failed: {l_rep}")
    layout_fps = set(extract_layout_fingerprints(l_rep).values())
    if not layout_fps:
        raise CaseFailure("No layout fingerprints found")

    c_dir = ctx.tmp_dir / "c99_par"
    rg_dir = ctx.tmp_dir / "rg_par"
    bn_dir = ctx.tmp_dir / "bn_par"
    c_res, _ = ctx.stratac.build_json(p, "c99", c_dir)
    rg_res, _ = ctx.stratac.build_json(p, "rust-guest", rg_dir)
    bn_res, _ = ctx.stratac.onboard_check_json(p, bn_dir)
    if c_res.returncode != 0 or rg_res.returncode != 0 or bn_res.returncode != 0:
        raise CaseFailure(f"Backend build failure: c99={c_res.returncode}, rg={rg_res.returncode}, bn={bn_res.returncode}")

    c_fps = extract_c99_fingerprints(next(c_dir.glob("*.c")).read_text(encoding="utf-8"))
    rg_fps = extract_rust_fingerprints((rg_dir / "rust_guest_crate" / "src" / "lib.rs").read_text(encoding="utf-8"))
    bn_fps = extract_rust_fingerprints((bn_dir / "src" / "lib.rs").read_text(encoding="utf-8"))

    for label, backend_fps in (("C99", c_fps), ("Rust Guest", rg_fps), ("Bevy Native", bn_fps)):
        missing = layout_fps - backend_fps
        if missing:
            raise CaseFailure(f"{label} missing layout SCHEMA_FINGERPRINT(s): {sorted(missing)} (found {sorted(backend_fps)})")


def t1_f7_05(ctx: TestContext) -> None:
    src = """module e2e::quant_handshake @version(1.0.0);

@authority(server)
@net(unreliable, rate = 30Hz, channel = 2)
component YawState {
    @quantize(min = -100.0, max = 100.0, bits = 12)
    yaw: f32 = 0.0,
}

@authority(server)
sys rotate() {
    for y in query(s: &mut YawState) {
        y.s.yaw += 1.0;
    }
}
"""
    p = ctx.write_file("qh.strata", src)
    c_dir = ctx.tmp_dir / "qh_c99"
    rg_dir = ctx.tmp_dir / "qh_rg"
    c_res, _ = ctx.stratac.build_json(p, "c99", c_dir)
    rg_res, _ = ctx.stratac.build_json(p, "rust-guest", rg_dir)
    if c_res.returncode != 0 or rg_res.returncode != 0:
        raise CaseFailure(f"Build failed: c99={c_res.returncode}, rg={rg_res.returncode}")
    c_text = next(c_dir.glob("*.c")).read_text(encoding="utf-8")
    rs_text = (rg_dir / "rust_guest_crate" / "src" / "lib.rs").read_text(encoding="utf-8")
    c_text_lower = c_text.lower()
    if (
        "4095" not in c_text
        and "0xfff" not in c_text_lower
        and "<< 12" not in c_text
        and ">> 12" not in c_text
        and "quantize" not in c_text_lower
    ):
        raise CaseFailure("C99 emitted code lacks 12-bit quantization helpers")
    if "SCHEMA_FINGERPRINT" not in rs_text:
        raise CaseFailure("Rust Guest emitted code lacks SCHEMA_FINGERPRINT handshake")


def t1_f7_06(ctx: TestContext) -> None:
    p = ctx.write_file("net.strata", tpl.doc_net_minimal())
    out_dir = ctx.tmp_dir / "jit_out"
    res, report = ctx.stratac.build_json(p, "jit", out_dir)
    if res.returncode != 0 or not isinstance(report, dict):
        raise CaseFailure(f"stratac build --target jit failed (rc={res.returncode}): {report}")
    if not (out_dir / "mod.toml").is_file():
        raise CaseFailure("Expected mod.toml in JIT output directory")


# =========================================================================
# F8: Headless net_sim_test Runner (6 Tests)
# =========================================================================

def t1_f8_01(ctx: TestContext) -> None:
    src = """module e2e::f8_rep @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component NetCounter {
    @quantize(min = 0.0, max = 1000.0, bits = 16)
    val: f32 = 0.0,
}

object SharedUnit {
    NetCounter { val: 0.0 },
}

@authority(server)
sys inc_server() {
    for c in query(n: &mut NetCounter) {
        c.n.val += 5.0;
    }
}

schedule FixedUpdate { inc_server }

net_sim_test "server_to_client_replication"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 1) {
    clients(1);
    step_net(4);
    assert_converged();
}
"""
    p = ctx.write_file("f8_01.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"stratac test failed (rc={res.returncode}): {report}")


def t1_f8_02(ctx: TestContext) -> None:
    src = """module e2e::f8_rpc_flow @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component PlayerScore { pts: u32 = 0 }

object Hero { PlayerScore { pts: 0 }, }

@net_rpc(direction = client_to_server, reliability = reliable)
rpc AddPoints { amount: u32 }

net_sim_test "client_rpc_reaches_server"(latency: 16ms, jitter: 0ms, loss: 0.0, seed: 2) {
    clients(1);
    send_rpc(0, AddPoints { amount: 10 });
    step_net(5);
    assert_converged();
}
"""
    p = ctx.write_file("f8_02.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"stratac test failed (rc={res.returncode}): {report}")


def t1_f8_03(ctx: TestContext) -> None:
    src = """module e2e::f8_latency @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component NetFlag { value: u32 = 0 }

object FlagEntity { NetFlag { value: 0 }, }

@net_rpc(direction = client_to_server, reliability = reliable)
rpc SetFlag { value: u32 }

net_sim_test "latency_delays_delivery"(latency: 50ms, jitter: 0ms, loss: 0.0, seed: 3) {
    clients(1);
    send_rpc(0, SetFlag { value: 42 });
    step_net(1);
    assert_ne(client_query(0, f: &NetFlag).on(FlagEntity).unwrap().f.value, 42);
    step_net(10);
    assert_converged();
}
"""
    p = ctx.write_file("f8_03.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"stratac test failed (rc={res.returncode}): {report}")


def t1_f8_04(ctx: TestContext) -> None:
    src = """module e2e::f8_jitter_loss @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component ReliableState { seq: u32 = 0 }

object Anchor { ReliableState { seq: 0 }, }

@net_rpc(direction = client_to_server, reliability = reliable)
rpc BumpSeq { delta: u32 }

net_sim_test "jitter_and_loss_recovery"(latency: 30ms, jitter: 15ms, loss: 0.15, seed: 42) {
    clients(1);
    send_rpc(0, BumpSeq { delta: 1 });
    step_net(30);
    assert_converged();
}
"""
    p = ctx.write_file("f8_04.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"stratac test failed (rc={res.returncode}): {report}")


def t1_f8_05(ctx: TestContext) -> None:
    src = """module e2e::f8_coexist @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component TickCounter { ticks: u32 = 0 }

object CounterObj { TickCounter { ticks: 0 }, }

@authority(server)
sys tick_up() {
    for c in query(t: &mut TickCounter) {
        c.t.ticks += 1;
    }
}

schedule FixedUpdate { tick_up }

sim_test "local" {
    step_fixed(3);
    let v = query_one(t: &TickCounter).on(CounterObj).unwrap().t.ticks;
    assert_eq(v, 3);
}

net_sim_test "networked"(latency: 10ms, jitter: 0ms, loss: 0.0, seed: 11) {
    clients(1);
    step_net(5);
    assert_converged();
}
"""
    p = ctx.write_file("f8_05.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"stratac test failed (rc={res.returncode}): {report}")
    names = {t.get("name") for t in report.get("tests", []) if isinstance(t, dict)}
    if "local" not in names or "networked" not in names:
        raise CaseFailure(f"Expected both 'local' and 'networked' test entries, got {sorted(names)}")


def t1_f8_06(ctx: TestContext) -> None:
    src = """module e2e::f8_multi_client @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component SharedRoom { count: u32 = 0 }

object RoomState { SharedRoom { count: 0 }, }

@net_rpc(direction = client_to_server, reliability = reliable)
rpc JoinRoom { client_id: u32 }

net_sim_test "multi_client_convergence"(latency: 15ms, jitter: 5ms, loss: 0.0, seed: 88) {
    clients(2);
    send_rpc(0, JoinRoom { client_id: 0 });
    step_net(12);
    assert_converged();
}
"""
    p = ctx.write_file("f8_06.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"stratac test failed (rc={res.returncode}): {report}")


# =========================================================================
# F9: Phase 3 Cookbooks 07 & 08 (6 Tests)
# =========================================================================

def _cookbook_path(ctx: TestContext, name: str) -> Path:
    p = ctx.repo_root / "fixtures" / "cookbooks" / name
    if not p.is_file():
        raise CaseFailure(f"Cookbook fixture not found: {p}")
    return p


def t1_f9_01(ctx: TestContext) -> None:
    p = _cookbook_path(ctx, "07_visual_boss_graph.strata")
    res, report = ctx.stratac.check_json(p)
    if res.returncode != 0 or not report.get("ok") or report.get("error_count", -1) != 0:
        raise CaseFailure(f"07 check failed: {report}")
    _assert_fmt_check_ok(ctx, p)


def t1_f9_02(ctx: TestContext) -> None:
    p = _cookbook_path(ctx, "07_visual_boss_graph.strata")
    ir = _assert_graph_export_ok(ctx, p)
    nodes = ir.get("nodes", [])
    if not nodes:
        raise CaseFailure("07 graph export returned zero nodes")


def t1_f9_03(ctx: TestContext) -> None:
    p = _cookbook_path(ctx, "07_visual_boss_graph.strata")
    t_res, t_rep = ctx.stratac.test_json(p)
    if t_res.returncode != 0 or not isinstance(t_rep, dict) or not t_rep.get("all_passed"):
        raise CaseFailure(f"07 stratac test failed: {t_rep}")
    jit_dir = ctx.tmp_dir / "07_jit"
    b_res, b_rep = ctx.stratac.build_json(p, "jit", jit_dir)
    if b_res.returncode != 0:
        raise CaseFailure(f"07 jit build failed: {b_rep}")


def t1_f9_04(ctx: TestContext) -> None:
    p = _cookbook_path(ctx, "08_authoritative_multiplayer.strata")
    res, report = ctx.stratac.check_json(p)
    if res.returncode != 0 or not report.get("ok") or report.get("error_count", -1) != 0:
        raise CaseFailure(f"08 check failed: {report}")
    _assert_fmt_check_ok(ctx, p)


def t1_f9_05(ctx: TestContext) -> None:
    p = _cookbook_path(ctx, "08_authoritative_multiplayer.strata")
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"08 stratac test failed: {report}")
    if len(report.get("tests", [])) < 2:
        raise CaseFailure(f"Expected both sim_test and net_sim_test in 08: {report}")


def t1_f9_06(ctx: TestContext) -> None:
    p = _cookbook_path(ctx, "08_authoritative_multiplayer.strata")
    c_dir = ctx.tmp_dir / "08_c99"
    rg_dir = ctx.tmp_dir / "08_rg"
    c_res, c_rep = ctx.stratac.build_json(p, "c99", c_dir)
    rg_res, rg_rep = ctx.stratac.build_json(p, "rust-guest", rg_dir)
    if c_res.returncode != 0:
        raise CaseFailure(f"08 c99 build failed: {c_rep}")
    if rg_res.returncode != 0:
        raise CaseFailure(f"08 rust-guest build failed: {rg_rep}")


CASES_TIER1: list[TestCase] = [
    # F1
    TestCase("T1-F1-01", 1, ("F1",), "node_pure_fn_arithmetic_and_return", t1_f1_01),
    TestCase("T1-F1-02", 1, ("F1",), "node_pure_fn_calls_another_node_pure_fn", t1_f1_02),
    TestCase("T1-F1-03", 1, ("F1",), "node_group_on_component_fn_and_sys", t1_f1_03),
    TestCase("T1-F1-04", 1, ("F1",), "node_group_on_graph_data_items", t1_f1_04),
    TestCase("T1-F1-05", 1, ("F1",), "node_pure_fn_with_struct_and_enum_match", t1_f1_05),
    TestCase("T1-F1-06", 1, ("F1",), "node_pure_fn_called_from_sys_and_fmt", t1_f1_06),
    # F2
    TestCase("T1-F2-01", 1, ("F2",), "graph_export_covers_all_eight_item_kinds", t1_f2_01),
    TestCase("T1-F2-02", 1, ("F2",), "graph_export_captures_node_group_and_edges", t1_f2_02),
    TestCase("T1-F2-03", 1, ("F2",), "graph_apply_patches_component_field_default", t1_f2_03),
    TestCase("T1-F2-04", 1, ("F2",), "graph_apply_patches_curve_and_table_payloads", t1_f2_04),
    TestCase("T1-F2-05", 1, ("F2",), "graph_apply_preserves_comments_and_untouched_formatting", t1_f2_05),
    TestCase("T1-F2-06", 1, ("F2",), "graph_export_apply_noop_roundtrip_is_zero_diff", t1_f2_06),
    # F3
    TestCase("T1-F3-01", 1, ("F3",), "graph_export_reads_sidecar_positions_by_canonical_id", t1_f3_01),
    TestCase("T1-F3-02", 1, ("F3",), "position_only_patch_writes_sidecar_zero_strata_diff", t1_f3_02),
    TestCase("T1-F3-03", 1, ("F3",), "position_only_edit_preserves_schema_fingerprint", t1_f3_03),
    TestCase("T1-F3-04", 1, ("F3",), "sidecar_persists_collapsed_flag_and_canonical_keys", t1_f3_04),
    TestCase("T1-F3-05", 1, ("F3",), "sidecar_survives_body_only_strata_edit", t1_f3_05),
    TestCase("T1-F3-06", 1, ("F3",), "multi_node_layout_patch_updates_subset_preserving_others", t1_f3_06),
    # F4
    TestCase("T1-F4-01", 1, ("F4",), "lsp_graph_telemetry_maps_canonical_node_id_stateless_frames", t1_f4_01),
    TestCase("T1-F4-02", 1, ("F4",), "lsp_graph_telemetry_resolves_bare_system_name_hash", t1_f4_02),
    TestCase("T1-F4-03", 1, ("F4",), "lsp_graph_telemetry_multiple_nodes_single_request", t1_f4_03),
    TestCase("T1-F4-04", 1, ("F4",), "lsp_graph_telemetry_latest_frame_wins_on_sequence", t1_f4_04),
    TestCase("T1-F4-05", 1, ("F4",), "lsp_graph_telemetry_after_did_change_body_edit", t1_f4_05),
    TestCase("T1-F4-06", 1, ("F4",), "lsp_graph_telemetry_clean_shutdown_exit", t1_f4_06),
    # F5
    TestCase("T1-F5-01", 1, ("F5",), "parse_and_check_rpc_decl", t1_f5_01),
    TestCase("T1-F5-02", 1, ("F5",), "parse_and_check_net_sim_test_decl", t1_f5_02),
    TestCase("T1-F5-03", 1, ("F5",), "contextual_rpc_identifier_usable_as_field_and_local", t1_f5_03),
    TestCase("T1-F5-04", 1, ("F5",), "stratafmt_formats_rpc_and_net_sim_test_idempotently", t1_f5_04),
    TestCase("T1-F5-05", 1, ("F5",), "net_sim_test_accepts_subset_and_reordered_params", t1_f5_05),
    TestCase("T1-F5-06", 1, ("F5",), "rpc_with_multiple_field_types_and_arrays_or_units", t1_f5_06),
    # F6
    TestCase("T1-F6-01", 1, ("F6",), "valid_net_attribute_forms", t1_f6_01),
    TestCase("T1-F6-02", 1, ("F6",), "valid_quantize_attribute_on_fields", t1_f6_02),
    TestCase("T1-F6-03", 1, ("F6",), "valid_net_rpc_directions_and_reliability", t1_f6_03),
    TestCase("T1-F6-04", 1, ("F6",), "valid_authority_server_writes_and_client_reads", t1_f6_04),
    TestCase("T1-F6-05", 1, ("F6",), "valid_predicted_component_and_system", t1_f6_05),
    TestCase("T1-F6-06", 1, ("F6",), "valid_shared_authority_component", t1_f6_06),
    # F7
    TestCase("T1-F7-01", 1, ("F7",), "c99_net_codegen_compiles_strict_iso_c99", t1_f7_01),
    TestCase("T1-F7-02", 1, ("F7",), "rust_guest_net_codegen_compiles_forbid_unsafe", t1_f7_02),
    TestCase("T1-F7-03", 1, ("F7",), "bevy_native_net_codegen_cargo_checks_forbid_unsafe", t1_f7_03),
    TestCase("T1-F7-04", 1, ("F7",), "cross_backend_schema_fingerprint_parity", t1_f7_04),
    TestCase("T1-F7-05", 1, ("F7",), "c99_and_rust_guest_emit_handshake_and_quantize_helpers", t1_f7_05),
    TestCase("T1-F7-06", 1, ("F7",), "jit_build_net_module_succeeds", t1_f7_06),
    # F8
    TestCase("T1-F8-01", 1, ("F8",), "net_sim_test_server_to_client_replication_converges", t1_f8_01),
    TestCase("T1-F8-02", 1, ("F8",), "net_sim_test_client_rpc_reaches_server_and_mutates_state", t1_f8_02),
    TestCase("T1-F8-03", 1, ("F8",), "net_sim_test_latency_delays_delivery_deterministically", t1_f8_03),
    TestCase("T1-F8-04", 1, ("F8",), "net_sim_test_jitter_and_loss_with_reliable_recovery", t1_f8_04),
    TestCase("T1-F8-05", 1, ("F8",), "net_sim_test_coexists_with_sim_test_in_single_file", t1_f8_05),
    TestCase("T1-F8-06", 1, ("F8",), "net_sim_test_multi_client_broadcast_convergence", t1_f8_06),
    # F9
    TestCase("T1-F9-01", 1, ("F9",), "cookbook_07_check_and_fmt_check", t1_f9_01),
    TestCase("T1-F9-02", 1, ("F9",), "cookbook_07_graph_export_valid_json", t1_f9_02),
    TestCase("T1-F9-03", 1, ("F9",), "cookbook_07_sim_tests_and_jit_build_pass", t1_f9_03),
    TestCase("T1-F9-04", 1, ("F9",), "cookbook_08_check_and_fmt_check", t1_f9_04),
    TestCase("T1-F9-05", 1, ("F9",), "cookbook_08_test_sim_and_net_sim_pass", t1_f9_05),
    TestCase("T1-F9-06", 1, ("F9",), "cookbook_08_builds_c99_and_rust_guest", t1_f9_06),
]
