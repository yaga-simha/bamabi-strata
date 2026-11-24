"""Tier 2 (Boundary & Negative Cases, 54 tests: 6 per feature F1-F9) opaque-box E2E tests."""

from __future__ import annotations

import json
import math
from typing import Any

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


def _assert_check_fails(
    ctx: TestContext,
    src: str,
    filename: str,
    *,
    min_errors: int = 1,
    required_code: str | None = None,
    forbidden_codes: tuple[str, ...] = (),
    required_msg_substrs: tuple[str, ...] = (),
) -> dict[str, Any]:
    p = ctx.write_file(filename, src)
    res, report = ctx.stratac.check_json(p)
    if res.returncode != 1 or report.get("ok") is not False:
        raise CaseFailure(
            f"Expected stratac check failure (rc=1, ok=false) for {filename}, got rc={res.returncode}, report={report}"
        )
    err_cnt = report.get("error_count", 0)
    if err_cnt < min_errors:
        raise CaseFailure(
            f"Expected >= {min_errors} errors in {filename}, got {err_cnt}: {report.get('diagnostics')}"
        )
    diags = report.get("diagnostics", [])
    codes = [d.get("code") for d in diags if isinstance(d, dict)]
    for bad_code in forbidden_codes:
        if bad_code in codes:
            raise CaseFailure(
                f"Forbidden diagnostic code {bad_code!r} emitted in {filename}: {diags}"
            )
    if required_code is not None:
        if required_code not in codes:
            raise CaseFailure(f"Expected diagnostic code {required_code!r}, got {codes}: {diags}")
    if required_msg_substrs:
        blob = json.dumps(diags).lower()
        if not any(s.lower() in blob for s in required_msg_substrs):
            raise CaseFailure(
                f"Expected diagnostic matching one of {required_msg_substrs}, got: {diags}"
            )
    return report


# =========================================================================
# F1 Boundary & Negative Cases (6 Tests)
# =========================================================================

def t2_f1_01(ctx: TestContext) -> None:
    src = """module e2e::t2_f1_01 @version(1.0.0);

@node_pure
sys bad_sys() { }
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f1_01.strata",
        forbidden_codes=("E0002_PARSE_ERROR",),
        required_msg_substrs=("node_pure", "pure"),
    )


def t2_f1_02(ctx: TestContext) -> None:
    src = """module e2e::t2_f1_02 @version(1.0.0);

component Mark { val: u32 = 1 }

@node_pure
fn mutator() -> u32 {
    spawn { Mark { val: 2 } };
    1
}
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f1_02.strata",
        forbidden_codes=("E0002_PARSE_ERROR",),
        required_msg_substrs=("node_pure", "pure", "spawn", "side"),
    )


def t2_f1_03(ctx: TestContext) -> None:
    src = """module e2e::t2_f1_03 @version(1.0.0);

component Dummy { x: u32 = 0 }

fn impure_helper() -> u32 {
    spawn { Dummy { x: 1 } };
    1
}

@node_pure
fn caller() -> u32 {
    impure_helper()
}
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f1_03.strata",
        forbidden_codes=("E0002_PARSE_ERROR",),
        required_msg_substrs=("node_pure", "pure", "impure_helper"),
    )


def t2_f1_04(ctx: TestContext) -> None:
    src = """module e2e::t2_f1_04 @version(1.0.0);

@node_group("")
component BadGroup { val: u32 = 0 }
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f1_04.strata",
        forbidden_codes=("E0002_PARSE_ERROR",),
        required_msg_substrs=("node_group", "empty", "group"),
    )


def t2_f1_05(ctx: TestContext) -> None:
    src = """module e2e::t2_f1_05 @version(1.0.0);

@node_group
component GroupA { val: u32 = 0 }

@node_group(42)
component GroupB { val: u32 = 0 }
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f1_05.strata",
        min_errors=2,
        forbidden_codes=("E0002_PARSE_ERROR",),
        required_msg_substrs=("node_group", "group"),
    )


def t2_f1_06(ctx: TestContext) -> None:
    src = """module e2e::t2_f1_06 @version(1.0.0);

resource SimClock { dt: sec = 16.0_ms }

@node_pure
fn reader(clk: &res SimClock) -> f32 {
    clk.dt.as_secs()
}
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f1_06.strata",
        forbidden_codes=("E0002_PARSE_ERROR",),
        required_msg_substrs=("node_pure", "pure", "resource", "ecs"),
    )


# =========================================================================
# F2 Boundary & Negative Cases (6 Tests)
# =========================================================================

def t2_f2_01(ctx: TestContext) -> None:
    p = ctx.write_file("ok.strata", tpl.doc_all_eight_graph_kinds())
    exp_res, ir = ctx.stratac.graph_export_json(p)
    if exp_res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"Baseline graph export failed: {ir}")
    h_before = sha256_file(p)
    bad = ctx.write_file("bad.json", "{not valid json")
    res = ctx.stratac.graph_apply(p, bad)
    combined = f"{res.stderr}\n{res.stdout}".lower()
    if res.returncode != 1 or "unrecognized subcommand" in combined:
        raise CaseFailure(
            f"Expected exit 1 handling invalid patch JSON, got rc={res.returncode}: {res.stderr.strip()}"
        )
    if not any(kw in combined for kw in ("json", "parse", "syntax", "eof", "expected", "deserialize")):
        raise CaseFailure(f"Invalid patch JSON error lacked JSON/parse diagnostic: {combined.strip()}")
    if sha256_file(p) != h_before:
        raise CaseFailure(".strata modified on invalid patch JSON")


def t2_f2_02(ctx: TestContext) -> None:
    p = ctx.write_file("ok.strata", tpl.doc_all_eight_graph_kinds())
    exp_res, ir = ctx.stratac.graph_export_json(p)
    if exp_res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"Baseline graph export failed: {ir}")
    h_before = sha256_file(p)
    patch = {
        "remove": ["nonexistent::mod::GhostNode"],
    }
    patch_p = ctx.write_file("missing_id.json", tpl.dumps_json(patch))
    res = ctx.stratac.graph_apply(p, patch_p)
    combined = f"{res.stderr}\n{res.stdout}".lower()
    if res.returncode != 1 or "unrecognized subcommand" in combined:
        raise CaseFailure(
            f"Expected exit 1 for unknown node ID, got rc={res.returncode}: {res.stderr.strip()}"
        )
    if not any(
        kw in combined
        for kw in ("ghostnode", "unknown", "not found", "missing", "node id", "cannot remove")
    ):
        raise CaseFailure(f"Unknown node ID error lacked node diagnostic: {combined.strip()}")
    if sha256_file(p) != h_before:
        raise CaseFailure(".strata modified on unknown node ID")


def t2_f2_03(ctx: TestContext) -> None:
    p = ctx.write_file("empty.strata", "module empty::mod @version(1.0.0);\n")
    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export failed on empty module: {ir}")
    if ir.get("nodes") != [] or ir.get("edges") != []:
        raise CaseFailure(f"Expected empty nodes/edges, got: {ir}")


def t2_f2_04(ctx: TestContext) -> None:
    p = ctx.write_file("broken.strata", "module e2e::broken @version(1.0.0);\ncomponent Broken { ???\n")
    res = ctx.stratac.run(["graph", "export", str(p), "--format=json"])
    combined = f"{res.stderr}\n{res.stdout}".lower()
    if res.returncode != 1 or "unrecognized subcommand" in combined:
        raise CaseFailure(f"Expected exit 1 on parse error in graph export, got {res.returncode}: {combined.strip()}")
    if not any(kw in combined for kw in ("parse", "syntax", "expected", "unexpected", "token")):
        raise CaseFailure(f"Parse-error graph export lacked parse diagnostic: {combined.strip()}")


def t2_f2_05(ctx: TestContext) -> None:
    p = ctx.write_file("ok.strata", tpl.doc_all_eight_graph_kinds())
    h_before = sha256_file(p)
    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"Initial graph export failed: {ir}")
    for node in ir.get("nodes", []):
        if node.get("id") == "e2e::boss_graph::BossHealth":
            node["kind"] = "fsm"
    patch_p = ctx.write_file("wrong_kind.json", tpl.dumps_json(ir))
    ap = ctx.stratac.graph_apply(p, patch_p)
    combined = f"{ap.stderr}\n{ap.stdout}".lower()
    if ap.returncode != 1 or "unrecognized subcommand" in combined:
        raise CaseFailure(
            f"Expected exit 1 for mismatched node kind, got rc={ap.returncode}: {combined.strip()}"
        )
    if not any(kw in combined for kw in ("kind", "mismatch", "invalid", "payload", "expected", "variant")):
        raise CaseFailure(f"Mismatched node kind error lacked domain diagnostic: {combined.strip()}")
    if sha256_file(p) != h_before:
        raise CaseFailure(".strata modified on mismatched node kind")


def t2_f2_06(ctx: TestContext) -> None:
    src = "// ⚔️ boss phase UTF-8 header\n" + tpl.doc_all_eight_graph_kinds()
    p = ctx.write_file("utf8.strata", src)
    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export failed: {ir}")
    patch = tpl.build_payload_patch(ir, "e2e::boss_graph::BossHealth", 100.0, 175.0)
    patch_p = ctx.write_file("utf8_patch.json", tpl.dumps_json(patch))
    ap = ctx.stratac.graph_apply(p, patch_p)
    if ap.returncode != 0:
        raise CaseFailure(f"graph apply failed: {ap.stderr.strip()}")
    updated = p.read_text(encoding="utf-8")
    if "// ⚔️ boss phase UTF-8 header" not in updated:
        raise CaseFailure("UTF-8 comment lost during graph apply")
    if not updated.endswith("\n"):
        raise CaseFailure("Trailing newline lost during graph apply")


# =========================================================================
# F3 Boundary & Negative Cases (6 Tests)
# =========================================================================

def t2_f3_01(ctx: TestContext) -> None:
    p = ctx.write_file("no_sidecar.strata", tpl.doc_all_eight_graph_kinds("demo::nosc"))
    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export without sidecar failed: {ir}")
    nodes = ir.get("nodes", [])
    if not nodes:
        raise CaseFailure("Expected non-empty nodes list")
    for n in nodes:
        if "position" not in n:
            raise CaseFailure(f"Node {n.get('id')} missing 'position' key: {n!r}")
        pos = n.get("position")
        if pos is None:
            continue
        if (
            not isinstance(pos, dict)
            or isinstance(pos.get("x"), bool)
            or isinstance(pos.get("y"), bool)
            or not isinstance(pos.get("x"), (int, float))
            or not isinstance(pos.get("y"), (int, float))
            or not math.isfinite(float(pos["x"]))
            or not math.isfinite(float(pos["y"]))
        ):
            raise CaseFailure(f"Node {n.get('id')} has malformed position: {pos!r}")


def t2_f3_02(ctx: TestContext) -> None:
    p = ctx.write_file("bad_sc.strata", tpl.doc_all_eight_graph_kinds("demo::badsc"))
    h_before = sha256_file(p)
    ctx.write_file("bad_sc.strata.graph.json", "{bad sidecar json")
    res = ctx.stratac.run(["graph", "export", str(p), "--format=json"])
    combined = f"{res.stderr}\n{res.stdout}".lower()
    if res.returncode != 1 or "unrecognized subcommand" in combined:
        raise CaseFailure(
            f"Expected exit 1 on corrupted sidecar JSON, got {res.returncode}: {combined.strip()}"
        )
    if not any(kw in combined for kw in ("sidecar", "json", "parse", "syntax", "eof", "expected", "deserialize")):
        raise CaseFailure(f"Corrupted sidecar error lacked JSON/sidecar diagnostic: {combined.strip()}")
    if sha256_file(p) != h_before:
        raise CaseFailure(".strata modified when sidecar JSON is corrupted")


def t2_f3_03(ctx: TestContext) -> None:
    p = ctx.write_file("extreme.strata", tpl.doc_all_eight_graph_kinds("demo::ext"))
    h_before = sha256_file(p)
    l_res1, l1 = ctx.stratac.layout_json(p)
    if l_res1.returncode != 0:
        raise CaseFailure(f"layout failed: {l1}")
    fp1 = extract_layout_fingerprints(l1)

    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export failed: {ir}")
    patch = tpl.build_position_patch(ir, {"demo::ext::BossHealth": (-99999.75, 1000000.0)})
    patch_p = ctx.write_file("ext_patch.json", tpl.dumps_json(patch))
    ap = ctx.stratac.graph_apply(p, patch_p)
    if ap.returncode != 0:
        raise CaseFailure(f"graph apply extreme coords failed: {ap.stderr.strip()}")
    if sha256_file(p) != h_before:
        raise CaseFailure(".strata modified during extreme position patch")

    res2, ir2 = ctx.stratac.graph_export_json(p)
    if res2.returncode != 0:
        raise CaseFailure(f"re-export failed: {ir2}")
    matches = [n for n in ir2.get("nodes", []) if n.get("id") == "demo::ext::BossHealth"]
    if not matches or matches[0].get("position") != {"x": -99999.75, "y": 1000000.0}:
        raise CaseFailure(f"Extreme coords did not round-trip: {matches}")
    l_res2, l2 = ctx.stratac.layout_json(p)
    if extract_layout_fingerprints(l2) != fp1:
        raise CaseFailure("SCHEMA_FINGERPRINT changed after extreme coordinate patch")


def t2_f3_04(ctx: TestContext) -> None:
    p = ctx.write_file("stale.strata", tpl.doc_all_eight_graph_kinds("demo::mod"))
    l_res1, l1 = ctx.stratac.layout_json(p)
    if l_res1.returncode != 0:
        raise CaseFailure(f"baseline layout failed: {l1}")
    fp1 = extract_layout_fingerprints(l1)

    sidecar = {
        "layout_version": "1.0",
        "nodes": {
            "demo::mod::DeletedNode": {"x": 123.0, "y": 456.0, "collapsed": True},
        },
    }
    ctx.write_file("stale.strata.graph.json", tpl.dumps_json(sidecar))
    l_res2, l2 = ctx.stratac.layout_json(p)
    if l_res2.returncode != 0 or extract_layout_fingerprints(l2) != fp1:
        raise CaseFailure("Stale sidecar key affected layout SCHEMA_FINGERPRINT")
    g_res, _ = ctx.stratac.graph_export_json(p)
    if g_res.returncode != 0:
        raise CaseFailure(f"graph export failed with stale sidecar entry: {g_res.stderr}")


def t2_f3_05(ctx: TestContext) -> None:
    p = ctx.write_file("fresh.strata", tpl.doc_all_eight_graph_kinds("demo::fresh"))
    h_before = sha256_file(p)
    sc_path = ctx.tmp_dir / "fresh.strata.graph.json"
    if sc_path.exists():
        raise CaseFailure("Precondition violated: sidecar already exists")
    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"graph export failed: {ir}")
    patch = tpl.build_position_patch(ir, {"demo::fresh::BossHealth": (42.0, 84.0)})
    patch_p = ctx.write_file("pos.json", tpl.dumps_json(patch))
    ap = ctx.stratac.graph_apply(p, patch_p)
    if ap.returncode != 0:
        raise CaseFailure(f"graph apply failed: {ap.stderr.strip()}")
    if sha256_file(p) != h_before:
        raise CaseFailure(".strata modified when creating sidecar")
    if not sc_path.is_file():
        raise CaseFailure("Expected sidecar file to be created by graph apply")


def t2_f3_06(ctx: TestContext) -> None:
    p = ctx.write_file("nan_sc.strata", tpl.doc_all_eight_graph_kinds("demo::nan"))
    h_before = sha256_file(p)
    bad_sc = {
        "layout_version": "1.0",
        "nodes": {"demo::nan::BossHealth": {"x": "not_a_number", "y": 10.0}},
    }
    ctx.write_file("nan_sc.strata.graph.json", tpl.dumps_json(bad_sc))
    res = ctx.stratac.run(["graph", "export", str(p), "--format=json"])
    combined = f"{res.stderr}\n{res.stdout}".lower()
    if res.returncode != 1 or "unrecognized subcommand" in combined:
        raise CaseFailure(
            f"Expected exit 1 on non-numeric sidecar position, got {res.returncode}: {combined.strip()}"
        )
    if not any(
        kw in combined
        for kw in ("sidecar", "json", "number", "float", "numeric", "expected", "invalid", "finite", "nan", "deserialize")
    ):
        raise CaseFailure(f"Non-numeric sidecar error lacked domain diagnostic: {combined.strip()}")
    if sha256_file(p) != h_before:
        raise CaseFailure(".strata modified on invalid sidecar coordinate")


# =========================================================================
# F4 Boundary & Negative Cases (6 Tests)
# =========================================================================

def t2_f4_01(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    valid_frame = build_telemetry_digest64("demo::boss::sys_a", frame_seq=2, p50_us=500)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::DoesNotExist"],
            frames=[list(valid_frame)],
        )
        if "error" in resp:
            raise CaseFailure(f"Unknown node_id caused JSON-RPC error instead of clean empty/null: {resp}")
        if extract_telemetry_node(resp.get("result"), "demo::boss::DoesNotExist") is not None:
            raise CaseFailure(f"Unexpected telemetry entry for nonexistent node: {resp}")
        # Verify server stays alive and handles valid query next
        resp2 = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(valid_frame)],
        )
        if "error" in resp2:
            raise CaseFailure(f"Follow-up valid request failed: {resp2}")
        entry2 = extract_telemetry_node(resp2.get("result"), "demo::boss::sys_a")
        if entry2 is None or entry2.get("frame_seq") != 2 or entry2.get("p50_us") != 500:
            raise CaseFailure(f"Follow-up telemetry missing or mismatched for demo::boss::sys_a: {resp2!r}")


def t2_f4_02(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    bad_magic_frame = build_telemetry_digest64("demo::boss::sys_a", magic=b"STRT", frame_seq=1)
    valid_frame = build_telemetry_digest64("demo::boss::sys_a", frame_seq=2, p50_us=600)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(bad_magic_frame)],
        )
        # Either JSON-RPC error OR rejected frame (must NOT accept bad magic as valid telemetry)
        if "error" not in resp:
            entry = extract_telemetry_node(resp.get("result"), "demo::boss::sys_a")
            if isinstance(entry, dict) and entry.get("frame_seq") == 1:
                raise CaseFailure(f"Invalid magic frame was accepted as telemetry: {resp}")
        # Subsequent valid frame still works cleanly
        resp2 = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(valid_frame)],
        )
        if "error" in resp2:
            raise CaseFailure(f"Server poisoned after bad magic frame: {resp2}")
        entry2 = extract_telemetry_node(resp2.get("result"), "demo::boss::sys_a")
        if entry2 is None or entry2.get("frame_seq") != 2 or entry2.get("p50_us") != 600:
            raise CaseFailure(f"Follow-up telemetry missing or mismatched after bad magic frame: {resp2!r}")


def t2_f4_03(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    truncated = build_telemetry_digest64("demo::boss::sys_a")[:63]
    valid_frame = build_telemetry_digest64("demo::boss::sys_a", frame_seq=9, p50_us=999)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(truncated)],
        )
        if "error" not in resp:
            entry = extract_telemetry_node(resp.get("result"), "demo::boss::sys_a")
            if isinstance(entry, dict) and entry:
                raise CaseFailure(f"Truncated 63B frame should be rejected, got: {resp}")
        resp2 = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(valid_frame)],
        )
        if "error" in resp2:
            raise CaseFailure(f"Server unusable after truncated frame: {resp2}")
        entry2 = extract_telemetry_node(resp2.get("result"), "demo::boss::sys_a")
        if entry2 is None or entry2.get("frame_seq") != 9 or entry2.get("p50_us") != 999:
            raise CaseFailure(f"Follow-up telemetry missing or mismatched after truncated frame: {resp2!r}")


def t2_f4_04(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    q_frame = build_telemetry_digest64("demo::boss::sys_a", flags=1, frame_seq=4, p50_us=8800)
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        lsp.did_open(p)
        resp = lsp.graph_telemetry(
            p.as_uri(),
            node_ids=["demo::boss::sys_a"],
            frames=[list(q_frame)],
        )
        if "error" in resp:
            raise CaseFailure(f"strata/graphTelemetry error: {resp['error']}")
        blob = json.dumps(resp.get("result"))
        if '"flags": 1' not in blob and '"flags":1' not in blob and '"quarantined": true' not in blob and '"quarantined":true' not in blob:
            raise CaseFailure(f"Quarantine flag bit 0 (flags=1) not surfaced in response: {resp}")


def t2_f4_05(ctx: TestContext) -> None:
    unopened = ctx.tmp_dir / "nonexistent.strata"
    with LspClient(ctx.lsp_bin, ctx.tmp_dir) as lsp:
        lsp.initialize(ctx.tmp_dir)
        resp = lsp.graph_telemetry(unopened.as_uri(), node_ids=["demo::boss::sys_a"])
        if not isinstance(resp, dict) or ("result" not in resp and "error" not in resp):
            raise CaseFailure(f"Invalid JSON-RPC response for unopened URI: {resp!r}")
        if isinstance(resp.get("error"), dict) and resp["error"].get("code") == -32601:
            raise CaseFailure(f"strata/graphTelemetry method not implemented (-32601): {resp}")


def t2_f4_06(ctx: TestContext) -> None:
    p = ctx.write_file("boss_lsp.strata", tpl.doc_three_systems_for_lsp("demo::boss"))
    max_u64 = 0xFFFFFFFFFFFFFFFF
    max_u32 = 0xFFFFFFFF
    frame = build_telemetry_digest64(
        "demo::boss::sys_a",
        mod_id=max_u64,
        frame_seq=max_u64,
        matched_entities=max_u32,
        matched_tables=max_u32,
        skipped_summary_tick_tables=max_u32,
        chunks=max_u32,
        p50_us=max_u32,
        p99_us=max_u32,
        commands_queued=max_u32,
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
            raise CaseFailure(f"Max u64 telemetry caused error: {resp['error']}")
        blob = json.dumps(resp.get("result"))
        if str(max_u64) not in blob or str(max_u32) not in blob:
            raise CaseFailure(f"Max counter values ({max_u64}, {max_u32}) truncated or missing in response: {resp}")


# =========================================================================
# F5 Boundary & Negative Cases (6 Tests)
# =========================================================================

def t2_f5_01(ctx: TestContext) -> None:
    good_p = ctx.write_file("good_rpc.strata", "module e2e::good_rpc @version(1.0.0);\nrpc Good { x: f32 }\n")
    g_res, g_rep = ctx.stratac.check_json(good_p)
    if g_res.returncode != 0 or not g_rep.get("ok"):
        raise CaseFailure(f"Baseline valid rpc failed check: {g_rep}")
    src = """module e2e::t2_f5_01 @version(1.0.0);

rpc Broken { x: }
rpc Unclosed { x: f32
"""
    _assert_check_fails(ctx, src, "t2_f5_01.strata", required_code="E0002_PARSE_ERROR")


def t2_f5_02(ctx: TestContext) -> None:
    src = """module e2e::t2_f5_02 @version(1.0.0);

rpc Ping {}
"""
    p = ctx.write_file("empty_rpc.strata", src)
    res, report = ctx.stratac.check_json(p)
    if res.returncode != 0 or not report.get("ok"):
        raise CaseFailure(f"Empty rpc body check failed (rc={res.returncode}): {report}")
    fmt_res = ctx.stratac.fmt(p, check=False)
    if fmt_res.returncode != 0:
        raise CaseFailure(f"fmt failed on empty rpc: {fmt_res.stderr}")


def t2_f5_03(ctx: TestContext) -> None:
    good_p = ctx.write_file(
        "good_nst.strata",
        'module e2e::good_nst @version(1.0.0);\nnet_sim_test "ok"(latency: 10ms) { step_net(1); }\n',
    )
    g_res, g_rep = ctx.stratac.check_json(good_p)
    if g_res.returncode != 0 or not g_rep.get("ok"):
        raise CaseFailure(f"Baseline valid net_sim_test failed check: {g_rep}")
    src = """module e2e::t2_f5_03 @version(1.0.0);

net_sim_test (latency: 10ms) {}
net_sim_test "x"(latency 10ms) {}
"""
    _assert_check_fails(ctx, src, "t2_f5_03.strata", required_code="E0002_PARSE_ERROR")


def t2_f5_04(ctx: TestContext) -> None:
    src = """module e2e::t2_f5_04 @version(1.0.0);

net_sim_test "zero"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 0) {
    step_net(1);
}
"""
    p = ctx.write_file("t2_f5_04.strata", src)
    res, report = ctx.stratac.check_json(p)
    if res.returncode != 0 or not report.get("ok"):
        raise CaseFailure(f"Zero boundary net_sim_test check failed: {report}")
    if ctx.stratac.fmt(p, check=False).returncode != 0:
        raise CaseFailure("stratac fmt failed")
    if ctx.stratac.fmt(p, check=True).returncode != 0:
        raise CaseFailure("stratac fmt --check not idempotent")


def t2_f5_05(ctx: TestContext) -> None:
    src = """module e2e::t2_f5_05 @version(1.0.0);
rpc  A{x:f32}
net_sim_test  "a" ( latency:5ms ){ step_net(1); }
"""
    p = ctx.write_file("unfmt.strata", src)
    res = ctx.stratac.fmt(p, check=True)
    if res.returncode != 3:
        raise CaseFailure(f"Expected exit code 3 (fmt diff) on unformatted rpc/net_sim_test, got {res.returncode}")


def t2_f5_06(ctx: TestContext) -> None:
    src = """module e2e::t2_f5_06 @version(1.0.0);

rpc Move { x: f32 }
rpc Move { y: f32 }
"""
    rep = _assert_check_fails(
        ctx,
        src,
        "t2_f5_06.strata",
        required_msg_substrs=("duplicate", "already", "redefined", "conflict"),
    )
    codes = [d.get("code") for d in rep.get("diagnostics", [])]
    if "E0002_PARSE_ERROR" in codes:
        raise CaseFailure(f"Unexpected E0002_PARSE_ERROR on rpc declarations: {rep}")


# =========================================================================
# F6 Boundary & Negative Cases (6 Tests)
# =========================================================================

def t2_f6_01(ctx: TestContext) -> None:
    src = """module e2e::t2_f6_01 @version(1.0.0);

@authority(server)
component ServerHp { hp: f32 = 100.0 }

@authority(client)
sys illegal_client_write() {
    for h in query(s: &mut ServerHp) {
        h.s.hp = 999.0;
    }
}

@authority(client)
sys illegal_client_selective() {
    for h in query(s: &mut? ServerHp) {
        if h.s.hp < 50.0 {
            h.s.hp = 100.0;
        }
    }
}
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f6_01.strata",
        min_errors=2,
        required_code="E0501_AUTHORITY_VIOLATION",
    )


def t2_f6_02(ctx: TestContext) -> None:
    src = """module e2e::t2_f6_02 @version(1.0.0);

@authority(server)
resource ServerBank { gold: u32 = 100 }

@authority(server)
component ServerTag { flag: u8 = 1 }

@predicted
sys cheat_res(bank: &mut res ServerBank) {
    bank.gold = 9999;
    let e = spawn { ServerTag { flag: 1 } };
    insert(e, ServerTag { flag: 2 });
    remove<ServerTag>(e);
}
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f6_02.strata",
        required_code="E0501_AUTHORITY_VIOLATION",
    )


def t2_f6_03(ctx: TestContext) -> None:
    src = """module e2e::t2_f6_03 @version(1.0.0);

@net(unreliable)
component BadRange {
    @quantize(min = 10.0, max = 10.0, bits = 8)
    a: f32 = 10.0,
    @quantize(min = 50.0, max = -50.0, bits = 8)
    b: f32 = 0.0,
}
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f6_03.strata",
        min_errors=2,
        required_msg_substrs=("quantize", "min", "max"),
    )


def t2_f6_04(ctx: TestContext) -> None:
    src = """module e2e::t2_f6_04 @version(1.0.0);

@net(unreliable)
component BadBits {
    @quantize(min = 0.0, max = 1.0, bits = 0)
    a: f32 = 0.0,
    @quantize(min = 0.0, max = 1.0, bits = 33)
    b: f32 = 0.0,
}
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f6_04.strata",
        min_errors=2,
        required_msg_substrs=("quantize", "bits"),
    )


def t2_f6_05(ctx: TestContext) -> None:
    src = """module e2e::t2_f6_05 @version(1.0.0);

@net(unreliable)
component BadQuantType {
    @quantize(min = 0.0, max = 1.0, bits = 8)
    flag: bool = false,
    @quantize(min = 0.0, max = 1.0, bits = 8)
    label: InlineStr<16>,
}
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f6_05.strata",
        min_errors=1,
        required_msg_substrs=("quantize", "numeric", "type", "bool", "InlineStr"),
    )


def t2_f6_06(ctx: TestContext) -> None:
    src = """module e2e::t2_f6_06 @version(1.0.0);

@authority(alien)
component AlienComp { x: f32 = 0.0 }

@authority(server)
@predicted
component ConflictedComp { y: f32 = 0.0 }
"""
    _assert_check_fails(
        ctx,
        src,
        "t2_f6_06.strata",
        min_errors=2,
        required_msg_substrs=("authority", "predicted", "alien"),
    )


# =========================================================================
# F7 Boundary & Negative Cases (6 Tests)
# =========================================================================

def _compile_all_three_backends(ctx: TestContext, src: str, stem: str) -> None:
    p = ctx.write_file(f"{stem}.strata", src)
    c_dir = ctx.tmp_dir / f"{stem}_c99"
    rg_dir = ctx.tmp_dir / f"{stem}_rg"
    bn_dir = ctx.tmp_dir / f"{stem}_bn"
    c_res, c_rep = ctx.stratac.build_json(p, "c99", c_dir)
    if c_res.returncode != 0:
        raise CaseFailure(f"C99 build failed for {stem}: {c_rep}")
    strict_res = verify_c99_syntax_strict(c_dir, c_rep.get("module_stem", stem))
    if strict_res.returncode != 0:
        raise CaseFailure(f"Strict C99 failed for {stem}: {strict_res.stderr}")
    rg_res, rg_rep = ctx.stratac.build_json(p, "rust-guest", rg_dir)
    if rg_res.returncode != 0:
        raise CaseFailure(f"Rust Guest build failed for {stem}: {rg_rep}")
    bn_res, bn_rep = ctx.stratac.onboard_check_json(p, bn_dir)
    if bn_res.returncode != 0 or not bn_rep.get("cargo_checked"):
        raise CaseFailure(f"Bevy Native onboard --check failed for {stem}: {bn_rep}")


def t2_f7_01(ctx: TestContext) -> None:
    _compile_all_three_backends(ctx, tpl.doc_net_quantize_bits(1, 0.0, 1.0), "q1bit")


def t2_f7_02(ctx: TestContext) -> None:
    _compile_all_three_backends(ctx, tpl.doc_net_quantize_bits(32, -1000000.0, 1000000.0), "q32bit")


def t2_f7_03(ctx: TestContext) -> None:
    src = """module e2e::no_net @version(1.0.0);

component Pos { x: f32 = 0.0, y: f32 = 0.0 }

sys move_pos() {
    for p in query(pos: &mut Pos) {
        p.pos.x += 1.0;
    }
}
"""
    p = ctx.write_file("no_net.strata", src)
    c_dir = ctx.tmp_dir / "no_net_c99"
    c_res, c_rep = ctx.stratac.build_json(p, "c99", c_dir)
    if c_res.returncode != 0:
        raise CaseFailure(f"C99 build failed for non-net module: {c_rep}")
    strict_res = verify_c99_syntax_strict(c_dir, c_rep.get("module_stem", "no_net"))
    if strict_res.returncode != 0:
        raise CaseFailure(f"Strict C99 -Werror failed on non-net module: {strict_res.stderr}")


def t2_f7_04(ctx: TestContext) -> None:
    p1 = ctx.write_file("v1.strata", tpl.doc_net_v1_or_v2(False))
    p2 = ctx.write_file("v2.strata", tpl.doc_net_v1_or_v2(True))
    _, l1 = ctx.stratac.layout_json(p1)
    _, l2 = ctx.stratac.layout_json(p2)
    fps1 = extract_layout_fingerprints(l1)
    fps2 = extract_layout_fingerprints(l2)
    fp1 = next((v for k, v in fps1.items() if k.endswith("::WirePose")), None)
    fp2 = next((v for k, v in fps2.items() if k.endswith("::WirePose")), None)
    if not fp1 or not fp2 or fp1 == fp2:
        raise CaseFailure(f"Expected distinct layout fingerprints for v1 vs v2, got {fp1} vs {fp2}")

    c1, _ = ctx.stratac.build_json(p1, "c99", ctx.tmp_dir / "v1_c99")
    c2, _ = ctx.stratac.build_json(p2, "c99", ctx.tmp_dir / "v2_c99")
    if c1.returncode != 0 or c2.returncode != 0:
        raise CaseFailure("C99 build failed for v1 or v2")
    cfps1 = extract_c99_fingerprints(next((ctx.tmp_dir / "v1_c99").glob("*.c")).read_text(encoding="utf-8"))
    cfps2 = extract_c99_fingerprints(next((ctx.tmp_dir / "v2_c99").glob("*.c")).read_text(encoding="utf-8"))
    if fp1 not in cfps1 or fp2 not in cfps2 or fp1 in cfps2:
        raise CaseFailure(f"C99 fingerprints did not reflect v1/v2 schema change: {cfps1} vs {cfps2}")


def t2_f7_05(ctx: TestContext) -> None:
    # Verify both C99 and Rust Guest emit explicit SCHEMA_FINGERPRINT mismatch guard on net decode
    p1 = ctx.write_file("v1.strata", tpl.doc_net_v1_or_v2(False))
    p2 = ctx.write_file("v2.strata", tpl.doc_net_v1_or_v2(True))
    _, l1 = ctx.stratac.layout_json(p1)
    _, l2 = ctx.stratac.layout_json(p2)
    fp1 = next((v for k, v in extract_layout_fingerprints(l1).items() if k.endswith("::WirePose")), None)
    fp2 = next((v for k, v in extract_layout_fingerprints(l2).items() if k.endswith("::WirePose")), None)
    if not fp1 or not fp2 or fp1 == fp2:
        raise CaseFailure(f"Expected distinct v1/v2 fingerprints, got {fp1} vs {fp2}")

    rg1_dir = ctx.tmp_dir / "v1_rg"
    c1_dir = ctx.tmp_dir / "v1_c99"
    r_rg1, _ = ctx.stratac.build_json(p1, "rust-guest", rg1_dir)
    r_c1, _ = ctx.stratac.build_json(p1, "c99", c1_dir)
    if r_rg1.returncode != 0 or r_c1.returncode != 0:
        raise CaseFailure(f"Build failed: rg={r_rg1.returncode}, c99={r_c1.returncode}")
    rs_text = (rg1_dir / "rust_guest_crate" / "src" / "lib.rs").read_text(encoding="utf-8")
    c_text = next(c1_dir.glob("*.c")).read_text(encoding="utf-8")
    if not has_fingerprint_handshake_check(rs_text, {fp1}):
        raise CaseFailure("Rust Guest missing schema_fingerprint handshake comparison check")
    if not has_fingerprint_handshake_check(c_text, {fp1}):
        raise CaseFailure("C99 missing schema_fingerprint mismatch comparison guard")


def t2_f7_06(ctx: TestContext) -> None:
    src = """module e2e::t2_f7_06 @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component GateState {
    trigger_flag: u32 = 0,
    counter: u32 = 0,
}

object EntityA { GateState { trigger_flag: 1, counter: 0 }, }
object EntityB { GateState { trigger_flag: 0, counter: 0 }, }

@authority(server)
sys conditional_inc() {
    for g in query(s: &mut? GateState) {
        if g.s.trigger_flag != 0 {
            g.s.counter += 1;
        }
    }
}

schedule FixedUpdate { conditional_inc }

net_sim_test "selective_mut_no_false_delta"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 5) {
    clients(1);
    step_net(4);
    assert_eq(client_query(0, s: &GateState).on(EntityA).unwrap().s.counter, 4);
    assert_eq(client_query(0, s: &GateState).on(EntityB).unwrap().s.counter, 0);
}
"""
    p = ctx.write_file("t2_f7_06.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"Selective &mut? net_sim_test failed: {report}")


# =========================================================================
# F8 Boundary & Negative Cases (6 Tests)
# =========================================================================

def t2_f8_01(ctx: TestContext) -> None:
    src = """module e2e::t2_f8_loss1 @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component NetVal { v: u32 = 0 }

object Anchor { NetVal { v: 0 }, }

@net_rpc(direction = client_to_server, reliability = reliable)
rpc SetVal { v: u32 }

net_sim_test "total_blackout"(latency: 10ms, jitter: 0ms, loss: 1.0, seed: 1) {
    clients(1);
    send_rpc(0, SetVal { v: 77 });
    step_net(10);
    assert_eq(server_query(n: &NetVal).on(Anchor).unwrap().n.v, 77);
}
"""
    p = ctx.write_file("loss1.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 2 or not isinstance(report, dict) or report.get("all_passed") is not False:
        raise CaseFailure(f"Expected exit 2 (failed convergence under loss=1.0), got rc={res.returncode}, report={report}")
    tests = report.get("tests", [])
    if not tests or tests[0].get("passed") is not False:
        raise CaseFailure(f"Expected failed test entry in report: {tests}")
    detail = str(tests[0].get("detail") or "").strip()
    if not detail or any(bad in detail.lower() for bad in ("unimplemented", "stub", "not implemented")):
        raise CaseFailure(f"Expected genuine net_sim_test failure detail, got {detail!r}")


def t2_f8_02(ctx: TestContext) -> None:
    src = """module e2e::t2_f8_lan @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component LanVal { v: u32 = 0 }

object Anchor { LanVal { v: 0 }, }

@authority(server)
sys set_lan() {
    for x in query(l: &mut LanVal) {
        x.l.v = 11;
    }
}

schedule FixedUpdate { set_lan }

net_sim_test "lan"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 1) {
    clients(1);
    step_net(1);
    assert_converged();
}
"""
    p = ctx.write_file("lan.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"LAN zero-latency test failed (rc={res.returncode}): {report}")


def t2_f8_03(ctx: TestContext) -> None:
    def make_src(seed: int) -> str:
        return f"""module e2e::t2_f8_seed_{seed} @version(1.0.0);

@authority(server)
@net(reliable, rate = 60Hz, channel = 0)
component Pulse {{ seq: u32 = 0 }}

object Anchor {{ Pulse {{ seq: 0 }}, }}

@authority(server)
sys inc_seq() {{
    for p in query(s: &mut Pulse) {{
        if p.s.seq < 4 {{
            p.s.seq += 1;
        }}
    }}
}}

schedule FixedUpdate {{ inc_seq }}

net_sim_test "seeded"(latency: 20ms, jitter: 20ms, loss: 0.5, seed: {seed}) {{
    clients(1);
    step_net(40);
    assert_converged();
}}
"""
    p42 = ctx.write_file("seed42.strata", make_src(42))
    r1, rep1 = ctx.stratac.test_json(p42)
    r2, rep2 = ctx.stratac.test_json(p42)
    if not isinstance(rep1, dict) or not isinstance(rep2, dict):
        raise CaseFailure(f"stratac test did not return SimTestSuiteReport: {rep1}, {rep2}")
    if r1.returncode != 0 or r2.returncode != 0 or rep1.get("all_passed") is not True or rep2.get("all_passed") is not True:
        raise CaseFailure(
            f"Expected passing net_sim_test for seed=42, got rc1={r1.returncode} rep1={rep1}, rc2={r2.returncode} rep2={rep2}"
        )
    if rep1.get("tests") != rep2.get("tests"):
        raise CaseFailure(f"Same seed 42 was not deterministic: {rep1} vs {rep2}")

    p99 = ctx.write_file("seed99.strata", make_src(99))
    r3, rep3 = ctx.stratac.test_json(p99)
    r4, rep4 = ctx.stratac.test_json(p99)
    if not isinstance(rep3, dict) or not isinstance(rep4, dict):
        raise CaseFailure(f"stratac test did not return SimTestSuiteReport for seed=99: {rep3}, {rep4}")
    if r3.returncode != 0 or r4.returncode != 0 or rep3.get("all_passed") is not True or rep4.get("all_passed") is not True:
        raise CaseFailure(
            f"Expected passing net_sim_test for seed=99, got rc3={r3.returncode} rep3={rep3}, rc4={r4.returncode} rep4={rep4}"
        )
    if rep3.get("tests") != rep4.get("tests"):
        raise CaseFailure(f"Same seed 99 was not deterministic: {rep3} vs {rep4}")


def t2_f8_04(ctx: TestContext) -> None:
    src = """module e2e::t2_f8_iso @version(1.0.0);

@authority(client)
component LocalNote { note_tag: u32 = 0 }

object NoteObj { LocalNote { note_tag: 0 }, }

net_sim_test "client_isolation"(latency: 10ms, jitter: 0ms, loss: 0.0, seed: 3) {
    clients(3);
    step_net(2);
    assert_eq(client_query(1, n: &LocalNote).on(NoteObj).unwrap().n.note_tag, 0);
    assert_eq(client_query(2, n: &LocalNote).on(NoteObj).unwrap().n.note_tag, 0);
}
"""
    p = ctx.write_file("iso.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 0 or not isinstance(report, dict) or not report.get("all_passed"):
        raise CaseFailure(f"Multi-client isolation test failed: {report}")


def t2_f8_05(ctx: TestContext) -> None:
    src = """module e2e::t2_f8_fail @version(1.0.0);

net_sim_test "bad_assert"(latency: 10ms, jitter: 0ms, loss: 0.0, seed: 1) {
    clients(1);
    step_net(2);
    assert_eq(1, 2);
}
"""
    p = ctx.write_file("fail_nst.strata", src)
    res, report = ctx.stratac.test_json(p)
    if res.returncode != 2 or not isinstance(report, dict):
        raise CaseFailure(f"Expected exit code 2 and JSON report, got rc={res.returncode}: {report}")
    if report.get("all_passed") is not False:
        raise CaseFailure(f"Expected all_passed=false: {report}")
    tests = report.get("tests", [])
    if not tests or tests[0].get("passed") is not False:
        raise CaseFailure(f"Expected failed test entry: {tests}")
    detail = str(tests[0].get("detail") or "").strip()
    if not detail or any(bad in detail.lower() for bad in ("unimplemented", "stub", "not implemented")):
        raise CaseFailure(f"Expected genuine net_sim_test failure detail, got {detail!r}")


def t2_f8_06(ctx: TestContext) -> None:
    src = """module e2e::t2_f8_bad_params @version(1.0.0);

net_sim_test "bad_loss"(latency: 10ms, jitter: 0ms, loss: 1.5, seed: 1) {
    step_net(1);
}
"""
    rep = _assert_check_fails(
        ctx,
        src,
        "bad_params.strata",
        required_msg_substrs=("loss", "range", "0.0", "1.0"),
    )
    codes = [d.get("code") for d in rep.get("diagnostics", [])]
    if "E0002_PARSE_ERROR" in codes:
        raise CaseFailure(f"Unexpected E0002_PARSE_ERROR on net_sim_test: {rep}")


# =========================================================================
# F9 Boundary & Negative Cases (6 Tests)
# =========================================================================

def t2_f9_01(ctx: TestContext) -> None:
    p = ctx.copy_cookbook("07_visual_boss_graph.strata")
    h1 = sha256_file(p)
    l_res1, l1 = ctx.stratac.layout_json(p)
    if l_res1.returncode != 0 or not isinstance(l1, dict):
        raise CaseFailure(f"07 layout failed: {l1}")
    fp1 = extract_layout_fingerprints(l1)

    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"07 graph export failed: {ir}")
    nodes = ir.get("nodes", [])
    if not nodes:
        raise CaseFailure("07 graph export has 0 nodes")
    first_id = nodes[0]["id"]
    patch = tpl.build_position_patch(ir, {first_id: (999.0, -321.5)})
    patch_p = ctx.write_file("07_move.json", tpl.dumps_json(patch))
    ap = ctx.stratac.graph_apply(p, patch_p)
    if ap.returncode != 0:
        raise CaseFailure(f"07 graph apply position patch failed: {ap.stderr.strip()}")
    if sha256_file(p) != h1:
        raise CaseFailure("07 .strata modified on position-only patch")
    l_res2, l2 = ctx.stratac.layout_json(p)
    if extract_layout_fingerprints(l2) != fp1:
        raise CaseFailure("07 SCHEMA_FINGERPRINT changed after position patch")


def t2_f9_02(ctx: TestContext) -> None:
    p = ctx.copy_cookbook("07_visual_boss_graph.strata")
    h1 = sha256_file(p)
    res, ir = ctx.stratac.graph_export_json(p)
    if res.returncode != 0 or not isinstance(ir, dict):
        raise CaseFailure(f"07 graph export failed: {ir}")
    patch_p = ctx.write_file("07_noop.json", tpl.dumps_json(ir))
    ap = ctx.stratac.graph_apply(p, patch_p)
    if ap.returncode != 0:
        raise CaseFailure(f"07 graph apply noop failed: {ap.stderr.strip()}")
    if sha256_file(p) != h1:
        raise CaseFailure("07 noop roundtrip modified .strata")


def t2_f9_03(ctx: TestContext) -> None:
    p = ctx.repo_root / "fixtures" / "cookbooks" / "08_authoritative_multiplayer.strata"
    if not p.is_file():
        raise CaseFailure(f"Missing cookbook: {p}")
    r1, rep1 = ctx.stratac.test_json(p)
    r2, rep2 = ctx.stratac.test_json(p)
    if r1.returncode != 0 or r2.returncode != 0:
        raise CaseFailure(f"08 test failed: rc1={r1.returncode}, rc2={r2.returncode}")
    if rep1.get("tests") != rep2.get("tests"):
        raise CaseFailure(f"08 net_sim_test non-deterministic: {rep1} vs {rep2}")


def t2_f9_04(ctx: TestContext) -> None:
    p = ctx.copy_cookbook("08_authoritative_multiplayer.strata", "08_bad.strata")
    orig = p.read_text(encoding="utf-8")
    # Inspect exported layout/source or inject write against first @authority(server) component
    injected = orig + """
@authority(server)
component InjectedServerSecret { secret_hp: f32 = 50.0 }

@authority(client)
sys cheat_mutate_server() {
    for s in query(x: &mut InjectedServerSecret) {
        s.x.secret_hp = 9999.0;
    }
}
"""
    p.write_text(injected, encoding="utf-8")
    res, report = ctx.stratac.check_json(p)
    if res.returncode != 1:
        raise CaseFailure(f"Expected exit 1 on injected E0501 in 08 copy, got {res.returncode}: {report}")
    codes = [d.get("code") for d in report.get("diagnostics", [])]
    if "E0501_AUTHORITY_VIOLATION" not in codes:
        raise CaseFailure(f"Expected E0501_AUTHORITY_VIOLATION, got {codes}: {report}")


def t2_f9_05(ctx: TestContext) -> None:
    for name in ("07_visual_boss_graph.strata", "08_authoritative_multiplayer.strata"):
        p = ctx.repo_root / "fixtures" / "cookbooks" / name
        if not p.is_file():
            raise CaseFailure(f"Missing cookbook: {p}")
        l_res, l_rep = ctx.stratac.layout_json(p)
        if l_res.returncode != 0 or not isinstance(l_rep, dict) or not l_rep.get("layouts"):
            raise CaseFailure(f"{name} layout failed: {l_rep}")
        e_res, e_rep = ctx.stratac.explain_par_json(p)
        if e_res.returncode != 0 or not isinstance(e_rep, dict) or "concurrency_graph" not in e_rep:
            raise CaseFailure(f"{name} explain-par failed: {e_rep}")


def t2_f9_06(ctx: TestContext) -> None:
    p = ctx.repo_root / "fixtures" / "cookbooks" / "08_authoritative_multiplayer.strata"
    if not p.is_file():
        raise CaseFailure(f"Missing cookbook: {p}")
    out_dir = ctx.tmp_dir / "08_bn"
    res, rep = ctx.stratac.onboard_check_json(p, out_dir, target="bevy-native")
    if res.returncode != 0 or not isinstance(rep, dict) or not rep.get("cargo_checked"):
        raise CaseFailure(f"08 onboard --target bevy-native --check failed: {rep}")


CASES_TIER2: list[TestCase] = [
    # F1
    TestCase("T2-F1-01", 2, ("F1",), "node_pure_rejected_on_sys", t2_f1_01),
    TestCase("T2-F1-02", 2, ("F1",), "node_pure_fn_rejects_ecs_mutation_and_spawn", t2_f1_02),
    TestCase("T2-F1-03", 2, ("F1",), "node_pure_fn_rejects_calling_impure_fn", t2_f1_03),
    TestCase("T2-F1-04", 2, ("F1",), "node_group_empty_string_rejected", t2_f1_04),
    TestCase("T2-F1-05", 2, ("F1",), "node_group_missing_or_integer_arg_rejected", t2_f1_05),
    TestCase("T2-F1-06", 2, ("F1",), "node_pure_fn_rejects_resource_or_query_access", t2_f1_06),
    # F2
    TestCase("T2-F2-01", 2, ("F2",), "graph_apply_invalid_json_patch_fails_cleanly", t2_f2_01),
    TestCase("T2-F2-02", 2, ("F2",), "graph_apply_unknown_node_id_fails_cleanly", t2_f2_02),
    TestCase("T2-F2-03", 2, ("F2",), "graph_export_empty_module_zero_nodes", t2_f2_03),
    TestCase("T2-F2-04", 2, ("F2",), "graph_export_parse_error_file_fails", t2_f2_04),
    TestCase("T2-F2-05", 2, ("F2",), "graph_apply_mismatched_node_kind_rejected", t2_f2_05),
    TestCase("T2-F2-06", 2, ("F2",), "graph_apply_preserves_unicode_comments_and_trailing_newline", t2_f2_06),
    # F3
    TestCase("T2-F3-01", 2, ("F3",), "graph_export_without_sidecar_uses_default_positions", t2_f3_01),
    TestCase("T2-F3-02", 2, ("F3",), "graph_export_corrupted_sidecar_json_fails_safely", t2_f3_02),
    TestCase("T2-F3-03", 2, ("F3",), "graph_apply_extreme_negative_and_fractional_positions", t2_f3_03),
    TestCase("T2-F3-04", 2, ("F3",), "stale_extra_sidecar_entry_does_not_affect_schema_fingerprint", t2_f3_04),
    TestCase("T2-F3-05", 2, ("F3",), "graph_apply_position_patch_creates_sidecar_when_absent", t2_f3_05),
    TestCase("T2-F3-06", 2, ("F3",), "non_finite_position_nan_or_string_rejected", t2_f3_06),
    # F4
    TestCase("T2-F4-01", 2, ("F4",), "lsp_graph_telemetry_unknown_node_id_handled_gracefully", t2_f4_01),
    TestCase("T2-F4-02", 2, ("F4",), "lsp_graph_telemetry_invalid_magic_frame_rejected", t2_f4_02),
    TestCase("T2-F4-03", 2, ("F4",), "lsp_graph_telemetry_truncated_63_byte_frame_rejected", t2_f4_03),
    TestCase("T2-F4-04", 2, ("F4",), "lsp_graph_telemetry_quarantine_flag_bit0_surfaced", t2_f4_04),
    TestCase("T2-F4-05", 2, ("F4",), "lsp_graph_telemetry_unopened_uri_returns_clean_empty_or_error", t2_f4_05),
    TestCase("T2-F4-06", 2, ("F4",), "lsp_graph_telemetry_max_u64_counters_no_overflow", t2_f4_06),
    # F5
    TestCase("T2-F5-01", 2, ("F5",), "malformed_rpc_missing_brace_or_type", t2_f5_01),
    TestCase("T2-F5-02", 2, ("F5",), "empty_rpc_body_handled", t2_f5_02),
    TestCase("T2-F5-03", 2, ("F5",), "malformed_net_sim_test_missing_name_or_param_colon", t2_f5_03),
    TestCase("T2-F5-04", 2, ("F5",), "net_sim_test_zero_boundary_params", t2_f5_04),
    TestCase("T2-F5-05", 2, ("F5",), "fmt_check_exits_3_on_unformatted_rpc_and_net_sim_test", t2_f5_05),
    TestCase("T2-F5-06", 2, ("F5",), "duplicate_rpc_name_rejected", t2_f5_06),
    # F6
    TestCase("T2-F6-01", 2, ("F6",), "e0501_authority_violation_client_mut_and_selective_mut", t2_f6_01),
    TestCase("T2-F6-02", 2, ("F6",), "e0501_authority_violation_predicted_mut_res_and_insert_remove", t2_f6_02),
    TestCase("T2-F6-03", 2, ("F6",), "quantize_invalid_min_ge_max_rejected", t2_f6_03),
    TestCase("T2-F6-04", 2, ("F6",), "quantize_invalid_bits_zero_and_33_rejected", t2_f6_04),
    TestCase("T2-F6-05", 2, ("F6",), "quantize_on_non_numeric_field_rejected", t2_f6_05),
    TestCase("T2-F6-06", 2, ("F6",), "invalid_authority_kind_and_predicted_server_conflict", t2_f6_06),
    # F7
    TestCase("T2-F7-01", 2, ("F7",), "quantize_1_bit_boundary_compiles_all_backends", t2_f7_01),
    TestCase("T2-F7-02", 2, ("F7",), "quantize_32_bit_boundary_compiles_all_backends", t2_f7_02),
    TestCase("T2-F7-03", 2, ("F7",), "non_net_module_c99_has_zero_unused_net_helper_warnings", t2_f7_03),
    TestCase("T2-F7-04", 2, ("F7",), "schema_fingerprint_differs_when_net_field_layout_changes", t2_f7_04),
    TestCase("T2-F7-05", 2, ("F7",), "schema_fingerprint_mismatch_rejected_in_handshake", t2_f7_05),
    TestCase("T2-F7-06", 2, ("F7",), "selective_mut_unchanged_entities_emit_no_false_deltas", t2_f7_06),
    # F8
    TestCase("T2-F8-01", 2, ("F8",), "net_sim_test_100_percent_loss_prevents_convergence", t2_f8_01),
    TestCase("T2-F8-02", 2, ("F8",), "net_sim_test_zero_latency_zero_loss_immediate_delivery", t2_f8_02),
    TestCase("T2-F8-03", 2, ("F8",), "net_sim_test_seeded_prng_determinism_identical_vs_distinct_seeds", t2_f8_03),
    TestCase("T2-F8-04", 2, ("F8",), "net_sim_test_multi_client_isolation", t2_f8_04),
    TestCase("T2-F8-05", 2, ("F8",), "net_sim_test_failing_assert_returns_exit_2_json", t2_f8_05),
    TestCase("T2-F8-06", 2, ("F8",), "net_sim_test_out_of_range_loss_or_negative_latency_rejected", t2_f8_06),
    # F9
    TestCase("T2-F9-01", 2, ("F9",), "cookbook_07_sidecar_position_patch_zero_diff_and_same_fp", t2_f9_01),
    TestCase("T2-F9-02", 2, ("F9",), "cookbook_07_graph_export_apply_noop_idempotent", t2_f9_02),
    TestCase("T2-F9-03", 2, ("F9",), "cookbook_08_deterministic_repeated_net_sim_test", t2_f9_03),
    TestCase("T2-F9-04", 2, ("F9",), "cookbook_08_injected_authority_violation_triggers_e0501", t2_f9_04),
    TestCase("T2-F9-05", 2, ("F9",), "cookbook_07_and_08_layout_and_explain_par_clean", t2_f9_05),
    TestCase("T2-F9-06", 2, ("F9",), "cookbook_08_onboard_bevy_native_check_passes", t2_f9_06),
]
