#!/usr/bin/env python3
"""Opaque-box 4-tier E2E test runner for bamabi-strata Phase 3."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from lib.cases_tier1 import CASES_TIER1
from lib.cases_tier2 import CASES_TIER2
from lib.cases_tier3 import CASES_TIER3
from lib.cases_tier4 import CASES_TIER4
from lib.cli_driver import (
    BinaryNotFoundError,
    CaseFailure,
    StratacDriver,
    TestCase,
    TestContext,
    resolve_binary,
)


ALL_FEATURES = tuple(f"F{i}" for i in range(1, 10))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_e2e.py",
        description="Opaque-box 4-tier E2E test runner for bamabi-strata Phase 3.",
    )
    p.add_argument(
        "--tier",
        choices=("1", "2", "3", "4", "all"),
        default="all",
        help="Select which E2E tier(s) to execute (default: all).",
    )
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format on stdout (default: text).",
    )
    p.add_argument(
        "--stratac",
        default=None,
        help="Path to stratac executable (auto-discovered if omitted).",
    )
    p.add_argument(
        "--strata-lsp",
        default=None,
        help="Path to strata-lsp executable (auto-discovered if omitted).",
    )
    p.add_argument(
        "--filter",
        default=None,
        help="Case-insensitive substring filter matching test id or name.",
    )
    p.add_argument(
        "--feature",
        action="append",
        choices=ALL_FEATURES,
        default=None,
        help="Filter tests by feature tag F1..F9 (repeatable).",
    )
    p.add_argument(
        "--keep-tmp",
        action="store_true",
        help="Preserve per-test temporary directories for debugging.",
    )
    return p


def _collect_cases(
    tier: str,
    substr: str | None,
    features: list[str] | None,
) -> list[TestCase]:
    pool: list[TestCase] = []
    if tier in ("1", "all"):
        pool.extend(CASES_TIER1)
    if tier in ("2", "all"):
        pool.extend(CASES_TIER2)
    if tier in ("3", "all"):
        pool.extend(CASES_TIER3)
    if tier in ("4", "all"):
        pool.extend(CASES_TIER4)

    if features:
        feat_set = set(features)
        pool = [tc for tc in pool if feat_set.intersection(tc.features)]

    if substr:
        needle = substr.lower()
        pool = [tc for tc in pool if needle in tc.id.lower() or needle in tc.name.lower()]

    return pool


def _run_case(
    tc: TestCase,
    stratac_bin: Path,
    lsp_bin: Path,
    keep_tmp: bool,
) -> tuple[dict[str, Any], Path | None]:
    t0 = time.perf_counter()
    if keep_tmp:
        tmp_path = Path(tempfile.mkdtemp(prefix=f"strata_e2e_{tc.id}_"))
        ctx = TestContext(
            tmp_dir=tmp_path,
            stratac=StratacDriver(stratac_bin),
            lsp_bin=lsp_bin,
        )
        passed, detail = _exec_case_fn(tc, ctx)
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return (
            {
                "id": tc.id,
                "tier": tc.tier,
                "features": list(tc.features),
                "name": tc.name,
                "passed": passed,
                "duration_ms": elapsed_ms,
                "detail": detail,
            },
            tmp_path,
        )

    with tempfile.TemporaryDirectory(prefix=f"strata_e2e_{tc.id}_") as td:
        ctx = TestContext(
            tmp_dir=Path(td),
            stratac=StratacDriver(stratac_bin),
            lsp_bin=lsp_bin,
        )
        passed, detail = _exec_case_fn(tc, ctx)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return (
        {
            "id": tc.id,
            "tier": tc.tier,
            "features": list(tc.features),
            "name": tc.name,
            "passed": passed,
            "duration_ms": elapsed_ms,
            "detail": detail,
        },
        None,
    )


def _exec_case_fn(tc: TestCase, ctx: TestContext) -> tuple[bool, str]:
    try:
        tc.fn(ctx)
        return True, "ok"
    except CaseFailure as exc:
        return False, str(exc)
    except Exception as exc:  # pragma: no cover - safeguard against unexpected runtime issues
        return False, f"Unhandled {type(exc).__name__}: {exc}"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        stratac_bin = resolve_binary(args.stratac, "stratac")
        lsp_bin = resolve_binary(args.strata_lsp, "strata-lsp")
    except BinaryNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    cases = _collect_cases(args.tier, args.filter, args.feature)
    if not cases:
        print("error: no test cases matched selection criteria", file=sys.stderr)
        return 2

    suite_t0 = time.perf_counter()
    results: list[dict[str, Any]] = []
    kept_dirs: list[tuple[str, Path]] = []

    for tc in cases:
        res_entry, kept = _run_case(tc, stratac_bin, lsp_bin, args.keep_tmp)
        results.append(res_entry)
        if kept is not None:
            kept_dirs.append((tc.id, kept))

    total_ms = round((time.perf_counter() - suite_t0) * 1000.0, 2)
    passed_cnt = sum(1 for r in results if r["passed"])
    failed_cnt = len(results) - passed_cnt

    if args.format == "json":
        payload = {
            "suite": "e2e_phase3",
            "tier": args.tier,
            "total": len(results),
            "passed": passed_cnt,
            "failed": failed_cnt,
            "duration_ms": total_ms,
            "results": results,
        }
        print(json.dumps(payload, indent=2))
        if kept_dirs:
            for cid, d in kept_dirs:
                print(f"[keep-tmp] {cid}: {d}", file=sys.stderr)
    else:
        print(
            f"e2e_phase3 (tier={args.tier}): {passed_cnt}/{len(results)} passed, "
            f"{failed_cnt} failed ({total_ms:.1f} ms)"
        )
        print(f"  stratac:    {stratac_bin}")
        print(f"  strata-lsp: {lsp_bin}")
        for r in results:
            tag = "PASS" if r["passed"] else "FAIL"
            feats = ",".join(r["features"])
            print(f"[{tag}] {r['id']} (T{r['tier']} {feats}) {r['name']} ({r['duration_ms']:.1f} ms)")
            if not r["passed"]:
                print(f"       {r['detail']}")
        if kept_dirs:
            print("Preserved temp directories:")
            for cid, d in kept_dirs:
                print(f"  {cid}: {d}")

    return 0 if failed_cnt == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
