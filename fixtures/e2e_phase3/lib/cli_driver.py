"""CLI driver and artifact inspection helpers for opaque-box E2E tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[3]
COOKBOOKS_DIR = REPO_ROOT / "fixtures" / "cookbooks"


class BinaryNotFoundError(RuntimeError):
    """Raised when stratac or strata-lsp cannot be located or executed."""


class CaseFailure(AssertionError):
    """Raised by a test case when an opaque-box assertion fails."""


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    cmd: list[str]


@dataclass(frozen=True)
class TestCase:
    id: str
    tier: int
    features: tuple[str, ...]
    name: str
    fn: Callable[["TestContext"], None]


@dataclass
class TestContext:
    tmp_dir: Path
    stratac: "StratacDriver"
    lsp_bin: Path
    repo_root: Path = REPO_ROOT

    def write_file(self, rel_path: str, content: str) -> Path:
        p = self.tmp_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def write_bytes(self, rel_path: str, content: bytes) -> Path:
        p = self.tmp_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        return p

    def copy_cookbook(self, filename: str, dest_name: str | None = None) -> Path:
        src = COOKBOOKS_DIR / filename
        if not src.is_file():
            raise CaseFailure(f"Missing cookbook fixture: {src}")
        dst = self.tmp_dir / (dest_name or filename)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        sidecar_src = COOKBOOKS_DIR / f"{filename}.graph.json"
        if sidecar_src.is_file():
            shutil.copy2(sidecar_src, self.tmp_dir / f"{dst.name}.graph.json")
        return dst


def resolve_binary(explicit: str | None, name: str) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    else:
        candidates.append(REPO_ROOT / "target" / "debug" / name)
        candidates.append(REPO_ROOT / "target" / "release" / name)
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))

    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c.resolve()

    raise BinaryNotFoundError(
        f"Could not find executable '{name}'. Checked: "
        + ", ".join(str(c) for c in candidates)
    )


def resolve_c_compiler() -> str | None:
    for cc in ("cc", "clang", "gcc"):
        found = shutil.which(cc)
        if found:
            return found
    return None


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_json_output(raw: str, label: str) -> Any:
    text = raw.strip()
    if not text:
        raise CaseFailure(f"{label}: expected JSON output on stdout, got empty string")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        preview = text[:300].replace("\n", "\\n")
        raise CaseFailure(f"{label}: invalid JSON ({exc}): {preview}") from exc


def extract_diagnostics(parsed: Any) -> list[dict[str, Any]]:
    if isinstance(parsed, dict) and isinstance(parsed.get("diagnostics"), list):
        return parsed["diagnostics"]
    if isinstance(parsed, list):
        return parsed
    return []


def normalize_fingerprint(val: Any) -> str | None:
    if isinstance(val, int) and not isinstance(val, bool):
        return f"0x{val & 0xFFFFFFFFFFFFFFFF:016X}"
    if isinstance(val, str):
        s = val.strip()
        if s.lower().startswith("0x"):
            try:
                return f"0x{int(s, 16) & 0xFFFFFFFFFFFFFFFF:016X}"
            except ValueError:
                return None
        try:
            return f"0x{int(s, 10) & 0xFFFFFFFFFFFFFFFF:016X}"
        except ValueError:
            return None
    return None


def extract_layout_fingerprints(layout_report: Any) -> dict[str, str]:
    if not isinstance(layout_report, dict):
        return {}
    out: dict[str, str] = {}
    for item in layout_report.get("layouts", []):
        name = item.get("canonical_name")
        fp = normalize_fingerprint(item.get("schema_fingerprint"))
        if isinstance(name, str) and fp is not None:
            out[name] = fp
    return out


_C99_FP_RE = re.compile(
    r"schema_fingerprint\s*(?:=|!=|==)\s*(0x[0-9a-fA-F]+)(?:u?ll|U?LL|u|U)?",
    re.IGNORECASE,
)
_RUST_FP_RE = re.compile(
    r"(?:SCHEMA_FINGERPRINT(?:\s*:\s*u64)?\s*=\s*|schema_fingerprint\s*(?:!=|==|:)\s*)(0x[0-9a-fA-F_]+)"
)


def extract_c99_fingerprints(c_text: str) -> set[str]:
    fps: set[str] = set()
    for m in _C99_FP_RE.finditer(c_text):
        norm = normalize_fingerprint(m.group(1))
        if norm:
            fps.add(norm)
    return fps


def extract_rust_fingerprints(rs_text: str) -> set[str]:
    fps: set[str] = set()
    for m in _RUST_FP_RE.finditer(rs_text):
        norm = normalize_fingerprint(m.group(1).replace("_", ""))
        if norm:
            fps.add(norm)
    return fps


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_FP_IDENT = r"[A-Za-z_][A-Za-z0-9_.:]*(?:fingerprint|SCHEMA_FINGERPRINT|_fp|fp)[A-Za-z0-9_.:]*"
_FP_CMP_RE = re.compile(
    rf"(?:{_FP_IDENT}\s*(?:!=|==)\s*[^;{{\n]+|[^;{{\n]+\s*(?:!=|==)\s*{_FP_IDENT})",
    re.IGNORECASE,
)


def has_fingerprint_handshake_check(
    source_text: str,
    expected_fps: set[str] | None = None,
) -> bool:
    """Return True iff emitted C99/Rust contains a `!=` or `==` fingerprint comparison."""
    stripped = _BLOCK_COMMENT_RE.sub(" ", _LINE_COMMENT_RE.sub(" ", source_text))
    if _FP_CMP_RE.search(stripped):
        return True
    if expected_fps:
        for fp in expected_fps:
            norm = normalize_fingerprint(fp)
            if not norm:
                continue
            hex_digits = norm[2:].lstrip("0") or "0"
            # Match 0x... (with optional underscores/suffixes) compared via == or !=
            lit_pat = (
                r"0x0*"
                + r"_*".join(re.escape(ch) for ch in hex_digits)
                + r"(?:_?u64|u?ll|U?LL|u|U)?"
            )
            if re.search(rf"(?:!=|==)\s*{lit_pat}\b|\b{lit_pat}\s*(?:!=|==)", stripped, re.IGNORECASE):
                return True
    return False


def verify_c99_syntax_strict(c99_dir: Path, stem: str) -> CmdResult:
    cc = resolve_c_compiler()
    if cc is None:
        raise CaseFailure("No C compiler (cc/clang/gcc) found on PATH")
    c_file = c99_dir / f"{stem}.c"
    if not c_file.is_file():
        c_files = sorted(c99_dir.glob("*.c"))
        if not c_files:
            raise CaseFailure(f"No .c file generated in {c99_dir}")
        c_file = c_files[0]
    cmd = [
        cc,
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        "-fsyntax-only",
        "-I",
        str(c99_dir),
        str(c_file),
    ]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    elapsed = (time.perf_counter() - t0) * 1000.0
    return CmdResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        duration_ms=elapsed,
        cmd=cmd,
    )


def replace_json_scalar(obj: Any, old_val: Any, new_val: Any) -> tuple[Any, int]:
    """Recursively replace matching scalar values inside a JSON-compatible payload."""
    if isinstance(obj, dict):
        count = 0
        out: dict[str, Any] = {}
        for k, v in obj.items():
            nv, c = replace_json_scalar(v, old_val, new_val)
            out[k] = nv
            count += c
        return out, count
    if isinstance(obj, list):
        count = 0
        out_list: list[Any] = []
        for item in obj:
            nv, c = replace_json_scalar(item, old_val, new_val)
            out_list.append(nv)
            count += c
        return out_list, count
    if obj == old_val and type(obj) is type(old_val):
        return new_val, 1
    if isinstance(old_val, float) and isinstance(obj, (int, float)) and not isinstance(obj, bool):
        if abs(float(obj) - old_val) < 1e-6:
            return new_val, 1
    if isinstance(obj, str) and obj.strip() == str(old_val):
        return str(new_val), 1
    return obj, 0


class StratacDriver:
    """Wrapper invoking the real `stratac` executable."""

    def __init__(self, stratac_bin: Path, cwd: Path = REPO_ROOT) -> None:
        self.bin_path = stratac_bin
        self.cwd = cwd

    def run(
        self,
        args: list[str],
        cwd: Path | None = None,
        timeout: int = 180,
    ) -> CmdResult:
        cmd = [str(self.bin_path), *args]
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd or self.cwd),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = (time.perf_counter() - t0) * 1000.0
            raise CaseFailure(
                f"Command timed out after {timeout}s: {' '.join(cmd)}\n"
                f"stdout={exc.stdout!r}\nstderr={exc.stderr!r}"
            ) from exc
        elapsed = (time.perf_counter() - t0) * 1000.0
        return CmdResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_ms=elapsed,
            cmd=cmd,
        )

    def check_json(self, file_path: Path) -> tuple[CmdResult, dict[str, Any]]:
        res = self.run(["check", str(file_path), "--format=json"])
        parsed = parse_json_output(res.stdout, f"stratac check {file_path.name}")
        if not isinstance(parsed, dict):
            raise CaseFailure(f"stratac check expected CheckReport object, got {type(parsed).__name__}")
        return res, parsed

    def fmt(self, file_path: Path, check: bool = False) -> CmdResult:
        args = ["fmt", str(file_path)]
        if check:
            args.append("--check")
        return self.run(args)

    def layout_json(self, file_path: Path) -> tuple[CmdResult, Any]:
        res = self.run(["layout", str(file_path), "--format=json"])
        parsed = parse_json_output(res.stdout, f"stratac layout {file_path.name}")
        return res, parsed

    def explain_par_json(self, file_path: Path) -> tuple[CmdResult, Any]:
        res = self.run(["explain-par", str(file_path), "--format=json"])
        parsed = parse_json_output(res.stdout, f"stratac explain-par {file_path.name}")
        return res, parsed

    def test_json(self, file_path: Path, timeout: int = 240) -> tuple[CmdResult, Any]:
        res = self.run(["test", str(file_path), "--format=json"], timeout=timeout)
        parsed = parse_json_output(res.stdout, f"stratac test {file_path.name}")
        return res, parsed

    def build_json(
        self,
        file_path: Path,
        target: str,
        out_dir: Path,
        release: bool = False,
        timeout: int = 300,
    ) -> tuple[CmdResult, Any]:
        args = [
            "build",
            str(file_path),
            "--target",
            target,
            "--out",
            str(out_dir),
            "--format=json",
        ]
        if release:
            args.append("--release")
        res = self.run(args, timeout=timeout)
        parsed = parse_json_output(res.stdout, f"stratac build --target {target}")
        return res, parsed

    def onboard_check_json(
        self,
        file_path: Path,
        out_dir: Path,
        target: str = "bevy-native",
        timeout: int = 300,
    ) -> tuple[CmdResult, Any]:
        args = [
            "onboard",
            str(file_path),
            "--target",
            target,
            "--out",
            str(out_dir),
            "--check",
            "--format=json",
        ]
        res = self.run(args, timeout=timeout)
        parsed = parse_json_output(res.stdout, f"stratac onboard --target {target}")
        return res, parsed

    def graph_export_json(self, file_path: Path) -> tuple[CmdResult, Any]:
        res = self.run(["graph", "export", str(file_path), "--format=json"])
        if res.returncode != 0 and not res.stdout.strip():
            raise CaseFailure(
                f"stratac graph export failed (exit {res.returncode}): {res.stderr.strip()}"
            )
        parsed = parse_json_output(res.stdout, f"stratac graph export {file_path.name}")
        return res, parsed

    def graph_apply(self, file_path: Path, patch_path: Path) -> CmdResult:
        return self.run(["graph", "apply", str(file_path), str(patch_path)])
