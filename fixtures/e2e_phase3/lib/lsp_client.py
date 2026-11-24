"""Stdio JSON-RPC 2.0 LSP client and Layer-0 SystemTelemetryDigest64 ("BAMT") frame builder."""

from __future__ import annotations

import json
import queue
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .cli_driver import CaseFailure


BAMT_MAGIC = b"BAMT"
BAMT_VERSION = 1
FNV1A_64_OFFSET = 0xCBF29CE484222325
FNV1A_64_PRIME = 0x100000001B3


def fnv1a_64(text: str) -> int:
    h = FNV1A_64_OFFSET
    for b in text.encode("utf-8"):
        h ^= b
        h = (h * FNV1A_64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def extract_telemetry_node(result: Any, node_id: str) -> dict[str, Any] | None:
    """Extract a node's telemetry dict from dict- or list-shaped LSP responses."""
    if isinstance(result, list):
        for item in result:
            if isinstance(item, dict) and (
                item.get("node_id") == node_id or item.get("id") == node_id
            ):
                return item
        return None
    if not isinstance(result, dict):
        return None
    if node_id in result and isinstance(result[node_id], dict):
        return result[node_id]
    for container_key in ("nodes", "entries", "metrics"):
        container = result.get(container_key)
        if isinstance(container, dict) and node_id in container:
            entry = container[node_id]
            return entry if isinstance(entry, dict) else None
        if isinstance(container, list):
            for item in container:
                if isinstance(item, dict) and (
                    item.get("node_id") == node_id or item.get("id") == node_id
                ):
                    return item
    return None


def build_telemetry_digest64(
    system_name: str = "",
    *,
    magic: bytes = BAMT_MAGIC,
    version: int = BAMT_VERSION,
    flags: int = 0,
    mod_id: int = 0,
    system_hash: int | None = None,
    frame_seq: int = 1,
    matched_entities: int = 128,
    matched_tables: int = 4,
    skipped_summary_tick_tables: int = 0,
    chunks: int = 4,
    p50_us: int = 1000,
    p99_us: int = 2500,
    commands_queued: int = 0,
    reserved: int = 0,
) -> bytes:
    """Build a canonical 64-byte little-endian Layer-0 SystemTelemetryDigest64 ("BAMT") frame."""
    if len(magic) != 4:
        raise ValueError(f"telemetry magic must be 4 bytes, got {magic!r}")
    h = fnv1a_64(system_name) if system_hash is None else (system_hash & 0xFFFFFFFFFFFFFFFF)
    return struct.pack(
        "<4sHHQQQIIIIIIII",
        magic,
        version & 0xFFFF,
        flags & 0xFFFF,
        mod_id & 0xFFFFFFFFFFFFFFFF,
        h,
        frame_seq & 0xFFFFFFFFFFFFFFFF,
        matched_entities & 0xFFFFFFFF,
        matched_tables & 0xFFFFFFFF,
        skipped_summary_tick_tables & 0xFFFFFFFF,
        chunks & 0xFFFFFFFF,
        p50_us & 0xFFFFFFFF,
        p99_us & 0xFFFFFFFF,
        commands_queued & 0xFFFFFFFF,
        reserved & 0xFFFFFFFF,
    )


class LspClient:
    """Content-Length framed JSON-RPC 2.0 client for `strata-lsp` over stdio."""

    def __init__(self, lsp_bin: Path, cwd: Path) -> None:
        self.lsp_bin = lsp_bin
        self.cwd = cwd
        self.proc: subprocess.Popen[bytes] | None = None
        self._next_id = 1
        self._msg_queue: queue.Queue[dict[str, Any] | Exception | None] = queue.Queue()
        self._reader_thread: threading.Thread | None = None
        self.notifications: list[dict[str, Any]] = []
        self._closed = False

    def __enter__(self) -> "LspClient":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if not self._closed:
            try:
                self.shutdown_and_exit()
            except Exception:
                self.kill()

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [str(self.lsp_bin)],
            cwd=str(self.cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _read_loop(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        stdout = self.proc.stdout
        try:
            while True:
                content_length: int | None = None
                while True:
                    line = stdout.readline()
                    if not line:
                        self._msg_queue.put(None)
                        return
                    stripped = line.strip()
                    if not stripped:
                        break
                    lower = stripped.decode("ascii", errors="replace").lower()
                    if lower.startswith("content-length:"):
                        val = lower.split(":", 1)[1].strip()
                        content_length = int(val)
                if content_length is None:
                    continue
                body = b""
                while len(body) < content_length:
                    chunk = stdout.read(content_length - len(body))
                    if not chunk:
                        self._msg_queue.put(None)
                        return
                    body += chunk
                msg = json.loads(body.decode("utf-8"))
                self._msg_queue.put(msg)
        except Exception as exc:  # pragma: no cover - defensive reader
            self._msg_queue.put(exc)

    def _send(self, payload: dict[str, Any]) -> None:
        if self.proc is None or self.proc.stdin is None:
            raise CaseFailure("LSP process is not running")
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        header = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii")
        try:
            self.proc.stdin.write(header + raw)
            self.proc.stdin.flush()
        except BrokenPipeError as exc:
            raise CaseFailure("Broken pipe writing to strata-lsp") from exc

    def request(
        self,
        method: str,
        params: Any = None,
        *,
        omit_params: bool = False,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        msg: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
        }
        if not omit_params:
            msg["params"] = params
        self._send(msg)

        deadline = time.monotonic() + timeout
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise CaseFailure(f"Timed out waiting for LSP response to '{method}' (id={req_id})")
            try:
                item = self._msg_queue.get(timeout=rem)
            except queue.Empty as exc:
                raise CaseFailure(f"Timed out waiting for LSP response to '{method}' (id={req_id})") from exc
            if item is None:
                rc = self.proc.poll() if self.proc else None
                stderr = self._read_stderr_nonblocking()
                raise CaseFailure(f"strata-lsp EOF while awaiting '{method}' (rc={rc}, stderr={stderr})")
            if isinstance(item, Exception):
                raise CaseFailure(f"LSP reader error: {item}") from item
            if "id" in item and item["id"] == req_id:
                return item
            # Server notification or unrelated message
            self.notifications.append(item)

    def notify(
        self,
        method: str,
        params: Any = None,
        *,
        omit_params: bool = False,
    ) -> None:
        msg: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if not omit_params:
            msg["params"] = params
        self._send(msg)

    def drain_notifications(self, wait_s: float = 0.05) -> list[dict[str, Any]]:
        deadline = time.monotonic() + wait_s
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                break
            try:
                item = self._msg_queue.get(timeout=rem)
            except queue.Empty:
                break
            if item is None or isinstance(item, Exception):
                break
            self.notifications.append(item)
        return list(self.notifications)

    def initialize(self, root_path: Path) -> dict[str, Any]:
        resp = self.request(
            "initialize",
            {
                "processId": None,
                "rootUri": root_path.as_uri(),
                "capabilities": {},
            },
        )
        if "error" in resp:
            raise CaseFailure(f"LSP initialize failed: {resp['error']}")
        self.notify("initialized", {})
        self.drain_notifications(0.05)
        return resp

    def did_open(self, file_path: Path, text: str | None = None, version: int = 1) -> None:
        body = text if text is not None else file_path.read_text(encoding="utf-8")
        self.notify(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": file_path.as_uri(),
                    "languageId": "strata",
                    "version": version,
                    "text": body,
                }
            },
        )
        self.drain_notifications(0.05)

    def did_change(self, file_path: Path, text: str, version: int = 2) -> None:
        self.notify(
            "textDocument/didChange",
            {
                "textDocument": {
                    "uri": file_path.as_uri(),
                    "version": version,
                },
                "contentChanges": [{"text": text}],
            },
        )
        self.drain_notifications(0.05)

    def graph_telemetry(
        self,
        uri: str,
        *,
        node_ids: list[str] | None = None,
        frames: list[list[int]] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"uri": uri}
        if node_ids is not None:
            params["node_ids"] = node_ids
        if frames is not None:
            params["frames"] = frames
        if extra:
            params.update(extra)
        return self.request("strata/graphTelemetry", params)

    def shutdown_and_exit(self, timeout: float = 5.0) -> int:
        if self._closed:
            return self.proc.returncode if self.proc and self.proc.returncode is not None else 0
        self._closed = True
        assert self.proc is not None
        resp = self.request("shutdown", omit_params=True, timeout=timeout)
        if "error" in resp:
            raise CaseFailure(f"LSP shutdown error: {resp['error']}")
        self.notify("exit", omit_params=True)
        if self.proc.stdin is not None:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            rc = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.kill()
            raise CaseFailure("strata-lsp hung on exit") from exc
        return rc

    def kill(self) -> None:
        self._closed = True
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=2)

    def _read_stderr_nonblocking(self) -> str:
        if self.proc is None or self.proc.stderr is None:
            return ""
        try:
            if self.proc.poll() is not None:
                return self.proc.stderr.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""
