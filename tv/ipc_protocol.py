"""IPC protocol: shared constants, encode/decode for JSON-line communication."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 1

COMMANDS = frozenset({"status", "check", "reconnect", "disconnect"})

# Таймауты
CLIENT_TIMEOUT = 10.0  # макс ожидание ответа
SERVER_CLIENT_TIMEOUT = 5.0  # макс ожидание запроса от клиента


def socket_path(script_dir: Path, socket_file: str = "") -> Path:
    """Resolve socket path inside log_dir."""
    from tv.app_config import cfg

    log_dir = script_dir / cfg.paths.log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / (socket_file or cfg.paths.socket_file)


def encode(obj: dict[str, Any]) -> bytes:
    """Serialize dict to JSON line (bytes)."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def decode(line: bytes) -> dict[str, Any]:
    """Deserialize JSON line to dict."""
    return json.loads(line.strip())


def make_request(cmd: str, **kwargs: Any) -> dict[str, Any]:
    """Build a request dict."""
    req: dict[str, Any] = {"v": PROTOCOL_VERSION, "cmd": cmd}
    if kwargs:
        req.update(kwargs)
    return req


def make_response(ok: bool, **kwargs: Any) -> dict[str, Any]:
    """Build a response dict."""
    resp: dict[str, Any] = {"ok": ok}
    if kwargs:
        resp.update(kwargs)
    return resp


def make_error(message: str) -> dict[str, Any]:
    """Build an error response."""
    return make_response(False, error=message)
