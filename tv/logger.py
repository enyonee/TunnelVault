"""Dual logger: file + optional debug stderr, backed by stdlib logging."""

from __future__ import annotations

import datetime
import logging
import os
import platform as plat
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from tv.app_config import cfg

if TYPE_CHECKING:
    from tv.net import NetManager

# --- Custom levels (between INFO=20 and WARNING=30) ---

WAIT = 21
ENV = 22
CHECK = 23

logging.addLevelName(WAIT, "WAIT")
logging.addLevelName(ENV, "ENV")
logging.addLevelName(CHECK, "CHECK")

# String -> numeric (covers both app and stdlib names)
_LEVEL_MAP: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WAIT": WAIT,
    "ENV": ENV,
    "CHECK": CHECK,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "FATAL": logging.CRITICAL,
    "CRITICAL": logging.CRITICAL,
}

# Numeric -> app display name (for non-standard mappings)
_DISPLAY_NAMES: dict[int, str] = {
    logging.WARNING: "WARN",
    logging.CRITICAL: "FATAL",
}


class _TVFormatter(logging.Formatter):
    """Format: [2026-02-22 14:30:45.123] [LEVEL] message"""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.datetime.fromtimestamp(record.created).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]
        level = _DISPLAY_NAMES.get(record.levelno, record.levelname)
        return f"[{ts}] [{level}] {record.getMessage()}"


class _StderrFormatter(_TVFormatter):
    """Same format wrapped in ANSI dim."""

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        return f"\033[2m{line}\033[0m"


def _parse_level(level_str: str) -> int:
    """Parse level string to numeric, fallback to DEBUG."""
    return _LEVEL_MAP.get(level_str.upper(), logging.DEBUG)


class Logger:
    """Drop-in replacement wrapping stdlib logging.

    Public API unchanged:
        .log(level, msg)
        .log_lines(level, text)
        .log_env(net, script_dir)
        .log_path
    """

    def __init__(self, log_path: Path, debug: bool = False):
        self.log_path = log_path
        self.debug = debug

        # Unique logger name per instance (avoids handler conflicts in tests)
        name = f"tunnelvault.{log_path.stem}.{id(self)}"
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)  # let handlers filter
        self._logger.propagate = False
        self._logger.handlers.clear()

        # File handler
        mode = "w" if cfg.logging.truncate_on_start else "a"
        fh = logging.FileHandler(str(log_path), mode=mode, encoding="utf-8")
        fh.setLevel(_parse_level(cfg.logging.level))
        fh.setFormatter(_TVFormatter())
        self._logger.addHandler(fh)

        # Ensure log file is readable without sudo
        try:
            os.chmod(str(log_path), 0o644)
        except OSError:
            pass

        # Debug stderr handler
        if debug:
            sh = logging.StreamHandler(sys.stderr)
            sh.setLevel(logging.DEBUG)
            sh.setFormatter(_StderrFormatter())
            self._logger.addHandler(sh)

    def log(self, level: str, msg: str) -> None:
        numeric = _LEVEL_MAP.get(level.upper(), logging.INFO)
        self._logger.log(numeric, msg)

    def log_lines(self, level: str, text: str) -> None:
        for line in text.splitlines():
            self.log(level, f"  {line}")

    def log_env(self, net: NetManager, script_dir: Path) -> None:
        """Snapshot environment at startup."""
        self.log("ENV", "=== Environment snapshot ===")
        self.log("ENV", f"uname: {' '.join(plat.uname())}")
        try:
            user = os.getlogin()
        except OSError:
            user = os.environ.get("USER", "?")
        euid = getattr(os, "geteuid", lambda: "N/A")()
        self.log("ENV", f"whoami: {user}, EUID={euid}")
        self.log("ENV", f"SCRIPT_DIR={script_dir}")
        self.log("ENV", f"PATH={os.environ.get('PATH', '')}")

        self.log("ENV", "--- Network interfaces ---")
        for iface, addr in net.interfaces().items():
            self.log("ENV", f"  {iface} -> {addr}")

        self.log("ENV", "--- Route table (default) ---")
        self.log_lines("ENV", net.route_table())

        self.log("ENV", "--- VPN processes ---")
        from tv.vpn.registry import available_types, get_plugin

        vpn_keywords = []
        for t in available_types():
            vpn_keywords.extend(get_plugin(t).process_names)

        r = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            timeout=cfg.timeouts.ps_aux,
        )
        for line in r.stdout.splitlines():
            if any(kw in line for kw in vpn_keywords) and "grep" not in line:
                self.log("ENV", f"  {line.strip()}")

        self.log("ENV", "=== /Snapshot ===")
