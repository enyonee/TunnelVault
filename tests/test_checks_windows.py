"""Tests for tv.checks: Windows-specific check behavior."""

from __future__ import annotations

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from tv.checks import (
    _check_port,
    _check_ping,
    _check_http,
    _check_http_any,
    get_external_ip,
    _ping_hint,
    _urllib_get,
)


# =========================================================================
# Windows: _check_port uses socket instead of nc
# =========================================================================

class TestCheckPortWindows:
    @patch("tv.checks.IS_WINDOWS", True)
    @patch("socket.create_connection")
    def test_port_open_via_socket(self, mock_conn):
        mock_conn.return_value.__enter__ = MagicMock()
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        assert _check_port("127.0.0.1", 80) is True

    @patch("tv.checks.IS_WINDOWS", True)
    @patch("socket.create_connection", side_effect=OSError("Connection refused"))
    def test_port_closed_via_socket(self, _):
        assert _check_port("127.0.0.1", 99999) is False

    @patch("tv.checks.IS_WINDOWS", False)
    @patch("shutil.which", return_value=None)
    @patch("socket.create_connection")
    def test_fallback_to_socket_when_no_nc(self, mock_conn, _):
        """Even on non-Windows, falls back to socket if nc not found."""
        mock_conn.return_value.__enter__ = MagicMock()
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        assert _check_port("127.0.0.1", 80) is True


# =========================================================================
# Windows: _check_ping uses -n flag
# =========================================================================

class TestCheckPingWindows:
    @patch("platform.system", return_value="Windows")
    @patch("subprocess.run")
    def test_windows_ping_flags(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        _check_ping("127.0.0.1", timeout=3)
        args = mock_run.call_args[0][0]
        assert "-n" in args
        assert "1" in args
        assert "-w" in args
        assert "3000" in args  # timeout in milliseconds
        assert "-c" not in args


# =========================================================================
# _ping_hint
# =========================================================================

class TestPingHintWindows:
    @patch("platform.system", return_value="Windows")
    def test_windows_hint(self, _):
        hint = _ping_hint("10.0.0.1")
        assert "-n 1" in hint
        assert "-w 3000" in hint


# =========================================================================
# HTTP: urllib fallback
# =========================================================================

class TestUrllibFallback:
    @patch("shutil.which", return_value=None)
    @patch("tv.checks._urllib_get", return_value=(200, ""))
    def test_check_http_uses_urllib(self, mock_urllib, _):
        assert _check_http("https://example.com") is True

    @patch("shutil.which", return_value=None)
    @patch("tv.checks._urllib_get", return_value=(500, ""))
    def test_check_http_fails_on_5xx(self, mock_urllib, _):
        assert _check_http("https://example.com") is False

    @patch("shutil.which", return_value=None)
    @patch("tv.checks._urllib_get", return_value=(0, ""))
    def test_check_http_fails_on_timeout(self, mock_urllib, _):
        assert _check_http("https://example.com") is False

    @patch("shutil.which", return_value=None)
    @patch("tv.checks._urllib_get", return_value=(301, ""))
    def test_check_http_ok_on_redirect(self, mock_urllib, _):
        assert _check_http("https://example.com") is True

    @patch("shutil.which", return_value=None)
    @patch("tv.checks._urllib_get", return_value=(200, ""))
    def test_check_http_any_uses_urllib(self, mock_urllib, _):
        assert _check_http_any("https://example.com") is True

    @patch("shutil.which", return_value=None)
    @patch("tv.checks._urllib_get", return_value=(0, ""))
    def test_check_http_any_fails_on_zero(self, mock_urllib, _):
        assert _check_http_any("https://example.com") is False

    @patch("shutil.which", return_value=None)
    @patch("tv.checks._urllib_get", return_value=(200, "1.2.3.4"))
    def test_get_external_ip_uses_urllib(self, mock_urllib, _):
        assert get_external_ip("https://ifconfig.me") == "1.2.3.4"

    @patch("shutil.which", return_value=None)
    @patch("tv.checks._urllib_get", return_value=(0, ""))
    def test_get_external_ip_fails(self, mock_urllib, _):
        assert get_external_ip("https://ifconfig.me") is None
