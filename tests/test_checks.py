"""Tests for tv.checks: health check primitives and runner."""

from __future__ import annotations

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from tv.checks import (
    _check_port,
    _check_ping,
    _check_dns,
    _check_http,
    get_external_ip,
    _run_one,
)


# =========================================================================
# Positive: primitives
# =========================================================================


class TestCheckPort:
    @patch("subprocess.run")
    def test_open_port(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        assert _check_port("127.0.0.1", 80) is True

    @patch("subprocess.run")
    def test_uses_nc(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        _check_port("host", 443, timeout=3)
        args = mock_run.call_args[0][0]
        assert "nc" in args
        assert "-w" in args
        assert "3" in args


class TestCheckPing:
    @pytest.mark.parametrize(
        "platform,flag,absent_flag",
        [
            ("Darwin", "-t", "-W"),
            ("Linux", "-W", "-t"),
        ],
    )
    @patch("subprocess.run")
    def test_platform_ping_flag(self, mock_run, platform, flag, absent_flag):
        """Platform-specific ping timeout flag."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch("platform.system", return_value=platform):
            _check_ping("127.0.0.1", timeout=3)
        args = mock_run.call_args[0][0]
        assert flag in args
        assert absent_flag not in args


class TestCheckDns:
    @patch("subprocess.run")
    def test_resolves(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "...", "")
        assert _check_dns("test.local", "10.0.0.1") is True


class TestCheckHttp:
    @pytest.mark.parametrize("status_code", ["200", "301"])
    @patch("subprocess.run")
    def test_success_codes(self, mock_run, status_code):
        mock_run.return_value = subprocess.CompletedProcess([], 0, status_code, "")
        assert _check_http("https://example.com") is True


class TestGetExternalIp:
    @patch("subprocess.run")
    def test_returns_ip(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "1.2.3.4", "")
        assert get_external_ip("https://ifconfig.me") == "1.2.3.4"


# =========================================================================
# Negative / inverse: check failures
# =========================================================================


class TestCheckPortInverse:
    @patch("subprocess.run")
    def test_closed_port(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert _check_port("127.0.0.1", 99999) is False


class TestCheckPingInverse:
    @patch("platform.system", return_value="Darwin")
    @patch("subprocess.run")
    def test_unreachable_host(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess([], 2, "", "")
        assert _check_ping("192.0.2.1") is False


class TestCheckDnsInverse:
    @patch("subprocess.run")
    def test_nxdomain(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "NXDOMAIN")
        assert _check_dns("nonexistent.invalid", "8.8.8.8") is False


class TestCheckHttpInverse:
    @pytest.mark.parametrize(
        "rc,stdout",
        [
            (0, "000"),  # curl timeout
            (7, ""),  # curl connection refused
            (0, "500"),  # server error (не начинается с 2 или 3)
        ],
    )
    @patch("subprocess.run")
    def test_failure_codes(self, mock_run, rc, stdout):
        mock_run.return_value = subprocess.CompletedProcess([], rc, stdout, "")
        assert _check_http("https://unreachable.test") is False


class TestGetExternalIpInverse:
    @pytest.mark.parametrize(
        "rc,stdout",
        [
            (28, ""),  # curl timeout
            (0, ""),  # empty response
        ],
    )
    @patch("subprocess.run")
    def test_returns_none(self, mock_run, rc, stdout):
        mock_run.return_value = subprocess.CompletedProcess([], rc, stdout, "")
        assert get_external_ip("https://ifconfig.me") is None


# =========================================================================
# Positive: run_one
# =========================================================================


class TestRunOne:
    def test_ok_result(self, capsys):
        r = _run_one(1, True, "test", lambda: True, "ok_msg", "fail_msg", None)
        assert r.status == "ok"
        assert r.detail == "ok_msg"

    def test_skip_when_guard_false(self, capsys):
        r = _run_one(1, False, "test", lambda: True, "ok", "fail", None)
        assert r.status == "skip"


# =========================================================================
# Negative / inverse: run_one failures
# =========================================================================


class TestRunOneInverse:
    def test_fail_result(self, capsys):
        r = _run_one(1, True, "test", lambda: False, "ok", "fail_msg", None)
        assert r.status == "fail"
        assert r.detail == "fail_msg"

    def test_exception_in_check_is_fail(self, capsys):
        """Исключение в check-функции = fail, не crash."""
        r = _run_one(1, True, "test", lambda: 1 / 0, "ok", "error", None)
        assert r.status == "fail"


# =========================================================================
# Quiet mode: _collect_check_tasks & run_all_quiet
# =========================================================================

from tv.checks import _collect_check_tasks, run_all_quiet  # noqa: E402


class TestCollectCheckTasks:
    def test_empty_input(self):
        assert _collect_check_tasks([]) == []

    def test_empty_checks(self):
        assert _collect_check_tasks([("tun", True, {})]) == []

    def test_collects_ports(self):
        checks = {"ports": [{"host": "10.0.0.1", "port": 22}]}
        tasks = _collect_check_tasks([("tun", True, checks)])
        assert len(tasks) == 1
        assert tasks[0][0] == "10.0.0.1:22"
        assert tasks[0][1] is True  # guard

    def test_collects_ping(self):
        checks = {"ping": [{"host": "10.0.0.1", "label": "DNS"}]}
        tasks = _collect_check_tasks([("tun", True, checks)])
        assert len(tasks) == 1
        assert "10.0.0.1" in tasks[0][0]
        assert "DNS" in tasks[0][0]

    def test_collects_dns(self):
        checks = {"dns": [{"name": "app.local", "server": "10.0.1.1"}]}
        tasks = _collect_check_tasks([("tun", True, checks)])
        assert len(tasks) == 1
        assert "app.local" in tasks[0][0]
        assert "@10.0.1.1" in tasks[0][0]

    def test_collects_http(self):
        checks = {"http": ["https://google.com"]}
        tasks = _collect_check_tasks([("tun", True, checks)])
        assert len(tasks) == 1
        assert "google.com" in tasks[0][0]

    def test_collects_external_ip(self):
        checks = {"external_ip_url": "https://ifconfig.me"}
        tasks = _collect_check_tasks([("tun", True, checks)])
        assert len(tasks) == 1
        assert tasks[0][2] == "ext_ip"

    def test_skips_invalid_entries(self):
        checks = {
            "ports": [{"host": "", "port": 0}, {"host": "ok", "port": 80}],
            "ping": [{"host": ""}],
            "dns": [{"name": "", "server": ""}],
        }
        tasks = _collect_check_tasks([("tun", True, checks)])
        assert len(tasks) == 1  # only valid port entry

    def test_guard_propagated(self):
        checks = {"ports": [{"host": "h", "port": 80}]}
        tasks = _collect_check_tasks([("tun", False, checks)])
        assert tasks[0][1] is False

    def test_multiple_tunnels(self):
        c1 = {"ports": [{"host": "a", "port": 1}]}
        c2 = {"ports": [{"host": "b", "port": 2}]}
        tasks = _collect_check_tasks([("t1", True, c1), ("t2", False, c2)])
        assert len(tasks) == 2
        assert tasks[0][0] == "a:1"
        assert tasks[1][0] == "b:2"


class TestRunAllQuiet:
    def test_empty_checks(self):
        results, ext_ip = run_all_quiet([])
        assert results == []
        assert ext_ip == ""

    @patch("socket.create_connection")
    @patch("subprocess.run")
    def test_all_pass(self, mock_run, mock_sock, capsys):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        mock_sock.return_value.__enter__ = lambda s: s
        mock_sock.return_value.__exit__ = lambda s, *a: None
        checks = {"ports": [{"host": "h", "port": 80}]}
        results, _ = run_all_quiet([("tun", True, checks)])
        assert len(results) == 1
        assert results[0].status == "ok"
        err = capsys.readouterr().err
        assert "1/1" in err
        assert "passed" in err

    @patch("socket.create_connection", side_effect=OSError("refused"))
    @patch("subprocess.run")
    def test_fail_shows_failed_count(self, mock_run, mock_sock, capsys):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        checks = {"ports": [{"host": "h", "port": 80}]}
        results, _ = run_all_quiet([("tun", True, checks)])
        assert results[0].status == "fail"
        err = capsys.readouterr().err
        assert "failed" in err

    def test_skip_when_guard_false(self, capsys):
        checks = {"ports": [{"host": "h", "port": 80}]}
        results, _ = run_all_quiet([("tun", False, checks)])
        assert results[0].status == "skip"

    @patch("subprocess.run")
    def test_external_ip_captured(self, mock_run, capsys):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "1.2.3.4", "")
        checks = {"external_ip_url": "https://ifconfig.me"}
        results, ext_ip = run_all_quiet([("tun", True, checks)])
        assert ext_ip == "1.2.3.4"
        assert results[0].status == "ok"
        err = capsys.readouterr().err
        assert "1.2.3.4" in err

    def test_logger_receives_entries(self):
        log = MagicMock()
        checks = {"ports": [{"host": "h", "port": 80}]}
        mock_sock = MagicMock()
        with (
            patch(
                "subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
            patch("socket.create_connection", return_value=mock_sock),
        ):
            run_all_quiet([("tun", True, checks)], logger=log)
        log.log.assert_called()
