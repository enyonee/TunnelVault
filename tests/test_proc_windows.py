"""Tests for tv.proc: Windows-specific process management."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from tv import proc


# =========================================================================
# Windows: find_pids via PowerShell (primary) + wmic (fallback)
# =========================================================================

class TestFindPidsWindows:
    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_finds_pids_via_powershell(self, mock_run):
        """PowerShell Get-CimInstance is tried first."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "1234\n5678\n", "",
        )
        pids = proc.find_pids("openvpn")
        assert 1234 in pids
        assert 5678 in pids
        args = mock_run.call_args_list[0][0][0]
        assert args[0] == "powershell"
        assert "Get-CimInstance" in args[3]

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_falls_back_to_wmic(self, mock_run):
        """If PowerShell fails, falls back to wmic."""
        mock_run.side_effect = [
            # PowerShell fails
            subprocess.CompletedProcess([], 1, "", "error"),
            # wmic succeeds
            subprocess.CompletedProcess(
                [], 0,
                "\r\nProcessId=1234\r\n\r\nProcessId=5678\r\n\r\n",
                "",
            ),
        ]
        pids = proc.find_pids("openvpn")
        assert 1234 in pids
        assert 5678 in pids
        assert mock_run.call_count == 2
        assert mock_run.call_args_list[1][0][0][0] == "wmic"

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_powershell_timeout_falls_back(self, mock_run):
        """PowerShell timeout triggers wmic fallback."""
        mock_run.side_effect = [
            subprocess.TimeoutExpired(cmd="powershell", timeout=5),
            subprocess.CompletedProcess(
                [], 0, "\r\nProcessId=9999\r\n", "",
            ),
        ]
        pids = proc.find_pids("openvpn")
        assert 9999 in pids

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_filters_own_pid(self, mock_run):
        import os
        own = os.getpid()
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, f"{own}\n9999\n", "",
        )
        pids = proc.find_pids("python")
        assert own not in pids
        assert 9999 in pids

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_empty_on_no_match(self, mock_run):
        """Both PowerShell and wmic return nothing."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert proc.find_pids("nonexistent") == []

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_both_binaries_missing(self, mock_run):
        """Neither powershell nor wmic found - returns empty, no crash."""
        mock_run.side_effect = FileNotFoundError("No such file")
        assert proc.find_pids("openvpn") == []

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_ps_ok_wmic_missing(self, mock_run):
        """PowerShell fails (rc=1), wmic binary missing - returns empty."""
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 1, "", ""),
            FileNotFoundError("wmic not found"),
        ]
        assert proc.find_pids("openvpn") == []


# =========================================================================
# Windows: kill_pattern via taskkill
# =========================================================================

class TestKillPatternWindows:
    @patch("tv.proc.IS_WINDOWS", True)
    @patch("tv.proc.find_pids", return_value=[1234, 5678])
    @patch("subprocess.run")
    def test_kills_via_taskkill(self, mock_run, mock_find):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        proc.kill_pattern("openvpn")
        assert mock_run.call_count == 2
        for call in mock_run.call_args_list:
            args = call[0][0]
            assert args[0] == "taskkill"
            assert "/F" in args
            assert "/PID" in args

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("tv.proc.find_pids", return_value=[])
    @patch("subprocess.run")
    def test_no_kill_on_empty(self, mock_run, mock_find):
        proc.kill_pattern("nonexistent")
        mock_run.assert_not_called()

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_empty_pattern_noop(self, mock_run):
        proc.kill_pattern("")
        mock_run.assert_not_called()


# =========================================================================
# Windows: killall via taskkill /IM
# =========================================================================

class TestKillallWindows:
    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_uses_taskkill_im(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        proc.killall("openvpn.exe")
        args = mock_run.call_args[0][0]
        assert args == ["taskkill", "/F", "/IM", "openvpn.exe"]


# =========================================================================
# Windows: kill_by_pid via taskkill /PID
# =========================================================================

class TestKillByPidWindows:
    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_kills_pid(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = proc.kill_by_pid(1234)
        assert ok is True
        args = mock_run.call_args[0][0]
        assert args == ["taskkill", "/F", "/PID", "1234"]

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_returns_false_on_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "ERROR")
        assert proc.kill_by_pid(99999) is False


# =========================================================================
# Windows: is_alive via tasklist
# =========================================================================

class TestIsAliveWindows:
    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_alive_process(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "Image Name                     PID Session Name\n"
            "========================= ======== ===============\n"
            "python.exe                    1234 Console\n",
            "",
        )
        assert proc.is_alive(1234) is True

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_dead_process(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "INFO: No tasks are running which match the specified criteria.\n",
            "",
        )
        assert proc.is_alive(99999) is False

    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_tasklist_error(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert proc.is_alive(1234) is False


# =========================================================================
# Windows: sudo skipped in run/run_background
# =========================================================================

class TestSudoSkipWindows:
    @patch("tv.proc.IS_WINDOWS", True)
    @patch("subprocess.run")
    def test_run_ignores_sudo(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        proc.run(["test_cmd"], sudo=True)
        args = mock_run.call_args[0][0]
        assert args[0] == "test_cmd"
        assert "sudo" not in args
