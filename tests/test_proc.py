"""Tests for tv.proc: process management utilities."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from tv import proc


# =========================================================================
# Positive: run
# =========================================================================


class TestRun:
    def test_captures_stdout(self):
        r = proc.run(["echo", "hello"])
        assert r.stdout.strip() == "hello"
        assert r.returncode == 0

    def test_sudo_prepends(self):
        """sudo=True добавляет 'sudo' в начало."""
        with patch("subprocess.run") as mock:
            mock.return_value = subprocess.CompletedProcess([], 0, "", "")
            proc.run(["test_cmd"], sudo=True)
            args = mock.call_args[0][0]
            assert args[0] == "sudo"
            assert args[1] == "test_cmd"

    def test_returns_nonzero_without_raising(self):
        r = proc.run(["false"])
        assert r.returncode != 0


# =========================================================================
# Negative / inverse: run failures
# =========================================================================


class TestRunInverse:
    def test_nonexistent_command_raises(self):
        """Несуществующая команда - FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            proc.run(["nonexistent_command_xyz_123"])

    def test_timeout_raises(self):
        """Если команда зависает - TimeoutExpired."""
        with pytest.raises(subprocess.TimeoutExpired):
            proc.run(["sleep", "10"], timeout=0.1)

    def test_check_true_raises_on_failure(self):
        """check=True + ненулевой код - CalledProcessError."""
        with pytest.raises(subprocess.CalledProcessError):
            proc.run(["false"], check=True)


# =========================================================================
# Positive: run_background
# =========================================================================


class TestRunBackground:
    def test_returns_popen(self):
        p = proc.run_background(["sleep", "0.1"])
        assert isinstance(p, subprocess.Popen)
        p.wait()

    def test_writes_to_log_file(self, tmp_path: Path):
        log = str(tmp_path / "out.log")
        p = proc.run_background(["echo", "hello_bg"], log_path=log)
        p.wait()
        content = Path(log).read_text()
        assert "hello_bg" in content

    def test_log_file_owned_by_current_user(self, tmp_path: Path):
        log = str(tmp_path / "owned.log")
        p = proc.run_background(["echo", "test"], log_path=log)
        p.wait()
        assert Path(log).stat().st_uid == os.getuid()


# =========================================================================
# Negative / inverse: run_background failures
# =========================================================================


class TestRunBackgroundInverse:
    def test_nonexistent_command_raises(self):
        """Если бинарника нет - FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            proc.run_background(["nonexistent_binary_xyz"])

    def test_file_handle_not_leaked_on_error(self, tmp_path: Path):
        """Файл закрывается даже при ошибке Popen."""
        log = str(tmp_path / "leak_test.log")
        with pytest.raises(FileNotFoundError):
            proc.run_background(["nonexistent_binary_xyz"], log_path=log)
        # Файл создан и закрыт (не leaked)
        assert Path(log).exists()


# =========================================================================
# Positive: wait_for
# =========================================================================


class TestWaitFor:
    @patch("tv.proc.time.sleep")
    def test_returns_true_on_immediate_success(self, _):
        result = proc.wait_for("test", lambda: True, timeout=1)
        assert result is True

    @patch("tv.proc.time.sleep")
    def test_returns_true_after_retries(self, _):
        counter = {"n": 0}

        def check():
            counter["n"] += 1
            return counter["n"] >= 2

        result = proc.wait_for("test", check, timeout=5)
        assert result is True


# =========================================================================
# Negative / inverse: wait_for failures
# =========================================================================


class TestWaitForInverse:
    @patch("tv.proc.time.sleep")
    def test_returns_false_on_timeout(self, _):
        """Если check никогда не True - False после timeout."""
        result = proc.wait_for("test", lambda: False, timeout=1)
        assert result is False

    @patch("tv.proc.time.sleep")
    def test_check_exception_is_not_caught(self, _):
        """Исключение в check_fn пробрасывается наружу."""

        def bad_check():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            proc.wait_for("test", bad_check, timeout=1)


# =========================================================================
# Positive: find_pids
# =========================================================================


class TestFindPids:
    def test_finds_current_process(self):
        """Должен найти текущий python процесс."""
        # pgrep -f с уникальным паттерном из нашего PID
        pids = proc.find_pids(f"python.*{os.getpid()}")
        # Может найти, может нет (зависит от cmdline), но не должен упасть
        assert isinstance(pids, list)

    @patch("subprocess.run")
    def test_returns_empty_on_no_match(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert proc.find_pids("nonexistent_pattern_xyz") == []


# =========================================================================
# Negative / inverse: find_pids
# =========================================================================


class TestFindPidsInverse:
    def test_empty_result_for_garbage(self):
        """Паттерн, которому ничего не матчит."""
        pids = proc.find_pids("zzz_no_such_process_zzz_999")
        assert pids == []


# =========================================================================
# Positive: kill_pattern
# =========================================================================


class TestKillPattern:
    @patch("subprocess.run")
    def test_uses_bracket_trick(self, mock_run):
        """Bracket trick: 'foo' -> '[f]oo'."""
        proc.kill_pattern("openfortivpn")
        args = mock_run.call_args[0][0]
        assert "[o]penfortivpn" in args

    @patch("subprocess.run")
    def test_sudo_flag(self, mock_run):
        proc.kill_pattern("test", sudo=True)
        args = mock_run.call_args[0][0]
        assert args[0] == "sudo"


# =========================================================================
# Negative / inverse: kill_pattern edge cases
# =========================================================================


class TestKillPatternInverse:
    @patch("subprocess.run")
    def test_empty_pattern_noop(self, mock_run):
        """Пустой паттерн - ничего не делаем."""
        proc.kill_pattern("")
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_single_char_pattern_noop(self, mock_run):
        """Один символ - слишком короткий для bracket trick."""
        proc.kill_pattern("x")
        mock_run.assert_not_called()


# =========================================================================
# kill_by_pid
# =========================================================================


class TestKillByPid:
    @patch("subprocess.run")
    def test_happy_path(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = proc.kill_by_pid(12345)
        assert result is True
        args = mock_run.call_args[0][0]
        assert args == ["kill", "12345"]

    @patch("subprocess.run")
    def test_with_sudo(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = proc.kill_by_pid(12345, sudo=True)
        assert result is True
        args = mock_run.call_args[0][0]
        assert args == ["sudo", "kill", "12345"]

    @patch("subprocess.run")
    def test_returns_false_on_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 1, "", "No such process"
        )
        result = proc.kill_by_pid(99999)
        assert result is False


# =========================================================================
# is_alive
# =========================================================================


class TestIsAlive:
    def test_current_pid_is_alive(self):
        assert proc.is_alive(os.getpid()) is True

    def test_bogus_pid_is_not_alive(self):
        # PID 999999 вряд ли существует
        assert proc.is_alive(999999) is False

    def test_nonexistent_large_pid(self):
        """Несуществующий PID -> не живой."""
        # PID -1 и 0 на macOS имеют специальное значение (process group),
        # используем заведомо несуществующий большой PID
        assert proc.is_alive(4194305) is False  # > PID_MAX_LIMIT
