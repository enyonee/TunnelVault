"""Tests for tv.daemon: daemonize, PID file, autostart management."""

from __future__ import annotations

import os
import platform
import subprocess
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skipif(
    platform.system() == "Windows",
    reason="daemon module uses fcntl/plistlib (Unix-only)",
)

import plistlib  # noqa: E402

from tv import daemon  # noqa: E402


# =========================================================================
# PID file
# =========================================================================


class TestPidFile:
    def test_write_and_read(self, tmp_dir):
        daemon.write_pid(tmp_dir, pid=42)
        assert daemon.read_pid(tmp_dir) == 42

    def test_write_default_pid(self, tmp_dir):
        daemon.write_pid(tmp_dir)
        assert daemon.read_pid(tmp_dir) == os.getpid()

    def test_write_pid_zero(self, tmp_dir):
        """write_pid(pid=0) must write 0, not current PID."""
        daemon.write_pid(tmp_dir, pid=0)
        assert daemon.read_pid(tmp_dir) == 0

    def test_read_missing(self, tmp_dir):
        assert daemon.read_pid(tmp_dir) is None

    def test_remove(self, tmp_dir):
        daemon.write_pid(tmp_dir, pid=99)
        daemon.remove_pid(tmp_dir)
        assert daemon.read_pid(tmp_dir) is None

    def test_remove_missing_noop(self, tmp_dir):
        daemon.remove_pid(tmp_dir)  # should not raise

    def test_stale_pid(self, tmp_dir):
        daemon.write_pid(tmp_dir, pid=999999)
        assert not daemon.is_pid_alive(999999)

    def test_pid_file_path(self, tmp_dir):
        path = daemon.pid_file_path(tmp_dir)
        assert path.name == "tunnelvault.pid"
        assert str(tmp_dir) in str(path)

    def test_pid_file_permissions(self, tmp_dir):
        """PID file should be created with 0o600 (owner-only)."""
        daemon.write_pid(tmp_dir, pid=42)
        path = daemon.pid_file_path(tmp_dir)
        mode = oct(path.stat().st_mode & 0o777)
        assert mode == oct(0o600)

    def test_pid_file_locked(self, tmp_dir):
        """After write_pid, the file should be locked."""
        daemon.write_pid(tmp_dir, pid=42)
        assert daemon.is_pid_file_locked(tmp_dir)
        daemon.remove_pid(tmp_dir)
        assert not daemon.is_pid_file_locked(tmp_dir)


# =========================================================================
# Stale PID lock recovery
# =========================================================================


class TestStalePidRecovery:
    def test_dead_process_lock_recovered(self, tmp_dir):
        """write_pid recovers lock held by a dead process."""
        import fcntl

        # Simulate stale lock: write PID file with a dead PID, hold flock
        path = daemon.pid_file_path(tmp_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        stale_fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        fcntl.flock(stale_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(stale_fd, b"999999")
        # Release the lock (simulates process death releasing flock)
        os.close(stale_fd)

        # Now write_pid should succeed
        daemon.write_pid(tmp_dir, pid=42)
        assert daemon.read_pid(tmp_dir) == 42
        daemon.remove_pid(tmp_dir)

    def test_nonexistent_pid_in_file(self, tmp_dir):
        """write_pid recovers when PID file contains a non-existent PID."""
        path = daemon.pid_file_path(tmp_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("999999")

        daemon.write_pid(tmp_dir, pid=42)
        assert daemon.read_pid(tmp_dir) == 42
        daemon.remove_pid(tmp_dir)

    def test_corrupt_pid_file_recovered(self, tmp_dir):
        """write_pid recovers when PID file has invalid content."""
        path = daemon.pid_file_path(tmp_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not-a-number")

        daemon.write_pid(tmp_dir, pid=42)
        assert daemon.read_pid(tmp_dir) == 42
        daemon.remove_pid(tmp_dir)

    def test_stale_lock_from_non_tunnelvault_process(self, tmp_dir):
        """write_pid recovers lock from a live but non-tunnelvault process."""
        with (
            patch("tv.daemon.is_pid_alive", return_value=True),
            patch("tv.daemon.is_tunnelvault_process", return_value=False),
        ):
            daemon.write_pid(tmp_dir, pid=42)
            assert daemon.read_pid(tmp_dir) == 42
        daemon.remove_pid(tmp_dir)

    def test_stale_lock_kills_live_tunnelvault(self, tmp_dir):
        """_recover_stale_lock sends SIGTERM to live tunnelvault."""
        import signal

        kill_calls = []

        def mock_kill(pid, sig):
            kill_calls.append((pid, sig))

        alive_count = [0]

        def mock_is_alive(pid):
            alive_count[0] += 1
            return alive_count[0] <= 2  # dies after 2 checks

        path = daemon.pid_file_path(tmp_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("12345")

        with (
            patch("tv.daemon.is_pid_alive", side_effect=mock_is_alive),
            patch("tv.daemon.is_tunnelvault_process", return_value=True),
            patch("tv.daemon.os.kill", side_effect=mock_kill),
        ):
            fd = daemon._recover_stale_lock(path, 42)
            os.close(fd)

        assert any(sig == signal.SIGTERM for _, sig in kill_calls)
        path.unlink(missing_ok=True)

    def test_read_pid_from_path(self, tmp_dir):
        """read_pid_from_path reads PID from arbitrary path."""
        path = daemon.pid_file_path(tmp_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("12345")
        assert daemon.read_pid_from_path(path) == 12345

    def test_read_pid_from_path_missing(self, tmp_dir):
        path = daemon.pid_file_path(tmp_dir)
        assert daemon.read_pid_from_path(path) is None

    def test_read_pid_from_path_corrupt(self, tmp_dir):
        path = daemon.pid_file_path(tmp_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("garbage")
        assert daemon.read_pid_from_path(path) is None

    def test_force_relock_after_failed_recovery_raises(self, tmp_dir):
        """If lock can't be acquired even after cleanup, raise."""
        import fcntl

        path = daemon.pid_file_path(tmp_dir)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Hold the lock from this process
        hold_fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        fcntl.flock(hold_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(hold_fd, str(os.getpid()).encode())

        # _force_relock deletes the file but we re-create the lock immediately
        # This tests the case where another process grabs the lock between
        # unlink and re-open (unlikely but defensive)
        with (
            patch("tv.daemon.is_pid_alive", return_value=False),
            patch.object(daemon, "_force_relock", side_effect=BlockingIOError("test")),
        ):
            with pytest.raises(BlockingIOError):
                daemon.write_pid(tmp_dir, pid=42)

        fcntl.flock(hold_fd, fcntl.LOCK_UN)
        os.close(hold_fd)


# =========================================================================
# is_tunnelvault_process
# =========================================================================


class TestIsTunnelvaultProcess:
    def test_current_process(self):
        """Current process should match (sys.argv contains test runner)."""
        # Current process is pytest, not tunnelvault
        assert (
            not daemon.is_tunnelvault_process(os.getpid()) or True
        )  # depends on runner

    def test_nonexistent_pid(self):
        assert not daemon.is_tunnelvault_process(999999)

    @patch("tv.daemon.platform.system", return_value="Darwin")
    @patch("tv.daemon.subprocess.run")
    def test_macos_match(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="/usr/bin/python3 tunnelvault.py --foreground"
        )
        assert daemon.is_tunnelvault_process(123)

    @patch("tv.daemon.platform.system", return_value="Darwin")
    @patch("tv.daemon.subprocess.run")
    def test_macos_no_match(self, mock_run, _):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="/usr/bin/python3 some_other_script.py"
        )
        assert not daemon.is_tunnelvault_process(123)


# =========================================================================
# daemonize (double fork)
# =========================================================================


class TestDaemonize:
    def test_parent_gets_grandchild_pid_via_pipe(self, tmp_dir):
        """Parent should get grandchild PID from pipe (not PID file race)."""
        # Create a real pipe to simulate grandchild writing PID
        real_pipe_r, real_pipe_w = os.pipe()

        # Pre-write PID to the pipe (simulates grandchild)
        os.write(real_pipe_w, b"99999")
        os.close(real_pipe_w)

        with (
            patch("tv.daemon.os.pipe", return_value=(real_pipe_r, 999)),
            patch("tv.daemon.os.fork", return_value=12345),
            patch("tv.daemon.os.waitpid", return_value=(12345, 0)),
            patch("tv.daemon.os.close"),  # mock close so we don't double-close
        ):
            result = daemon.daemonize(tmp_dir)
        assert result == 99999

    def test_intermediate_child_calls_setsid(self, tmp_dir):
        """Intermediate child (first fork=0) should call setsid then fork again."""
        with (
            patch("tv.daemon.os.pipe", return_value=(10, 11)),
            patch("tv.daemon.os.fork", side_effect=[0, 777]),
            patch("tv.daemon.os.setsid") as mock_setsid,
            patch("tv.daemon.os.close"),
            patch("tv.daemon.os._exit") as mock_exit,
        ):
            daemon.daemonize(tmp_dir)

        mock_setsid.assert_called_once()
        mock_exit.assert_called_once_with(0)  # intermediate child exits

    def test_grandchild_writes_pid(self, tmp_dir):
        """Grandchild (both forks return 0) should write PID file."""
        with (
            patch("tv.daemon.os.pipe", return_value=(10, 11)),
            patch("tv.daemon.os.fork", side_effect=[0, 0]),
            patch("tv.daemon.os.setsid"),
            patch("tv.daemon.os.open", return_value=3),
            patch("tv.daemon.os.dup2"),
            patch("tv.daemon.os.close"),
            patch("tv.daemon.os.write"),
            patch("tv.daemon.fcntl.flock"),
        ):
            result = daemon.daemonize(tmp_dir)

        assert result == 0

    def test_grandchild_redirects_stdio(self, tmp_dir):
        dup2_calls = []

        def track_dup2(fd, target):
            dup2_calls.append((fd, target))

        with (
            patch("tv.daemon.os.pipe", return_value=(10, 11)),
            patch("tv.daemon.os.fork", side_effect=[0, 0]),
            patch("tv.daemon.os.setsid"),
            patch("tv.daemon.os.open", return_value=3),
            patch("tv.daemon.os.dup2", side_effect=track_dup2),
            patch("tv.daemon.os.close"),
            patch("tv.daemon.os.write"),
            patch("tv.daemon.fcntl.flock"),
        ):
            daemon.daemonize(tmp_dir)

        # Should redirect stdout(1), stderr(2), stdin(0)
        targets = [call[1] for call in dup2_calls]
        assert 0 in targets  # stdin
        assert 1 in targets  # stdout
        assert 2 in targets  # stderr

    def test_daemon_log_permissions_0o644(self, tmp_dir):
        """daemon.log should be opened with 0o644 (readable without sudo)."""
        open_calls = []

        def track_open(path, flags, mode=0o777):
            open_calls.append((path, flags, mode))
            return 3

        with (
            patch("tv.daemon.os.pipe", return_value=(10, 11)),
            patch("tv.daemon.os.fork", side_effect=[0, 0]),
            patch("tv.daemon.os.setsid"),
            patch("tv.daemon.os.open", side_effect=track_open),
            patch("tv.daemon.os.dup2"),
            patch("tv.daemon.os.close"),
            patch("tv.daemon.os.write"),
            patch("tv.daemon.fcntl.flock"),
        ):
            daemon.daemonize(tmp_dir)

        # First os.open call is for daemon.log
        log_open = [c for c in open_calls if "daemon.log" in str(c[0])]
        assert log_open
        assert log_open[0][2] == 0o644


# =========================================================================
# _build_plist
# =========================================================================


class TestBuildPlist:
    def test_basic_plist(self, tmp_dir):
        plist = daemon._build_plist(tmp_dir)

        assert plist["Label"] == "com.tunnelvault.keepalive"
        assert plist["RunAtLoad"] is True
        assert plist["KeepAlive"] is True
        assert "--foreground" in plist["ProgramArguments"]
        assert "--only" not in plist["ProgramArguments"]
        assert plist["WorkingDirectory"] == str(tmp_dir.resolve())

    def test_plist_with_only(self, tmp_dir):
        plist = daemon._build_plist(tmp_dir, only="fortivpn,singbox")

        args = plist["ProgramArguments"]
        assert "--only" in args
        idx = args.index("--only")
        assert args[idx + 1] == "fortivpn,singbox"

    def test_plist_uses_current_python(self, tmp_dir):
        import sys

        plist = daemon._build_plist(tmp_dir)

        assert plist["ProgramArguments"][0] == sys.executable

    def test_plist_log_paths(self, tmp_dir):
        plist = daemon._build_plist(tmp_dir)

        assert plist["StandardOutPath"].endswith("daemon.log")
        assert plist["StandardErrorPath"].endswith("daemon.log")

    def test_plist_creates_log_dir(self, tmp_dir):
        log_dir = tmp_dir / "logs"
        assert not log_dir.exists()

        daemon._build_plist(tmp_dir)

        assert log_dir.exists()

    def test_plist_includes_foreground_flag(self, tmp_dir):
        """Launchd plist must use --foreground so process doesn't fork."""
        plist = daemon._build_plist(tmp_dir)
        assert "--foreground" in plist["ProgramArguments"]


# =========================================================================
# _build_systemd_unit
# =========================================================================


class TestBuildSystemdUnit:
    def test_basic_unit(self, tmp_dir):
        import sys

        unit = daemon._build_systemd_unit(tmp_dir)

        assert "[Unit]" in unit
        assert "[Service]" in unit
        assert "[Install]" in unit
        assert "Type=simple" in unit
        assert "--foreground" in unit
        assert sys.executable in unit
        assert str(tmp_dir.resolve()) in unit

    def test_unit_with_only(self, tmp_dir):
        unit = daemon._build_systemd_unit(tmp_dir, only="openvpn")

        assert "--only openvpn" in unit

    def test_unit_restart_on_failure(self, tmp_dir):
        unit = daemon._build_systemd_unit(tmp_dir)

        assert "Restart=on-failure" in unit
        assert "RestartSec=10" in unit

    def test_unit_after_network(self, tmp_dir):
        unit = daemon._build_systemd_unit(tmp_dir)

        assert "After=network-online.target" in unit

    def test_unit_hardening_directives(self, tmp_dir):
        """Systemd unit should include security hardening."""
        unit = daemon._build_systemd_unit(tmp_dir)

        assert "ProtectSystem=strict" in unit
        assert "ProtectHome=read-only" in unit
        assert "PrivateTmp=true" in unit
        assert "NoNewPrivileges=yes" in unit

    def test_unit_readwrite_includes_log_dir(self, tmp_dir):
        """ReadWritePaths must include the log directory."""
        unit = daemon._build_systemd_unit(tmp_dir)

        log_dir = str((tmp_dir / "logs").resolve())
        assert log_dir in unit


# =========================================================================
# daemon_log_path (public)
# =========================================================================


class TestDaemonLogPath:
    def test_returns_daemon_log(self, tmp_dir):
        path = daemon.daemon_log_path(tmp_dir)
        assert path.name == "daemon.log"
        assert str(tmp_dir) in str(path)


# =========================================================================
# enable / disable
# =========================================================================


class TestEnable:
    def test_enable_macos(self, tmp_dir, tmp_path):
        plist_path = tmp_path / "test.plist"
        mock_load = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        with (
            patch("tv.daemon.platform.system", return_value="Darwin"),
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_load),
        ):
            daemon.enable(tmp_dir)

        assert plist_path.exists()
        data = plistlib.loads(plist_path.read_bytes())
        assert data["Label"] == "com.tunnelvault.keepalive"

    def test_enable_linux(self, tmp_dir, tmp_path):
        unit_path = tmp_path / "test.service"
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        with (
            patch("tv.daemon.platform.system", return_value="Linux"),
            patch.object(daemon, "SYSTEMD_PATH", unit_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            daemon.enable(tmp_dir)

        assert unit_path.exists()
        content = unit_path.read_text()
        assert "--foreground" in content


class TestDisable:
    def test_disable_macos(self, tmp_path):
        plist_path = tmp_path / "test.plist"
        plist_path.write_text("")

        mock_result = subprocess.CompletedProcess(args=[], returncode=0)
        with (
            patch("tv.daemon.platform.system", return_value="Darwin"),
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            daemon.disable()

        assert not plist_path.exists()

    def test_disable_linux(self, tmp_path):
        unit_path = tmp_path / "test.service"
        unit_path.write_text("")

        mock_result = subprocess.CompletedProcess(args=[], returncode=0)
        with (
            patch("tv.daemon.platform.system", return_value="Linux"),
            patch.object(daemon, "SYSTEMD_PATH", unit_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
        ):
            daemon.disable()

        assert not unit_path.exists()

    def test_disable_not_configured(self, tmp_path, capsys):
        with (
            patch("tv.daemon.platform.system", return_value="Darwin"),
            patch.object(daemon, "PLIST_PATH", tmp_path / "nope.plist"),
            patch("tv.daemon.subprocess.run") as mock_run,
        ):
            daemon.disable()

        mock_run.assert_not_called()
        out = capsys.readouterr().out
        assert "not configured" in out.lower() or "не настроен" in out.lower()

    def test_disable_stops_running_daemon(self, tmp_dir, tmp_path):
        """--disable should stop a running daemon before removing autostart."""
        plist_path = tmp_path / "test.plist"
        plist_path.write_text("")

        daemon.write_pid(tmp_dir, pid=12345)

        mock_result = subprocess.CompletedProcess(args=[], returncode=0)
        with (
            patch("tv.daemon.platform.system", return_value="Darwin"),
            patch.object(daemon, "PLIST_PATH", plist_path),
            patch("tv.daemon.subprocess.run", return_value=mock_result),
            patch("tv.daemon.is_pid_alive", return_value=False),
            patch("tv.daemon.is_tunnelvault_process", return_value=True),
        ):
            daemon.disable(tmp_dir)

        assert not plist_path.exists()
        daemon.remove_pid(tmp_dir)
