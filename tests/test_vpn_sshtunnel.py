"""Tests for SSHTunnelPlugin: SSH tunnel via SOCKS proxy or sshuttle."""

from __future__ import annotations

import contextlib
from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.sshtunnel import SSHTunnelPlugin


@contextlib.contextmanager
def _socks_connect_ok(plugin, *, socks_port=1080):
    """Set up successful SOCKS connect: ssh spawns, port opens."""
    mock_popen = MagicMock()
    mock_popen.pid = 5555
    with patch("tv.vpn.sshtunnel.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.is_alive.return_value = True
        mock_proc.wait_for.return_value = True
        yield mock_proc


@contextlib.contextmanager
def _socks_connect_fail_port(plugin):
    """Set up SOCKS connect failure: port never opens."""
    mock_popen = MagicMock()
    mock_popen.pid = 5555
    with patch("tv.vpn.sshtunnel.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.is_alive.return_value = True
        mock_proc.wait_for.return_value = False
        yield mock_proc


@contextlib.contextmanager
def _socks_connect_fail_exit(plugin):
    """Set up SOCKS connect failure: ssh process exits immediately."""
    mock_popen = MagicMock()
    mock_popen.pid = 5555
    with patch("tv.vpn.sshtunnel.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.is_alive.return_value = False
        mock_proc.wait_for.return_value = False
        yield mock_proc


@contextlib.contextmanager
def _sshuttle_connect_ok(plugin):
    """Set up successful sshuttle connect."""
    mock_popen = MagicMock()
    mock_popen.pid = 6666
    with (
        patch("tv.vpn.sshtunnel.proc") as mock_proc,
        patch("tv.vpn.sshtunnel.shutil.which", return_value="/usr/bin/sshuttle"),
    ):
        mock_proc.run_background.return_value = mock_popen
        mock_proc.is_alive.return_value = True
        mock_proc.wait_for.return_value = True
        yield mock_proc


@contextlib.contextmanager
def _sshuttle_connect_fail_binary(plugin):
    """Set up sshuttle connect failure: binary not found."""
    with patch("tv.vpn.sshtunnel.shutil.which", return_value=None):
        yield


@pytest.fixture
def socks_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="ssh-socks",
        type="sshtunnel",
        order=5,
        log=str(tmp_dir / "sshtunnel.log"),
        auth={"host": "user@example.com", "port": "22"},
        extra={"mode": "socks", "socks_port": "1080"},
    )


@pytest.fixture
def shuttle_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="ssh-shuttle",
        type="sshtunnel",
        order=5,
        log=str(tmp_dir / "sshtunnel.log"),
        auth={"host": "user@example.com", "port": "22"},
        extra={"mode": "sshuttle", "subnets": "10.0.0.0/8,192.168.0.0/16"},
    )


@pytest.fixture
def socks_plugin(socks_cfg, mock_net, logger, tmp_dir):
    return SSHTunnelPlugin(socks_cfg, mock_net, logger, tmp_dir)


@pytest.fixture
def shuttle_plugin(shuttle_cfg, mock_net, logger, tmp_dir):
    return SSHTunnelPlugin(shuttle_cfg, mock_net, logger, tmp_dir)


# =========================================================================
# Meta
# =========================================================================


class TestMeta:
    def test_process_name_socks(self, socks_plugin):
        assert socks_plugin.process_name == "ssh"

    def test_process_name_sshuttle(self, shuttle_plugin):
        assert shuttle_plugin.process_name == "sshuttle"

    def test_display_name_socks(self, socks_plugin):
        assert "socks" in socks_plugin.display_name.lower()

    def test_display_name_sshuttle(self, shuttle_plugin):
        assert "sshuttle" in shuttle_plugin.display_name.lower()

    def test_registered(self):
        from tv.vpn.registry import get_plugin

        assert get_plugin("sshtunnel") is SSHTunnelPlugin

    def test_binary(self):
        assert SSHTunnelPlugin.binary == "ssh"

    def test_type_display_name(self):
        assert SSHTunnelPlugin.type_display_name == "SSH Tunnel"

    def test_process_names(self):
        assert "ssh -D" in SSHTunnelPlugin.process_names
        assert "sshuttle" in SSHTunnelPlugin.process_names

    def test_process_names_do_not_match_ssh_agent(self):
        # Голый "ssh" ловил ssh-agent/sshd подстрокой (фантом в --status)
        assert "ssh" not in SSHTunnelPlugin.process_names

    def test_config_schema(self):
        schema = SSHTunnelPlugin.config_schema()
        keys = [p.key for p in schema]
        assert "host" in keys
        assert "mode" in keys
        assert "port" in keys
        assert "identity_file" in keys
        assert "socks_port" in keys
        assert "subnets" in keys

    def test_config_schema_host_required(self):
        schema = SSHTunnelPlugin.config_schema()
        host_param = next(p for p in schema if p.key == "host")
        assert host_param.required is True
        assert host_param.env_var == "VPN_SSH_HOST"


# =========================================================================
# SOCKS mode: successful connection
# =========================================================================


class TestConnectSOCKS:
    def test_normal_connection(self, socks_plugin):
        """ssh -D spawns, SOCKS port opens."""
        with _socks_connect_ok(socks_plugin):
            r = socks_plugin.connect()

        assert r.ok is True
        assert r.pid == 5555
        assert "socks5" in r.detail

    def test_builds_correct_command(self, socks_plugin):
        """Verify ssh command includes -D, -N, ServerAliveInterval."""
        with _socks_connect_ok(socks_plugin) as mock_proc:
            socks_plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert cmd[0] == "ssh"
        assert "-D" in cmd
        assert "1080" in cmd
        assert "-N" in cmd
        assert "ServerAliveInterval=30" in " ".join(cmd)
        assert "user@example.com" in cmd

    def test_custom_socks_port(self, socks_plugin):
        """Custom SOCKS port used in command."""
        socks_plugin.cfg.extra["socks_port"] = "9999"
        with _socks_connect_ok(socks_plugin) as mock_proc:
            socks_plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert "9999" in cmd

    def test_identity_file(self, socks_plugin):
        """Identity file added to command."""
        socks_plugin.cfg.extra["identity_file"] = "/home/user/.ssh/id_ed25519"
        with _socks_connect_ok(socks_plugin) as mock_proc:
            socks_plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert "-i" in cmd
        assert "/home/user/.ssh/id_ed25519" in cmd

    def test_custom_ssh_port(self, socks_plugin):
        """Non-default SSH port added to command."""
        socks_plugin.cfg.auth["port"] = "2222"
        with _socks_connect_ok(socks_plugin) as mock_proc:
            socks_plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert "-p" in cmd
        assert "2222" in cmd

    def test_default_port_not_in_cmd(self, socks_plugin):
        """Default SSH port 22 is not explicitly added to command."""
        socks_plugin.cfg.auth["port"] = "22"
        with _socks_connect_ok(socks_plugin) as mock_proc:
            socks_plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert "-p" not in cmd

    def test_no_sudo(self, socks_plugin):
        """SOCKS mode does not use sudo."""
        with _socks_connect_ok(socks_plugin) as mock_proc:
            socks_plugin.connect()

        call_kwargs = mock_proc.run_background.call_args
        # sudo not passed or False
        assert call_kwargs[1].get("sudo") is not True


# =========================================================================
# sshuttle mode: successful connection
# =========================================================================


class TestConnectSshuttle:
    def test_normal_connection(self, shuttle_plugin):
        """sshuttle spawns and stays alive."""
        with _sshuttle_connect_ok(shuttle_plugin):
            r = shuttle_plugin.connect()

        assert r.ok is True
        assert r.pid == 6666
        assert "sshuttle" in r.detail

    def test_builds_correct_command(self, shuttle_plugin):
        """Verify sshuttle command includes -r, subnets, --dns."""
        with _sshuttle_connect_ok(shuttle_plugin) as mock_proc:
            shuttle_plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert cmd[0] == "sshuttle"
        assert "-r" in cmd
        assert "user@example.com" in cmd
        assert "10.0.0.0/8" in cmd
        assert "192.168.0.0/16" in cmd
        assert "--dns" in cmd

    def test_sudo(self, shuttle_plugin):
        """sshuttle runs with sudo."""
        with _sshuttle_connect_ok(shuttle_plugin) as mock_proc:
            shuttle_plugin.connect()

        call_kwargs = mock_proc.run_background.call_args
        assert call_kwargs[1].get("sudo") is True

    def test_default_subnets(self, shuttle_plugin):
        """When subnets empty, defaults to 0/0."""
        shuttle_plugin.cfg.extra["subnets"] = ""
        with _sshuttle_connect_ok(shuttle_plugin) as mock_proc:
            shuttle_plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert "0/0" in cmd

    def test_custom_ssh_port_in_sshuttle(self, shuttle_plugin):
        """Non-default SSH port passed via -e to sshuttle."""
        shuttle_plugin.cfg.auth["port"] = "2222"
        with _sshuttle_connect_ok(shuttle_plugin) as mock_proc:
            shuttle_plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert "-e" in cmd
        # Find the -e argument value
        e_idx = cmd.index("-e")
        ssh_sub = cmd[e_idx + 1]
        assert "-p 2222" in ssh_sub

    def test_identity_in_sshuttle(self, shuttle_plugin):
        """Identity file passed via -e to sshuttle."""
        shuttle_plugin.cfg.extra["identity_file"] = "/root/.ssh/key"
        with _sshuttle_connect_ok(shuttle_plugin) as mock_proc:
            shuttle_plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert "-e" in cmd
        e_idx = cmd.index("-e")
        ssh_sub = cmd[e_idx + 1]
        assert "-i /root/.ssh/key" in ssh_sub


# =========================================================================
# Connection failures
# =========================================================================


class TestConnectFailure:
    def test_socks_port_not_open(self, socks_plugin, capsys):
        """SOCKS port never opens - process alive but port closed."""
        with _socks_connect_fail_port(socks_plugin):
            r = socks_plugin.connect()

        assert r.ok is False

    def test_socks_process_exits(self, socks_plugin, capsys):
        """ssh exits immediately."""
        with _socks_connect_fail_exit(socks_plugin):
            r = socks_plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "ssh" in out.lower() or "SSH" in out

    def test_sshuttle_binary_not_found(self, shuttle_plugin, capsys):
        """sshuttle not installed."""
        with _sshuttle_connect_fail_binary(shuttle_plugin):
            r = shuttle_plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "sshuttle" in out.lower() or "not installed" in out.lower()

    def test_no_host_configured(self, socks_plugin, capsys):
        """Host not set returns failure."""
        socks_plugin.cfg.auth["host"] = ""
        with patch("tv.vpn.sshtunnel.proc"):
            r = socks_plugin.connect()

        assert r.ok is False


# =========================================================================
# Disconnect
# =========================================================================


class TestDisconnect:
    def test_disconnect_kills_pid(self, socks_plugin):
        """disconnect() kills process by PID."""
        socks_plugin._pid = 5555
        with patch("tv.vpn.base.proc") as mock_base_proc:
            mock_base_proc.is_alive.return_value = True
            mock_base_proc.kill_by_pid.return_value = None
            socks_plugin.disconnect()

        mock_base_proc.kill_by_pid.assert_called_once()

    def test_disconnect_pattern_fallback_socks(self, socks_plugin):
        """Fallback to pattern kill for SOCKS mode."""
        socks_plugin._pid = None
        with patch("tv.vpn.sshtunnel.proc") as mock_proc:
            mock_proc.is_alive.return_value = False
            socks_plugin.disconnect()

        mock_proc.kill_pattern.assert_called_once()
        pattern = mock_proc.kill_pattern.call_args[0][0]
        assert "ssh -D" in pattern
        assert "example.com" in pattern

    def test_disconnect_pattern_fallback_sshuttle(self, shuttle_plugin):
        """Fallback to pattern kill for sshuttle mode."""
        shuttle_plugin._pid = None
        with patch("tv.vpn.sshtunnel.proc") as mock_proc:
            mock_proc.is_alive.return_value = False
            shuttle_plugin.disconnect()

        mock_proc.kill_pattern.assert_called_once()
        pattern = mock_proc.kill_pattern.call_args[0][0]
        assert "sshuttle" in pattern
        assert "example.com" in pattern


# =========================================================================
# discover_pid
# =========================================================================


class TestDiscoverPid:
    def test_discover_socks(self, socks_cfg, tmp_dir):
        """discover_pid finds ssh -D process matching host."""
        with patch("tv.vpn.sshtunnel.proc") as mock_proc:
            mock_proc.find_pids.return_value = [4444]
            pid = SSHTunnelPlugin.discover_pid(socks_cfg, tmp_dir)

        assert pid == 4444

    def test_discover_sshuttle(self, shuttle_cfg, tmp_dir):
        """discover_pid finds sshuttle process matching host."""
        with patch("tv.vpn.sshtunnel.proc") as mock_proc:
            # First call (ssh -D) returns nothing, second (sshuttle) matches
            mock_proc.find_pids.side_effect = [[], [7777]]
            pid = SSHTunnelPlugin.discover_pid(shuttle_cfg, tmp_dir)

        assert pid == 7777

    def test_discover_no_host(self, socks_cfg, tmp_dir):
        """discover_pid returns None when host not set."""
        socks_cfg.auth = {}
        pid = SSHTunnelPlugin.discover_pid(socks_cfg, tmp_dir)
        assert pid is None
