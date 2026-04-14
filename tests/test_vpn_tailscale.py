"""Tests for TailscalePlugin: Tailscale/Headscale connection."""

from __future__ import annotations

import contextlib
from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.tailscale import TailscalePlugin


@contextlib.contextmanager
def _ts_connect_ok(plugin, *, interface="tailscale0"):
    """Set up successful tailscale connect: run() ok, interface appears."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    with patch("tv.vpn.tailscale.proc") as mock_proc:
        mock_proc.run.return_value = mock_result
        mock_proc.wait_for.return_value = True
        mock_proc.find_pids.return_value = [9999]
        plugin.net.check_interface.return_value = True
        plugin.net.iface_info.return_value = f"{interface}: flags=8051<UP>"
        yield mock_proc


@contextlib.contextmanager
def _ts_connect_fail_setup(plugin, stderr=""):
    """Set up failing tailscale up: run() returns non-zero exit code."""
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = stderr
    with patch("tv.vpn.tailscale.proc") as mock_proc:
        mock_proc.run.return_value = mock_result
        yield mock_proc


@contextlib.contextmanager
def _ts_connect_fail_iface(plugin):
    """Set up: tailscale up ok but interface never appears."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    with (
        patch("tv.vpn.tailscale.proc") as mock_proc,
        patch("tv.vpn.tailscale.subprocess") as mock_subprocess,
    ):
        mock_proc.run.return_value = mock_result
        mock_proc.wait_for.return_value = False
        mock_proc.find_pids.return_value = []
        plugin.net.check_interface.return_value = False
        # tailscale status --json fallback also fails
        mock_status = MagicMock()
        mock_status.returncode = 1
        mock_status.stdout = ""
        mock_subprocess.run.return_value = mock_status
        yield mock_proc


@pytest.fixture
def ts_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="tailscale",
        type="tailscale",
        order=5,
        log=str(tmp_dir / "tailscale.log"),
        interface="tailscale0",
        auth={"auth_key": "tskey-auth-test123"},
        routes={
            "hosts": ["10.0.0.1"],
            "networks": ["10.0.0.0/24"],
        },
    )


@pytest.fixture
def plugin(ts_cfg, mock_net, logger, tmp_dir):
    return TailscalePlugin(ts_cfg, mock_net, logger, tmp_dir)


# =========================================================================
# Meta
# =========================================================================


class TestMeta:
    def test_process_name(self, plugin):
        assert plugin.process_name == "tailscaled"

    def test_display_name(self, plugin):
        assert plugin.display_name == "Tailscale"

    def test_registered(self):
        from tv.vpn.registry import get_plugin

        assert get_plugin("tailscale") is TailscalePlugin

    def test_binary(self):
        assert TailscalePlugin.binary == "tailscale"

    def test_type_display_name(self):
        assert TailscalePlugin.type_display_name == "Tailscale"


# =========================================================================
# Positive: successful connection
# =========================================================================


class TestConnectSuccess:
    def test_normal_connection(self, plugin):
        """tailscale up succeeds, interface appears, routes added."""
        with _ts_connect_ok(plugin):
            r = plugin.connect()

        assert r.ok is True
        assert r.pid == 9999

    def test_adds_routes_from_config(self, plugin):
        """Adds host and network routes from TunnelConfig."""
        with _ts_connect_ok(plugin):
            plugin.connect()

        route_calls = plugin.net.add_iface_route.call_args_list
        targets = [c[0][0] for c in route_calls]
        assert "10.0.0.1" in targets
        assert "10.0.0.0/24" in targets

    def test_sets_up_dns_from_config(self, plugin):
        """DNS resolver set up from TunnelConfig.dns."""
        plugin.cfg.dns = {"nameservers": ["10.0.1.1"], "domains": ["ts.local"]}
        with _ts_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_called_once_with(
            ["ts.local"],
            ["10.0.1.1"],
            "tailscale0",
        )

    def test_no_dns_when_not_configured(self, plugin):
        """No DNS setup when dns is empty."""
        plugin.cfg.dns = {}
        with _ts_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_not_called()

    def test_launches_with_sudo(self, plugin):
        """tailscale up runs with sudo."""
        with _ts_connect_ok(plugin) as mock_proc:
            plugin.connect()

        run_call = mock_proc.run.call_args
        assert run_call[1].get("sudo") is True

    def test_command_includes_auth_key(self, plugin):
        """tailscale up includes --auth-key flag."""
        with _ts_connect_ok(plugin) as mock_proc:
            plugin.connect()

        cmd = mock_proc.run.call_args[0][0]
        assert any("--auth-key=" in arg for arg in cmd)

    def test_command_includes_accept_routes(self, plugin):
        """tailscale up includes --accept-routes flag."""
        with _ts_connect_ok(plugin) as mock_proc:
            plugin.connect()

        cmd = mock_proc.run.call_args[0][0]
        assert "--accept-routes" in cmd

    def test_command_includes_login_server(self, plugin):
        """tailscale up includes --login-server when set."""
        plugin.cfg.auth["login_server"] = "https://headscale.example.com"
        with _ts_connect_ok(plugin) as mock_proc:
            plugin.connect()

        cmd = mock_proc.run.call_args[0][0]
        assert "--login-server=https://headscale.example.com" in cmd

    def test_command_includes_exit_node(self, plugin):
        """tailscale up includes --exit-node when set."""
        plugin.cfg.extra["exit_node"] = "exit-nl"
        with _ts_connect_ok(plugin) as mock_proc:
            plugin.connect()

        cmd = mock_proc.run.call_args[0][0]
        assert "--exit-node=exit-nl" in cmd

    def test_command_without_optional_flags(self, plugin):
        """No --login-server or --exit-node when not configured."""
        with _ts_connect_ok(plugin) as mock_proc:
            plugin.connect()

        cmd = mock_proc.run.call_args[0][0]
        assert not any("--login-server" in arg for arg in cmd)
        assert not any("--exit-node" in arg for arg in cmd)

    def test_auto_detect_interface(self, plugin):
        """When interface is empty, auto-detect new tailscale/utun interface."""
        plugin.cfg.interface = ""

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("tv.vpn.tailscale.proc") as mock_proc:
            mock_proc.run.return_value = mock_result
            mock_proc.find_pids.return_value = [8888]

            def fake_wait_for(desc, check_fn, timeout, log):
                plugin.net.interfaces.return_value = {
                    "en0": "192.168.1.7",
                    "lo0": "127.0.0.1",
                    "tailscale0": "100.64.0.1",
                }
                return check_fn()

            mock_proc.wait_for.side_effect = fake_wait_for
            plugin.net.iface_info.return_value = "tailscale0: flags=8051<UP>"

            r = plugin.connect()

        assert r.ok is True
        assert plugin.cfg.interface == "tailscale0"


# =========================================================================
# Negative: connection failures
# =========================================================================


class TestConnectFailure:
    def test_tailscale_exit_nonzero(self, plugin, capsys):
        """tailscale up returns non-zero exit code."""
        with _ts_connect_fail_setup(plugin):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "exit code 1" in out or "код 1" in out

    def test_interface_not_appeared(self, plugin, capsys):
        """tailscale up ok but interface never shows up."""
        with _ts_connect_fail_iface(plugin):
            r = plugin.connect()

        assert r.ok is False

    def test_shows_log_hint(self, plugin, capsys):
        """On tailscale failure, shows log hint."""
        with _ts_connect_fail_setup(plugin):
            plugin.connect()

        out = capsys.readouterr().out
        assert "tailscale status" in out

    def test_shows_stderr_on_failure(self, plugin, capsys):
        """On tailscale failure, shows last line of stderr."""
        with _ts_connect_fail_setup(
            plugin, stderr="Line 1\nfailed to connect to control server"
        ):
            plugin.connect()

        out = capsys.readouterr().out
        assert "failed to connect to control server" in out

    def test_no_auth_key(self, plugin, capsys):
        """Missing auth key fails immediately."""
        plugin.cfg.auth = {}
        with patch("tv.vpn.tailscale.proc"):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "auth key" in out.lower() or "auth_key" in out.lower()


# =========================================================================
# Disconnect
# =========================================================================


class TestDisconnect:
    def test_disconnect_uses_tailscale_down(self, plugin):
        """disconnect() calls tailscale down."""
        with patch("tv.vpn.tailscale.proc") as mock_proc:
            plugin.disconnect()

        cmd = mock_proc.run.call_args[0][0]
        assert cmd[0] == "tailscale"
        assert cmd[1] == "down"
        assert mock_proc.run.call_args[1].get("sudo") is True


# =========================================================================
# Config schema
# =========================================================================


class TestConfigSchema:
    def test_schema_has_auth_key(self):
        schema = TailscalePlugin.config_schema()
        keys = [p.key for p in schema]
        assert "auth_key" in keys

    def test_auth_key_is_secret(self):
        schema = TailscalePlugin.config_schema()
        auth_key = [p for p in schema if p.key == "auth_key"][0]
        assert auth_key.secret is True
        assert auth_key.required is True
        assert auth_key.env_var == "VPN_TS_AUTH_KEY"

    def test_login_server_optional(self):
        schema = TailscalePlugin.config_schema()
        login_server = [p for p in schema if p.key == "login_server"][0]
        assert login_server.required is False
        assert login_server.env_var == "VPN_TS_LOGIN_SERVER"

    def test_exit_node_no_prompt(self):
        schema = TailscalePlugin.config_schema()
        exit_node = [p for p in schema if p.key == "exit_node"][0]
        assert exit_node.required is False
        assert exit_node.prompt is False
        assert exit_node.target == "extra"
