"""Tests for WireGuardPlugin: WireGuard connection via wg-quick."""

from __future__ import annotations

import contextlib
from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.wireguard import WireGuardPlugin


@contextlib.contextmanager
def _wg_connect_ok(plugin, *, interface="utun97"):
    """Set up successful wg-quick connect: run() ok, interface appears."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    with patch("tv.vpn.wireguard.proc") as mock_proc:
        mock_proc.run.return_value = mock_result
        mock_proc.wait_for.return_value = True
        mock_proc.find_pids.return_value = [7777]
        plugin.net.check_interface.return_value = True
        plugin.net.iface_info.return_value = f"{interface}: flags=8051<UP>"
        yield mock_proc


@contextlib.contextmanager
def _wg_connect_fail_setup(plugin):
    """Set up failing wg-quick: run() returns non-zero exit code."""
    mock_result = MagicMock()
    mock_result.returncode = 1
    with patch("tv.vpn.wireguard.proc") as mock_proc:
        mock_proc.run.return_value = mock_result
        yield mock_proc


@contextlib.contextmanager
def _wg_connect_fail_iface(plugin):
    """Set up: wg-quick ok but interface never appears."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    with patch("tv.vpn.wireguard.proc") as mock_proc:
        mock_proc.run.return_value = mock_result
        mock_proc.wait_for.return_value = False
        plugin.net.check_interface.return_value = False
        yield mock_proc


@pytest.fixture
def wg_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="wireguard",
        type="wireguard",
        order=4,
        config_file="wg0.conf",
        log=str(tmp_dir / "wireguard.log"),
        interface="utun97",
        routes={
            "hosts": ["10.0.0.1"],
            "networks": ["10.0.0.0/24"],
        },
    )


@pytest.fixture
def plugin(wg_cfg, mock_net, logger, tmp_dir):
    return WireGuardPlugin(wg_cfg, mock_net, logger, tmp_dir)


# =========================================================================
# Meta
# =========================================================================


class TestMeta:
    def test_process_name(self, plugin):
        assert plugin.process_name == "wireguard-go"

    def test_display_name(self, plugin):
        assert plugin.display_name == "WireGuard"

    def test_registered(self):
        from tv.vpn.registry import get_plugin
        assert get_plugin("wireguard") is WireGuardPlugin

    def test_binary(self):
        assert WireGuardPlugin.binary == "wg-quick"

    def test_type_display_name(self):
        assert WireGuardPlugin.type_display_name == "WireGuard"


# =========================================================================
# Positive: successful connection
# =========================================================================


class TestConnectSuccess:
    def test_normal_connection(self, plugin):
        """wg-quick up succeeds, interface appears, routes added."""
        with _wg_connect_ok(plugin):
            r = plugin.connect()

        assert r.ok is True
        assert r.pid == 7777

    def test_adds_routes_from_config(self, plugin):
        """Adds host and network routes from TunnelConfig."""
        with _wg_connect_ok(plugin):
            plugin.connect()

        route_calls = plugin.net.add_iface_route.call_args_list
        targets = [c[0][0] for c in route_calls]
        assert "10.0.0.1" in targets
        assert "10.0.0.0/24" in targets

    def test_sets_up_dns_from_config(self, plugin):
        """DNS resolver set up from TunnelConfig.dns."""
        plugin.cfg.dns = {"nameservers": ["10.0.1.1"], "domains": ["wg.local"]}
        with _wg_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_called_once_with(
            ["wg.local"], ["10.0.1.1"], "utun97",
        )

    def test_no_dns_when_not_configured(self, plugin):
        """No DNS setup when dns is empty."""
        plugin.cfg.dns = {}
        with _wg_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_not_called()

    def test_launches_with_sudo(self, plugin):
        """wg-quick runs with sudo."""
        with _wg_connect_ok(plugin) as mock_proc:
            plugin.connect()

        run_call = mock_proc.run.call_args
        assert run_call[1].get("sudo") is True

    def test_auto_detect_interface(self, plugin):
        """When interface is empty, auto-detect new utun/wg interface."""
        plugin.cfg.interface = ""

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("tv.vpn.wireguard.proc") as mock_proc:
            mock_proc.run.return_value = mock_result
            mock_proc.find_pids.return_value = [8888]

            # Simulate wait_for callback finding a new interface
            def fake_wait_for(desc, check_fn, timeout, log):
                # Simulate new interface appearing
                plugin.net.interfaces.return_value = {
                    "en0": "192.168.1.7", "lo0": "127.0.0.1", "utun42": "10.0.0.2"
                }
                return check_fn()

            mock_proc.wait_for.side_effect = fake_wait_for
            plugin.net.iface_info.return_value = "utun42: flags=8051<UP>"

            r = plugin.connect()

        assert r.ok is True
        assert plugin.cfg.interface == "utun42"


# =========================================================================
# Negative: connection failures
# =========================================================================


class TestConnectFailure:
    def test_wg_quick_exit_nonzero(self, plugin, capsys):
        """wg-quick up returns non-zero exit code."""
        with _wg_connect_fail_setup(plugin):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "exit code 1" in out or "код 1" in out

    def test_interface_not_appeared(self, plugin, capsys):
        """wg-quick ok but interface never shows up."""
        with _wg_connect_fail_iface(plugin):
            r = plugin.connect()

        assert r.ok is False

    def test_shows_config_hint(self, plugin, capsys):
        """On wg-quick failure, shows config path hint."""
        with _wg_connect_fail_setup(plugin):
            plugin.connect()

        out = capsys.readouterr().out
        assert "wg0.conf" in out


# =========================================================================
# Disconnect
# =========================================================================


class TestDisconnect:
    def test_disconnect_uses_wg_quick_down(self, plugin):
        """disconnect() calls wg-quick down with config path."""
        with patch("tv.vpn.wireguard.proc") as mock_proc:
            plugin.disconnect()

        cmd = mock_proc.run.call_args[0][0]
        assert cmd[0] == "wg-quick"
        assert cmd[1] == "down"
        assert "wg0.conf" in cmd[2]
        assert mock_proc.run.call_args[1].get("sudo") is True

    def test_disconnect_per_config(self, plugin):
        """Different config = different wg-quick down path."""
        plugin.cfg.config_file = "custom-wg.conf"
        with patch("tv.vpn.wireguard.proc") as mock_proc:
            plugin.disconnect()

        cmd = mock_proc.run.call_args[0][0]
        assert "custom-wg.conf" in cmd[2]
        assert "wg0.conf" not in cmd[2]


# =========================================================================
# Resolved defaults: connect uses cfg directly
# =========================================================================


class TestResolvedDefaults:
    def test_connect_uses_resolved_interface(self, plugin):
        """connect() takes interface from cfg directly."""
        plugin.cfg.interface = "utun50"
        with _wg_connect_ok(plugin, interface="utun50") as mock_proc:
            plugin.net.iface_info.return_value = "utun50: flags=8051<UP>"
            r = plugin.connect()

        assert r.ok is True
        wait_call = mock_proc.wait_for.call_args
        assert "utun50" in wait_call[0][0]

    def test_connect_uses_resolved_config(self, plugin):
        """connect() takes config_file from cfg directly."""
        plugin.cfg.config_file = "my-wg.conf"
        with _wg_connect_ok(plugin) as mock_proc:
            plugin.connect()

        run_call = mock_proc.run.call_args[0][0]
        assert any("my-wg.conf" in str(arg) for arg in run_call)

    def test_config_schema_default(self):
        """Config schema returns wg_config param."""
        schema = WireGuardPlugin.config_schema()
        assert len(schema) == 1
        assert schema[0].key == "config_file"
        assert schema[0].env_var == "VPN_WG_CONFIG"
        assert schema[0].target == "config_file"
