"""Tests for OpenVPNPlugin Windows branch: run_background, no Tunnelblick, TAP interface detection."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.openvpn import OpenVPNPlugin


def _setup_mock_net_tap(mock_net):
    """Configure mock_net.interfaces() to simulate TAP adapter appearing on Windows.

    First call returns {Ethernet, Loopback} (before snapshot).
    Subsequent calls return {Ethernet, Loopback, Ethernet 2} (after connect).
    """
    call_count = 0
    ifaces_before = {
        "Ethernet": "192.168.1.7",
        "Loopback Pseudo-Interface 1": "127.0.0.1",
    }
    ifaces_after = {
        "Ethernet": "192.168.1.7",
        "Loopback Pseudo-Interface 1": "127.0.0.1",
        "Ethernet 2": "10.8.0.2",
    }

    def _interfaces():
        nonlocal call_count
        call_count += 1
        return ifaces_before if call_count == 1 else ifaces_after

    mock_net.interfaces.side_effect = _interfaces


@pytest.fixture
def ovpn_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="openvpn",
        type="openvpn",
        order=1,
        config_file="client.ovpn",
        log=str(tmp_dir / "openvpn.log"),
    )


@pytest.fixture
def plugin(ovpn_cfg, mock_net, logger, tmp_dir):
    return OpenVPNPlugin(ovpn_cfg, mock_net, logger, tmp_dir)


# =========================================================================
# Windows: launch via run_background (no --daemon)
# =========================================================================


class TestWindowsLaunch:
    @patch("tv.vpn.openvpn.IS_WINDOWS", True)
    def test_uses_run_background_on_windows(self, plugin):
        """On Windows, uses proc.run_background() instead of proc.run() with --daemon."""
        _setup_mock_net_tap(plugin.net)
        mock_popen = MagicMock()
        mock_popen.pid = 5555
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()

            r = plugin.connect()

        assert r.ok is True
        assert r.pid == 5555
        mock_proc.run_background.assert_called_once()
        mock_proc.run.assert_not_called()

    @patch("tv.vpn.openvpn.IS_WINDOWS", True)
    def test_no_daemon_flag_on_windows(self, plugin):
        """On Windows, the command must NOT contain --daemon."""
        _setup_mock_net_tap(plugin.net)
        mock_popen = MagicMock()
        mock_popen.pid = 5555
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()

            plugin.connect()

        cmd = mock_proc.run_background.call_args[0][0]
        assert "--daemon" not in cmd
        assert "--config" in cmd
        assert "--log" in cmd

    @patch("tv.vpn.openvpn.IS_WINDOWS", True)
    def test_pid_from_popen_directly(self, plugin):
        """On Windows, PID comes from Popen object directly (no pgrep polling)."""
        _setup_mock_net_tap(plugin.net)
        mock_popen = MagicMock()
        mock_popen.pid = 7777
        with (
            patch("tv.vpn.openvpn.proc") as mock_proc,
            patch("tv.vpn.openvpn.time.sleep") as mock_sleep,
        ):
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()

            r = plugin.connect()

        assert r.pid == 7777
        # find_pids should NOT be called for PID discovery on Windows
        mock_proc.find_pids.assert_not_called()
        mock_sleep.assert_not_called()


# =========================================================================
# Windows: no Tunnelblick
# =========================================================================


class TestWindowsNoTunnelblick:
    @patch("tv.vpn.openvpn.IS_WINDOWS", True)
    def test_skips_tunnelblick_detection_on_windows(self, plugin):
        """Tunnelblick detection is skipped entirely on Windows."""
        _setup_mock_net_tap(plugin.net)
        mock_popen = MagicMock()
        mock_popen.pid = 5555
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()

            r = plugin.connect()

        assert r.ok is True
        # find_pids for Tunnelblick should never be called
        for call in mock_proc.find_pids.call_args_list:
            assert "Tunnelblick" not in str(call)


# =========================================================================
# Windows: TAP/Wintun interface detection (any new interface, not just tun/utun)
# =========================================================================


class TestWindowsTapDetection:
    @patch("tv.vpn.openvpn.IS_WINDOWS", True)
    def test_detects_tap_adapter_on_windows(self, plugin):
        """On Windows, any new interface is detected (not filtered by tun/utun prefix)."""
        _setup_mock_net_tap(plugin.net)
        mock_popen = MagicMock()
        mock_popen.pid = 5555
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()

            r = plugin.connect()

        assert r.ok is True
        assert plugin.cfg.interface == "Ethernet 2"

    @patch("tv.vpn.openvpn.IS_WINDOWS", True)
    def test_preserves_configured_interface(self, plugin):
        """If interface is pre-configured, it is NOT overwritten."""
        plugin.cfg.interface = "TAP-Windows V9"
        _setup_mock_net_tap(plugin.net)
        mock_popen = MagicMock()
        mock_popen.pid = 5555
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()

            plugin.connect()

        assert plugin.cfg.interface == "TAP-Windows V9"

    @patch("tv.vpn.openvpn.IS_WINDOWS", True)
    def test_timeout_when_no_new_interface(self, plugin):
        """Timeout if no new interface appears on Windows."""
        # interfaces() always returns same set (no new adapter)
        plugin.net.interfaces.return_value = {"Ethernet": "192.168.1.7"}
        mock_popen = MagicMock()
        mock_popen.pid = 5555
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.return_value = False
            mock_proc.is_alive.return_value = False

            r = plugin.connect()

        assert r.ok is False


# =========================================================================
# Windows: connect with routes and DNS
# =========================================================================


class TestWindowsRoutesAndDns:
    @patch("tv.vpn.openvpn.IS_WINDOWS", True)
    def test_applies_routes_after_windows_connect(self, plugin):
        """Routes from TOML applied after successful Windows connect."""
        plugin.cfg.routes = {"hosts": ["1.2.3.4"], "networks": ["10.0.0.0/8"]}
        _setup_mock_net_tap(plugin.net)
        mock_popen = MagicMock()
        mock_popen.pid = 5555
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()

            plugin.connect()

        route_calls = plugin.net.add_iface_route.call_args_list
        targets = [c[0][0] for c in route_calls]
        assert "1.2.3.4" in targets
        assert "10.0.0.0/8" in targets

    @patch("tv.vpn.openvpn.IS_WINDOWS", True)
    def test_sets_up_dns_after_windows_connect(self, plugin):
        """DNS resolver set up after successful Windows connect."""
        plugin.cfg.dns = {"nameservers": ["10.0.1.1"], "domains": ["alpha.local"]}
        _setup_mock_net_tap(plugin.net)
        mock_popen = MagicMock()
        mock_popen.pid = 5555
        with patch("tv.vpn.openvpn.proc") as mock_proc:
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()

            plugin.connect()

        plugin.net.setup_dns_resolver.assert_called_once()
