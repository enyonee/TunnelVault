"""Tests for XrayPlugin: xray-core connection (TUN + proxy modes)."""

from __future__ import annotations

import contextlib
import platform
from unittest.mock import MagicMock, patch

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.xray import XrayPlugin

IS_WINDOWS = platform.system() == "Windows"
tun_skip = pytest.mark.skipif(IS_WINDOWS, reason="xray TUN mode is Unix-only (sudo)")


@contextlib.contextmanager
def _xray_tun_ok(plugin, pid=5556):
    """Successful TUN connect: popen, interface up, process alive."""
    mock_popen = MagicMock()
    mock_popen.pid = pid
    with patch("tv.vpn.xray.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.return_value = True
        mock_proc.is_alive.return_value = True
        plugin.net.check_interface.return_value = True
        plugin.net.iface_info.return_value = "utun98: flags=8051<UP>"
        yield mock_proc


@contextlib.contextmanager
def _xray_tun_fail(plugin, poll=1, is_alive=False, pid=5556):
    """Failed TUN connect: wait_for=False."""
    mock_popen = MagicMock()
    mock_popen.pid = pid
    mock_popen.poll.return_value = poll
    with patch("tv.vpn.xray.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.return_value = False
        mock_proc.is_alive.return_value = is_alive
        yield mock_proc


@contextlib.contextmanager
def _xray_proxy_ok(plugin, pid=5557):
    """Successful proxy connect: popen, port listening."""
    mock_popen = MagicMock()
    mock_popen.pid = pid
    with (
        patch("tv.vpn.xray.proc") as mock_proc,
        patch("tv.vpn.xray._check_port_listening", return_value=True),
    ):
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.return_value = True
        mock_proc.is_alive.return_value = True
        yield mock_proc


@contextlib.contextmanager
def _xray_proxy_fail(plugin, poll=1, is_alive=False, pid=5557):
    """Failed proxy connect: wait_for=False."""
    mock_popen = MagicMock()
    mock_popen.pid = pid
    mock_popen.poll.return_value = poll
    with (
        patch("tv.vpn.xray.proc") as mock_proc,
        patch("tv.vpn.xray._check_port_listening", return_value=False),
    ):
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.return_value = False
        mock_proc.is_alive.return_value = is_alive
        yield mock_proc


@pytest.fixture
def xray_tun_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="xray",
        type="xray",
        order=4,
        config_file="xray.json",
        log=str(tmp_dir / "xray.log"),
        interface="utun98",
        routes={
            "hosts": ["203.0.113.40"],
            "networks": ["172.19.0.0/16"],
        },
    )


@pytest.fixture
def xray_proxy_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="xray-proxy",
        type="xray",
        order=4,
        config_file="xray.json",
        log=str(tmp_dir / "xray-proxy.log"),
        extra={"mode": "proxy", "socks_port": 10808},
    )


@pytest.fixture
def plugin(xray_tun_cfg, mock_net, logger, tmp_dir):
    return XrayPlugin(xray_tun_cfg, mock_net, logger, tmp_dir)


@pytest.fixture
def proxy_plugin(xray_proxy_cfg, mock_net, logger, tmp_dir):
    return XrayPlugin(xray_proxy_cfg, mock_net, logger, tmp_dir)


# ==========================================================================
# Meta
# ==========================================================================


class TestMeta:
    def test_process_name(self, plugin):
        assert plugin.process_name == "xray"

    def test_display_name(self, plugin):
        assert plugin.display_name == "xray"

    def test_type_display_name(self):
        assert XrayPlugin.type_display_name == "xray-core"

    def test_registered(self):
        from tv.vpn.registry import get_plugin

        assert get_plugin("xray") is XrayPlugin

    def test_binary(self):
        assert XrayPlugin.binary == "xray"

    def test_emergency_patterns_path_specific(self, tmp_dir):
        patterns = XrayPlugin.emergency_patterns(tmp_dir)
        assert len(patterns) == 1
        assert "xray run -c" in patterns[0]
        assert str(tmp_dir) in patterns[0]

    def test_config_schema_has_config_file(self):
        schema = XrayPlugin.config_schema()
        keys = [p.key for p in schema]
        assert "config_file" in keys
        cf = next(p for p in schema if p.key == "config_file")
        assert cf.env_var == "VPN_XRAY_CONFIG"


# ==========================================================================
# TUN mode (sudo, iface wait)
# ==========================================================================


@tun_skip
class TestConnectTun:
    def test_normal_connection(self, plugin):
        with _xray_tun_ok(plugin):
            r = plugin.connect()
        assert r.ok is True
        assert r.pid == 5556

    def test_launches_with_sudo(self, plugin):
        with _xray_tun_ok(plugin) as mock_proc:
            plugin.connect()
        bg_call = mock_proc.run_background.call_args
        assert bg_call[1].get("sudo") is True

    def test_launch_command_format(self, plugin):
        """Команда должна быть [binary, 'run', '-c', config_path]."""
        with _xray_tun_ok(plugin) as mock_proc:
            plugin.connect()
        cmd = mock_proc.run_background.call_args[0][0]
        assert cmd[1] == "run"
        assert cmd[2] == "-c"
        assert "xray.json" in cmd[3]

    def test_adds_routes_from_config(self, plugin):
        with _xray_tun_ok(plugin):
            plugin.connect()
        route_calls = plugin.net.add_iface_route.call_args_list
        targets = [c[0][0] for c in route_calls]
        assert "203.0.113.40" in targets
        assert "172.19.0.0/16" in targets

    def test_sets_up_dns_from_config(self, plugin):
        plugin.cfg.dns = {"nameservers": ["10.0.2.1"], "domains": ["beta.local"]}
        with _xray_tun_ok(plugin):
            plugin.connect()
        plugin.net.setup_dns_resolver.assert_called_once_with(
            ["beta.local"],
            ["10.0.2.1"],
            "utun98",
            gateway_host="",
        )

    def test_wait_for_uses_iface(self, plugin):
        with _xray_tun_ok(plugin) as mock_proc:
            plugin.connect()
        wait_call = mock_proc.wait_for.call_args
        assert "utun98" in wait_call[0][0]


@tun_skip
class TestConnectTunFailure:
    def test_interface_timeout(self, plugin):
        with _xray_tun_fail(plugin):
            r = plugin.connect()
        assert r.ok is False
        assert r.pid == 5556

    def test_process_alive_but_no_interface(self, plugin, capsys):
        with _xray_tun_fail(plugin, is_alive=True):
            r = plugin.connect()
        assert r.ok is False
        out = capsys.readouterr().out
        assert "PID=5556" in out

    def test_shows_log_hint(self, plugin, capsys):
        with _xray_tun_fail(plugin):
            plugin.connect()
        out = capsys.readouterr().out
        assert "xray.log" in out

    def test_poll_none_shows_question_mark(self, plugin, capsys):
        with _xray_tun_fail(plugin, poll=None):
            plugin.connect()
        out = capsys.readouterr().out
        assert "?" in out
        assert "None" not in out

    def test_late_crash_detected(self, plugin, capsys):
        """Процесс умирает ПОСЛЕ появления интерфейса - ошибка, не success."""
        mock_popen = MagicMock()
        mock_popen.pid = 5556
        mock_popen.poll.return_value = 2
        with patch("tv.vpn.xray.proc") as mock_proc:
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.return_value = True  # iface появился
            mock_proc.is_alive.return_value = False  # но процесс умер
            plugin.net.check_interface.return_value = True
            r = plugin.connect()
        assert r.ok is False
        assert r.pid == 5556

    def test_config_not_found(self, plugin):
        plugin.cfg.config_file = "nonexistent-xray.json"
        r = plugin.connect()
        assert r.ok is False
        assert r.detail == "config not found"


# ==========================================================================
# Proxy mode (no sudo, port wait, no routes/dns)
# ==========================================================================


class TestConnectProxy:
    def test_normal_proxy_connection(self, proxy_plugin):
        with _xray_proxy_ok(proxy_plugin):
            r = proxy_plugin.connect()
        assert r.ok is True
        assert r.pid == 5557
        assert "10808" in r.detail

    def test_launches_without_sudo(self, proxy_plugin):
        with _xray_proxy_ok(proxy_plugin) as mock_proc:
            proxy_plugin.connect()
        bg_call = mock_proc.run_background.call_args
        assert bg_call[1].get("sudo") is False

    def test_no_routes_added(self, proxy_plugin):
        proxy_plugin.cfg.routes = {"hosts": ["1.2.3.4"], "networks": ["10.0.0.0/8"]}
        with _xray_proxy_ok(proxy_plugin):
            proxy_plugin.connect()
        proxy_plugin.net.add_iface_route.assert_not_called()
        proxy_plugin.net.add_host_route.assert_not_called()

    def test_no_dns_setup(self, proxy_plugin):
        proxy_plugin.cfg.dns = {"nameservers": ["1.1.1.1"], "domains": ["test.local"]}
        with _xray_proxy_ok(proxy_plugin):
            proxy_plugin.connect()
        proxy_plugin.net.setup_dns_resolver.assert_not_called()

    def test_wait_for_uses_port(self, proxy_plugin):
        with _xray_proxy_ok(proxy_plugin) as mock_proc:
            proxy_plugin.connect()
        wait_call = mock_proc.wait_for.call_args
        assert ":10808" in wait_call[0][0]

    def test_port_timeout(self, proxy_plugin):
        with _xray_proxy_fail(proxy_plugin):
            r = proxy_plugin.connect()
        assert r.ok is False

    def test_alive_but_no_port(self, proxy_plugin, capsys):
        with _xray_proxy_fail(proxy_plugin, is_alive=True):
            proxy_plugin.connect()
        out = capsys.readouterr().out
        assert "PID=5557" in out

    def test_late_crash_after_port(self, proxy_plugin):
        mock_popen = MagicMock()
        mock_popen.pid = 5557
        mock_popen.poll.return_value = 1
        with (
            patch("tv.vpn.xray.proc") as mock_proc,
            patch("tv.vpn.xray._check_port_listening", return_value=True),
        ):
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.return_value = True
            mock_proc.is_alive.return_value = False
            r = proxy_plugin.connect()
        assert r.ok is False

    def test_custom_socks_port(self, xray_proxy_cfg, mock_net, logger, tmp_dir):
        xray_proxy_cfg.extra["socks_port"] = 20808
        p = XrayPlugin(xray_proxy_cfg, mock_net, logger, tmp_dir)
        with _xray_proxy_ok(p) as mock_proc:
            r = p.connect()
        assert r.ok is True
        wait_call = mock_proc.wait_for.call_args
        assert ":20808" in wait_call[0][0]

    def test_default_mode_is_tun(self, xray_tun_cfg, mock_net, logger, tmp_dir):
        """Без mode в extra - mode == tun."""
        p = XrayPlugin(xray_tun_cfg, mock_net, logger, tmp_dir)
        assert p._get_mode() == "tun"


# ==========================================================================
# Disconnect
# ==========================================================================


class TestDisconnect:
    def test_disconnect_by_pid(self, plugin):
        plugin._pid = 5556
        with patch("tv.vpn.base.proc") as mock_proc:
            mock_proc.is_alive.side_effect = [True, False]
            mock_proc.kill_by_pid.return_value = True
            plugin.disconnect()
        mock_proc.kill_by_pid.assert_called_once_with(5556, sudo=True)

    def test_disconnect_fallback_pattern(self, plugin):
        plugin._pid = None
        with patch("tv.vpn.xray.proc") as mock_proc:
            plugin.disconnect()
        mock_proc.kill_pattern.assert_called_once()
        pattern = mock_proc.kill_pattern.call_args[0][0]
        assert "xray run -c" in pattern
        assert "xray.json" in pattern

    def test_disconnect_pid_timeout_falls_back_to_pattern(self, plugin):
        plugin._pid = 5556
        with (
            patch("tv.vpn.base.proc") as base_proc,
            patch("tv.vpn.base.time.sleep"),
            patch("tv.vpn.xray.proc") as xr_proc,
        ):
            base_proc.is_alive.return_value = True
            base_proc.kill_by_pid.return_value = True
            plugin.disconnect()
        xr_proc.kill_pattern.assert_called_once()


# ==========================================================================
# discover_pid
# ==========================================================================


class TestDiscoverPid:
    def test_discover_returns_first_pid(self, xray_tun_cfg, tmp_dir):
        with patch("tv.vpn.xray.proc") as mock_proc:
            mock_proc.find_pids.return_value = [7777]
            pid = XrayPlugin.discover_pid(xray_tun_cfg, tmp_dir)
        assert pid == 7777

    def test_discover_returns_none_when_no_match(self, xray_tun_cfg, tmp_dir):
        with patch("tv.vpn.xray.proc") as mock_proc:
            mock_proc.find_pids.return_value = []
            pid = XrayPlugin.discover_pid(xray_tun_cfg, tmp_dir)
        assert pid is None
