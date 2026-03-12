"""Tests for TunnelConfig, TunnelPlugin ABC, and plugin registry."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from tv.logger import Logger
from tv.vpn.base import TunnelConfig, TunnelPlugin, VPNResult
from tv.vpn import registry


# ---------------------------------------------------------------------------
# TunnelConfig
# ---------------------------------------------------------------------------


class TestTunnelConfig:
    def test_defaults(self):
        tc = TunnelConfig()
        assert tc.name == ""
        assert tc.type == ""
        assert tc.order == 0
        assert tc.enabled is True
        assert tc.routes == {}
        assert tc.dns == {}
        assert tc.checks == {}
        assert tc.auth == {}
        assert tc.extra == {}
        assert tc._auto_config_file is False

    def test_with_values(self):
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            order=2,
            routes={"networks": ["10.0.0.0/8"]},
            dns={"nameservers": ["10.0.1.1"]},
            auth={"host": "vpn.test.local"},
        )
        assert tc.name == "fortivpn"
        assert tc.type == "fortivpn"
        assert tc.order == 2
        assert tc.routes["networks"] == ["10.0.0.0/8"]

    def test_enabled_false(self):
        tc = TunnelConfig(name="test", enabled=False)
        assert tc.enabled is False

    def test_mutable_defaults_independent(self):
        """Ensure mutable dict defaults don't share state between instances."""
        a = TunnelConfig(name="a")
        b = TunnelConfig(name="b")
        a.routes["hosts"] = ["1.2.3.4"]
        assert b.routes == {}


# ---------------------------------------------------------------------------
# TunnelPlugin ABC
# ---------------------------------------------------------------------------


class _DummyPlugin(TunnelPlugin):
    """Minimal concrete plugin for testing the ABC."""

    def connect(self) -> VPNResult:
        return VPNResult(ok=True, detail="dummy")

    @property
    def process_name(self) -> str:
        return "dummy-proc"


@pytest.fixture
def dummy_plugin(tmp_path, mock_net):
    cfg = TunnelConfig(
        name="test",
        type="dummy",
        routes={"hosts": ["1.2.3.4"], "networks": ["10.0.0.0/8"]},
        dns={"nameservers": ["10.0.1.1"], "domains": ["alpha.local"]},
        interface="",
    )
    log = Logger(tmp_path / "test.log")
    return _DummyPlugin(cfg, mock_net, log, tmp_path)


@pytest.fixture
def make_dummy(tmp_path, mock_net):
    """Factory for _DummyPlugin with custom TunnelConfig fields."""

    def _make(**cfg_kw):
        tc = TunnelConfig(**cfg_kw)
        log = Logger(tmp_path / "t.log")
        return _DummyPlugin(tc, mock_net, log, tmp_path)

    return _make


class TestTunnelPluginABC:
    def test_cannot_instantiate_abc(self, tmp_path, mock_net):
        with pytest.raises(TypeError):
            TunnelPlugin(TunnelConfig(), mock_net, Logger(tmp_path / "t.log"), tmp_path)

    def test_concrete_connect(self, dummy_plugin):
        result = dummy_plugin.connect()
        assert result.ok is True
        assert result.detail == "dummy"

    def test_process_name(self, dummy_plugin):
        assert dummy_plugin.process_name == "dummy-proc"

    def test_display_name_from_cfg(self, dummy_plugin):
        assert dummy_plugin.display_name == "test"

    def test_display_name_fallback_to_type(self, make_dummy):
        p = make_dummy(name="", type="openvpn")
        assert p.display_name == "openvpn"

    def test_add_routes_with_gateway(self, dummy_plugin):
        dummy_plugin.add_routes(gateway="192.168.1.1")
        dummy_plugin.net.add_host_route.assert_called_once_with(
            "1.2.3.4", "192.168.1.1"
        )
        dummy_plugin.net.add_net_route.assert_called_once_with(
            "10.0.0.0/8", "192.168.1.1"
        )

    def test_add_routes_with_interface(self, make_dummy, mock_net):
        p = make_dummy(
            name="singbox",
            type="singbox",
            interface="utun99",
            routes={"hosts": ["5.6.7.8"], "networks": ["172.16.0.0/12"]},
        )
        p.add_routes()
        mock_net.add_iface_route.assert_any_call("5.6.7.8", "utun99", host=True)
        mock_net.add_iface_route.assert_any_call("172.16.0.0/12", "utun99", host=False)

    def test_add_routes_no_gateway_no_iface_skips(self, dummy_plugin):
        """No interface and no gateway = routes silently skipped."""
        dummy_plugin.add_routes()
        dummy_plugin.net.add_host_route.assert_not_called()
        dummy_plugin.net.add_net_route.assert_not_called()

    def test_setup_dns(self, dummy_plugin):
        dummy_plugin.setup_dns()
        dummy_plugin.net.setup_dns_resolver.assert_called_once_with(
            ["alpha.local"],
            ["10.0.1.1"],
            "",
        )

    def test_setup_dns_passes_interface(self, make_dummy, mock_net):
        """Interface from cfg is passed to net.setup_dns_resolver."""
        p = make_dummy(
            name="vpn",
            type="dummy",
            interface="tun0",
            dns={"nameservers": ["10.0.1.1"], "domains": ["alpha.local"]},
        )
        p.setup_dns()
        mock_net.setup_dns_resolver.assert_called_once_with(
            ["alpha.local"],
            ["10.0.1.1"],
            "tun0",
        )

    def test_setup_dns_empty(self, make_dummy, mock_net):
        p = make_dummy(name="no-dns", dns={})
        p.setup_dns()
        mock_net.setup_dns_resolver.assert_not_called()

    def test_cleanup_dns(self, dummy_plugin):
        dummy_plugin.cleanup_dns()
        dummy_plugin.net.cleanup_dns_resolver.assert_called_once_with(
            ["alpha.local"], ""
        )

    def test_cleanup_dns_passes_interface(self, make_dummy, mock_net):
        """Interface from cfg is passed to net.cleanup_dns_resolver."""
        p = make_dummy(
            name="vpn",
            type="dummy",
            interface="tun0",
            dns={"nameservers": ["10.0.1.1"], "domains": ["alpha.local"]},
        )
        p.cleanup_dns()
        mock_net.cleanup_dns_resolver.assert_called_once_with(["alpha.local"], "tun0")

    def test_delete_routes(self, dummy_plugin):
        dummy_plugin.delete_routes()
        dummy_plugin.net.delete_host_route.assert_called_once_with("1.2.3.4")
        dummy_plugin.net.delete_net_route.assert_called_once_with("10.0.0.0/8")

    def test_default_log_path_from_cfg(self, make_dummy):
        """_default_log_path uses cfg.log when set."""
        p = make_dummy(name="test", type="dummy", log="/var/log/my.log")
        assert p._default_log_path() == Path("/var/log/my.log")

    def test_default_log_path_auto_generated(self, make_dummy):
        """_default_log_path generates from type and name when cfg.log is empty."""
        p = make_dummy(name="forti1", type="fortivpn")
        # log_dir default is "logs" (relative), resolved against script_dir
        expected = p.script_dir / "logs" / "fortivpn-forti1.log"
        assert p._default_log_path() == expected

    def test_default_log_path_fallback_to_type(self, make_dummy):
        """_default_log_path uses type when name is empty."""
        p = make_dummy(name="", type="openvpn")
        expected = p.script_dir / "logs" / "openvpn-openvpn.log"
        assert p._default_log_path() == expected

    def test_pid_initialized_to_none(self, dummy_plugin):
        """_pid defaults to None."""
        assert dummy_plugin._pid is None

    def test_kill_by_pid_success(self, dummy_plugin):
        """_kill_by_pid returns True when PID killed within timeout."""
        dummy_plugin._pid = 12345
        with patch("tv.vpn.base.proc") as mock_proc:
            mock_proc.is_alive.side_effect = [True, False]
            mock_proc.kill_by_pid.return_value = True

            result = dummy_plugin._kill_by_pid()

        assert result is True
        mock_proc.kill_by_pid.assert_called_once_with(12345, sudo=True)

    def test_kill_by_pid_no_pid_returns_false(self, dummy_plugin):
        """_kill_by_pid returns False when _pid is None."""
        with patch("tv.vpn.base.proc") as mock_proc:
            assert dummy_plugin._kill_by_pid() is False
        mock_proc.kill_by_pid.assert_not_called()

    def test_disconnect_calls_pattern_on_no_pid(self, dummy_plugin):
        """disconnect() calls _kill_by_pattern when no PID."""
        calls = []
        dummy_plugin._kill_by_pattern = lambda: calls.append("pattern")
        dummy_plugin.disconnect()
        assert "pattern" in calls

    def test_disconnect_skips_pattern_on_killed_pid(self, dummy_plugin):
        """disconnect() skips _kill_by_pattern when PID killed."""
        dummy_plugin._pid = 12345
        calls = []
        dummy_plugin._kill_by_pattern = lambda: calls.append("pattern")
        with patch("tv.vpn.base.proc") as mock_proc:
            mock_proc.is_alive.side_effect = [True, False]
            mock_proc.kill_by_pid.return_value = True

            dummy_plugin.disconnect()

        assert "pattern" not in calls

    def test_base_kill_by_pattern_is_noop(self, dummy_plugin):
        """Base _kill_by_pattern does nothing (override in subclasses)."""
        dummy_plugin._kill_by_pattern()  # should not raise


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    @pytest.fixture(autouse=True)
    def _isolate_registry(self):
        backup = dict(registry._registry)
        registry.clear()
        yield
        registry._registry.clear()
        registry._registry.update(backup)

    def test_register_and_get(self):
        @registry.register("test-vpn")
        class TestVPN(TunnelPlugin):
            def connect(self):
                return VPNResult()

            @property
            def process_name(self):
                return "test"

        assert registry.get_plugin("test-vpn") is TestVPN

    def test_available_types(self):
        @registry.register("beta")
        class B(TunnelPlugin):
            def connect(self):
                return VPNResult()

            @property
            def process_name(self):
                return "b"

        @registry.register("alpha")
        class A(TunnelPlugin):
            def connect(self):
                return VPNResult()

            @property
            def process_name(self):
                return "a"

        assert registry.available_types() == ["alpha", "beta"]

    def test_get_unknown_type(self):
        with pytest.raises(KeyError, match="Unknown tunnel type 'nonexistent'"):
            registry.get_plugin("nonexistent")

    def test_duplicate_register_raises(self):
        @registry.register("dup")
        class First(TunnelPlugin):
            def connect(self):
                return VPNResult()

            @property
            def process_name(self):
                return "first"

        with pytest.raises(ValueError, match="already registered"):

            @registry.register("dup")
            class Second(TunnelPlugin):
                def connect(self):
                    return VPNResult()

                @property
                def process_name(self):
                    return "second"

    def test_clear(self):
        @registry.register("temp")
        class Temp(TunnelPlugin):
            def connect(self):
                return VPNResult()

            @property
            def process_name(self):
                return "t"

        assert registry.available_types() == ["temp"]
        registry.clear()
        assert registry.available_types() == []
