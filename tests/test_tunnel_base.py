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
            gateway_host="",
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
            gateway_host="",
        )

    def test_setup_dns_passes_gateway_host(self, make_dummy, mock_net):
        """auth.host пробрасывается как gateway_host для carve-out."""
        p = make_dummy(
            name="forti",
            type="dummy",
            interface="utun4",
            dns={"nameservers": ["10.11.1.101"], "domains": ["new-mmc.com"]},
            auth={"host": "vpn.new-mmc.com"},
        )
        p.setup_dns()
        mock_net.setup_dns_resolver.assert_called_once_with(
            ["new-mmc.com"],
            ["10.11.1.101"],
            "utun4",
            gateway_host="vpn.new-mmc.com",
        )

    def test_setup_dns_empty(self, make_dummy, mock_net):
        p = make_dummy(name="no-dns", dns={})
        p.setup_dns()
        mock_net.setup_dns_resolver.assert_not_called()

    def test_cleanup_dns(self, dummy_plugin):
        dummy_plugin.cleanup_dns()
        dummy_plugin.net.cleanup_dns_resolver.assert_called_once_with(
            ["alpha.local"], "", gateway_host=""
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
        mock_net.cleanup_dns_resolver.assert_called_once_with(
            ["alpha.local"], "tun0", gateway_host=""
        )

    def test_gateway_host_from_auth(self, make_dummy):
        """gateway_host() по умолчанию берёт auth.host (openconnect/fortivpn/openvpn)."""
        p = make_dummy(name="x", type="dummy", auth={"host": " vpn.new-mmc.com "})
        assert p.gateway_host() == "vpn.new-mmc.com"

    def test_gateway_host_empty_without_auth(self, make_dummy):
        assert make_dummy(name="x", type="dummy").gateway_host() == ""

    def test_delete_routes(self, dummy_plugin):
        dummy_plugin.delete_routes()
        dummy_plugin.net.delete_host_route.assert_called_once_with("1.2.3.4")
        dummy_plugin.net.delete_net_route.assert_called_once_with("10.0.0.0/8")

    # ---- IPv6 dispatch (PR#2, H1 mitigation) ----

    def test_add_routes_dispatches_ipv4_vs_ipv6_with_gateway(
        self, make_dummy, mock_net
    ):
        """IPv6 CIDR/host идут в *route6 методы, IPv4 - в обычные (H1)."""
        p = make_dummy(
            name="mixed",
            type="dummy",
            routes={
                "hosts": ["1.2.3.4", "2001:db8::1"],
                "networks": ["10.0.0.0/8", "2001:db8::/32"],
            },
        )
        p.add_routes(gateway="192.168.1.1")
        # IPv4 через старые методы
        mock_net.add_host_route.assert_called_once_with("1.2.3.4", "192.168.1.1")
        mock_net.add_net_route.assert_called_once_with("10.0.0.0/8", "192.168.1.1")
        # IPv6 через новые методы
        mock_net.add_host_route6.assert_called_once_with("2001:db8::1", "192.168.1.1")
        mock_net.add_net_route6.assert_called_once_with("2001:db8::/32", "192.168.1.1")

    def test_add_routes_dispatches_ipv4_vs_ipv6_with_interface(
        self, make_dummy, mock_net
    ):
        p = make_dummy(
            name="tun",
            type="dummy",
            interface="utun99",
            routes={
                "hosts": ["1.2.3.4", "2001:db8::1"],
                "networks": ["10.0.0.0/8", "2001:db8::/32"],
            },
        )
        p.add_routes()
        mock_net.add_iface_route.assert_any_call("1.2.3.4", "utun99", host=True)
        mock_net.add_iface_route.assert_any_call("10.0.0.0/8", "utun99", host=False)
        mock_net.add_iface_route6.assert_any_call("2001:db8::1", "utun99", host=True)
        mock_net.add_iface_route6.assert_any_call("2001:db8::/32", "utun99", host=False)

    def test_delete_routes_dispatches_ipv6(self, make_dummy, mock_net):
        """H1: delete_routes ТОЖЕ должен dispatcher иначе IPv6 leak при disconnect."""
        p = make_dummy(
            name="mixed",
            type="dummy",
            routes={
                "hosts": ["1.2.3.4", "2001:db8::1"],
                "networks": ["10.0.0.0/8", "2001:db8::/32"],
            },
        )
        p.delete_routes()
        mock_net.delete_host_route.assert_called_once_with("1.2.3.4")
        mock_net.delete_net_route.assert_called_once_with("10.0.0.0/8")
        mock_net.delete_host_route6.assert_called_once_with("2001:db8::1")
        mock_net.delete_net_route6.assert_called_once_with("2001:db8::/32")

    def test_add_routes_invalid_cidr_routed_as_v4(self, make_dummy, mock_net):
        """M8: невалидный CIDR НЕ падает с ValueError - идёт в IPv4 методы
        (backward compat с pre-PR: add_net_route молча вернёт False).

        НЕ в *_route6 методы - это важно: мусор никогда не попадает в IPv6 dispatch."""
        p = make_dummy(
            name="t",
            type="dummy",
            interface="utun99",
            routes={"networks": ["not-a-cidr", "10.0.0.0/8"]},
        )
        p.add_routes()
        # Обе записи попали в add_iface_route (IPv4 метод)
        assert mock_net.add_iface_route.call_count == 2
        mock_net.add_iface_route6.assert_not_called()

    def test_add_routes_hostname_goes_to_ipv4(self, make_dummy, mock_net):
        """Backward compat: hostname (не IP) идёт в IPv4 add_host_route - engine
        resolve его через net.resolve_host. НЕ в add_host_route6."""
        p = make_dummy(
            name="t",
            type="dummy",
            routes={"hosts": ["git.test.local", "1.2.3.4"]},
        )
        p.add_routes(gateway="192.168.1.1")
        mock_net.add_host_route.assert_any_call("git.test.local", "192.168.1.1")
        mock_net.add_host_route.assert_any_call("1.2.3.4", "192.168.1.1")
        mock_net.add_host_route6.assert_not_called()

    def test_backward_compat_ipv4_only_identical(self, make_dummy, mock_net):
        """AC8 invariant: только IPv4 config работает идентично pre-PR.

        НЕ должны вызываться новые *_route6 методы при чисто IPv4 config."""
        p = make_dummy(
            name="v4",
            type="dummy",
            interface="utun99",
            routes={"hosts": ["1.2.3.4"], "networks": ["10.0.0.0/8"]},
        )
        p.add_routes()
        p.delete_routes()

        # IPv4 методы вызваны
        mock_net.add_iface_route.assert_any_call("1.2.3.4", "utun99", host=True)
        mock_net.add_iface_route.assert_any_call("10.0.0.0/8", "utun99", host=False)
        mock_net.delete_host_route.assert_called_once_with("1.2.3.4")
        mock_net.delete_net_route.assert_called_once_with("10.0.0.0/8")

        # IPv6 методы НЕ вызваны (только IPv4 config)
        mock_net.add_iface_route6.assert_not_called()
        mock_net.add_host_route6.assert_not_called()
        mock_net.add_net_route6.assert_not_called()
        mock_net.delete_host_route6.assert_not_called()
        mock_net.delete_net_route6.assert_not_called()

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


class TestAllPluginsRegistered:
    """Verify tv/vpn/__init__.py imports all plugins so they register."""

    def test_init_imports_all_plugins(self):
        """Check __init__.py has import lines for every plugin file."""
        from pathlib import Path

        vpn_dir = Path(__file__).resolve().parent.parent / "tv" / "vpn"
        init_text = (vpn_dir / "__init__.py").read_text()

        # Find all plugin files (exclude __init__, base, registry)
        # Exclude non-plugin modules (utilities, base classes)
        non_plugins = {"__init__", "base", "registry", "cert"}
        plugin_files = {
            p.stem for p in vpn_dir.glob("*.py") if p.stem not in non_plugins
        }

        missing = []
        for name in sorted(plugin_files):
            if f"from tv.vpn import {name}" not in init_text:
                missing.append(name)

        assert not missing, (
            f"Plugins not imported in tv/vpn/__init__.py: {missing}. "
            f"Add 'from tv.vpn import {missing[0]}  # noqa: F401' to register them."
        )
