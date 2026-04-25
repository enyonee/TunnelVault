"""Tests for tv.disconnect: cleanup and disconnect logic."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from tv.disconnect import run, run_plugins
from tv.vpn.base import TunnelConfig


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture
def v3_defs():
    """V3 format defs for disconnect tests."""
    return {
        "routes": {
            "vpn_servers": {
                "hosts": ["203.0.113.10"],
                "resolve": ["vpn.test.local"],
            },
        },
    }


@pytest.fixture
def global_defs():
    """Global format defs for disconnect tests."""
    return {
        "global": {
            "vpn_server_routes": {
                "hosts": ["10.20.30.40"],
                "resolve": ["vpn.test.local"],
            },
        },
    }


# =========================================================================
# Positive: emergency disconnect (run)
# =========================================================================


class TestDisconnect:
    def test_uses_emergency_patterns_with_script_dir(
        self, mock_net, logger, v3_defs, tmp_path
    ):
        """Uses targeted emergency_patterns when script_dir is provided."""
        with patch("tv.disconnect.proc") as mock_proc:
            run(net=mock_net, log=logger, defs=v3_defs, script_dir=tmp_path)

        patterns = [c[0][0] for c in mock_proc.kill_pattern.call_args_list]
        # FortiVPN: uses temp_dir pattern
        assert any("forti_" in p for p in patterns)
        # OpenVPN: uses script_dir path
        assert any(str(tmp_path) in p for p in patterns)
        # sing-box: uses script_dir path
        assert any("sing-box" in p and str(tmp_path) in p for p in patterns)
        # No killall calls
        mock_proc.killall.assert_not_called()

    def test_uses_kill_patterns_without_script_dir(self, mock_net, logger, v3_defs):
        """Falls back to kill_patterns when script_dir is not provided."""
        with patch("tv.disconnect.proc") as mock_proc:
            run(net=mock_net, log=logger, defs=v3_defs)

        patterns = [c[0][0] for c in mock_proc.kill_pattern.call_args_list]
        # Uses class-level kill_patterns as fallback
        assert any("openvpn" in p for p in patterns)
        assert any("forti_" in p for p in patterns)
        # No killall calls
        mock_proc.killall.assert_not_called()

    def test_removes_static_routes(self, mock_net, logger, v3_defs):
        """Deletes static VPN server routes from defs."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs)

        deleted_hosts = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "203.0.113.10" in deleted_hosts

    def test_resolves_and_removes_routes(self, mock_net, logger, v3_defs, tmp_path):
        """Читает resolved IPs из кеша при disconnect — DNS не вызывается."""
        import json
        from tv.app_config import cfg as _cfg

        cache_dir = tmp_path / _cfg.paths.log_dir
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / "resolved-route-cache.json"
        cache_file.write_text(json.dumps({"vpn.test.local": ["5.6.7.8", "9.10.11.12"]}))

        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs, script_dir=tmp_path)

        mock_net.resolve_host.assert_not_called()
        deleted_hosts = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "5.6.7.8" in deleted_hosts
        assert "9.10.11.12" in deleted_hosts

    def test_resolves_skipped_without_cache(self, mock_net, logger, v3_defs, tmp_path):
        """Без кеша resolved-маршруты не удаляются — DNS не вызывается."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs, script_dir=tmp_path)

        mock_net.resolve_host.assert_not_called()
        deleted_hosts = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "5.6.7.8" not in deleted_hosts

    def test_global_format_routes(self, mock_net, logger, global_defs):
        """Routes from global.vpn_server_routes format."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=global_defs)

        deleted_hosts = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "10.20.30.40" in deleted_hosts

    def test_restores_ipv6(self, mock_net, logger, v3_defs):
        """Restores IPv6."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs)

        mock_net.restore_ipv6.assert_called_once()

    def test_logs_completion(self, mock_net, logger, v3_defs):
        """Logs disconnect completion."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs)

        content = logger.log_path.read_text()
        assert "Disconnect complete" in content

    def test_prints_done_message(self, mock_net, logger, capsys, v3_defs):
        """Prints final message."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=v3_defs)

        out = capsys.readouterr().out
        assert "All disconnected" in out


# =========================================================================
# Negative / inverse: edge cases
# =========================================================================


class TestDisconnectInverse:
    def test_without_net_creates_default(self, logger, v3_defs):
        """Without net= -> creates NetManager via create()."""
        mock_net_instance = MagicMock()
        mock_net_instance.resolve_host.return_value = []

        with (
            patch("tv.disconnect.proc"),
            patch("tv.net.create", return_value=mock_net_instance),
        ):
            run(net=None, log=logger, defs=v3_defs)

    def test_without_logger_no_crash(self, mock_net, capsys, v3_defs):
        """Without logger -> no crash."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=None, defs=v3_defs)

        out = capsys.readouterr().out
        assert "All disconnected" in out

    def test_empty_defs_no_crash(self, mock_net, logger, capsys):
        """Empty defs -> nothing to clean, no crash."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs={})

        out = capsys.readouterr().out
        assert "All disconnected" in out

    def test_none_defs_no_crash(self, mock_net, logger, capsys):
        """defs=None -> no crash."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=None)

        out = capsys.readouterr().out
        assert "All disconnected" in out

    def test_kill_failure_doesnt_stop_cleanup(self, mock_net, logger, capsys, v3_defs):
        """Kill error does NOT stop cleanup."""
        with patch("tv.disconnect.proc") as mock_proc:
            mock_proc.killall.side_effect = Exception("kill failed")
            mock_proc.kill_pattern.side_effect = Exception("kill failed")
            run(net=mock_net, log=logger, defs=v3_defs)

        out = capsys.readouterr().out
        assert "All disconnected" in out
        mock_net.restore_ipv6.assert_called_once()

    def test_order_kill_before_routes(self, mock_net, logger, v3_defs):
        """Kill processes before deleting routes."""
        call_order = []

        with patch("tv.disconnect.proc") as mock_proc:
            mock_proc.killall.side_effect = lambda *a, **kw: call_order.append("kill")
            mock_proc.kill_pattern.side_effect = lambda *a, **kw: call_order.append(
                "kill"
            )
            mock_net.delete_host_route.side_effect = lambda *a, **kw: call_order.append(
                "route"
            )

            run(net=mock_net, log=logger, defs=v3_defs)

        first_route = (
            call_order.index("route") if "route" in call_order else len(call_order)
        )
        kills_before = [x for x in call_order[:first_route] if x == "kill"]
        assert len(kills_before) > 0


# =========================================================================
# Plugin-driven disconnect (run_plugins)
# =========================================================================


class TestRunPlugins:
    def test_disconnects_in_reverse_order(self, mock_net, logger, capsys):
        """Tunnels disconnected in reverse order."""
        order = []
        tunnels = [
            TunnelConfig(name="first", type="openvpn"),
            TunnelConfig(name="second", type="singbox"),
        ]
        with (
            patch(
                "tv.vpn.openvpn.OpenVPNPlugin.disconnect",
                side_effect=lambda: order.append("first"),
            ),
            patch(
                "tv.vpn.singbox.SingBoxPlugin.disconnect",
                side_effect=lambda: order.append("second"),
            ),
        ):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        assert order == ["second", "first"]

    def test_cleans_vpn_server_routes(self, mock_net, logger, capsys):
        """Removes VPN server routes."""
        tunnels = [TunnelConfig(name="t", type="openvpn")]
        defs = {
            "routes": {
                "vpn_servers": {
                    "hosts": ["1.2.3.4"],
                    "resolve": [],
                },
            },
        }
        with patch("tv.vpn.openvpn.OpenVPNPlugin.disconnect"):
            run_plugins(tunnels, net=mock_net, log=logger, defs=defs)

        deleted = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "1.2.3.4" in deleted

    def test_restores_ipv6(self, mock_net, logger, capsys):
        """Restores IPv6 after plugin disconnect."""
        tunnels = [TunnelConfig(name="t", type="openvpn")]
        with patch("tv.vpn.openvpn.OpenVPNPlugin.disconnect"):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        mock_net.restore_ipv6.assert_called_once()

    def test_exception_doesnt_stop_other_tunnels(self, mock_net, logger, capsys):
        """Exception in one tunnel doesn't block others."""
        tunnels = [
            TunnelConfig(name="first", type="openvpn"),
            TunnelConfig(name="second", type="singbox"),
        ]
        with (
            patch("tv.vpn.openvpn.OpenVPNPlugin.disconnect"),
            patch(
                "tv.vpn.singbox.SingBoxPlugin.disconnect",
                side_effect=RuntimeError("boom"),
            ),
        ):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        # Still got to the end
        mock_net.restore_ipv6.assert_called_once()

    def test_cleans_dns(self, mock_net, logger, capsys):
        """Cleans up DNS resolvers after disconnect."""
        tunnels = [
            TunnelConfig(
                name="fortivpn",
                type="fortivpn",
                order=1,
                dns={"nameservers": ["10.0.1.1"], "domains": ["alpha.local"]},
            ),
        ]
        with patch("tv.vpn.fortivpn.proc"), patch("tv.disconnect.proc"):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        mock_net.cleanup_dns_resolver.assert_called()

    def test_deletes_routes(self, mock_net, logger, capsys):
        """Deletes tunnel routes after disconnect."""
        tunnels = [
            TunnelConfig(
                name="fortivpn",
                type="fortivpn",
                order=1,
                routes={"networks": ["10.0.0.0/8"]},
            ),
        ]
        with patch("tv.vpn.fortivpn.proc"), patch("tv.disconnect.proc"):
            run_plugins(tunnels, net=mock_net, log=logger, defs={})

        mock_net.delete_net_route.assert_called()

    def test_empty_tunnels(self, mock_net, logger, capsys):
        """Empty tunnel list shouldn't crash."""
        run_plugins([], net=mock_net, log=logger, defs={})
        mock_net.restore_ipv6.assert_called_once()


# =========================================================================
# Bypass routes cleanup
# =========================================================================


class TestBypassRoutesCleanup:
    def test_removes_bypass_hosts(self, mock_net, logger, capsys):
        """Bypass host routes are deleted on disconnect."""
        defs = {
            "global": {
                "bypass": {
                    "hosts": ["8.8.8.8", "1.1.1.1"],
                    "domains": [],
                    "networks": [],
                },
            },
        }
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=defs)

        deleted = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "8.8.8.8" in deleted
        assert "1.1.1.1" in deleted

    def test_removes_bypass_domains(self, mock_net, logger, capsys):
        """Bypass domain routes are resolved and deleted."""
        mock_net.resolve_host.return_value = ["140.82.121.3"]
        defs = {
            "global": {
                "bypass": {
                    "hosts": [],
                    "domains": ["github.com"],
                    "networks": [],
                },
            },
        }
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=defs)

        mock_net.resolve_host.assert_any_call("github.com")
        deleted = [c[0][0] for c in mock_net.delete_host_route.call_args_list]
        assert "140.82.121.3" in deleted

    def test_removes_bypass_networks(self, mock_net, logger, capsys):
        """Bypass network routes are deleted."""
        defs = {
            "global": {
                "bypass": {
                    "hosts": [],
                    "domains": [],
                    "networks": ["192.168.1.0/24"],
                },
            },
        }
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs=defs)

        deleted = [c[0][0] for c in mock_net.delete_net_route.call_args_list]
        assert "192.168.1.0/24" in deleted

    def test_no_bypass_section_no_crash(self, mock_net, logger, capsys):
        """No bypass section - no crash."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs={})

        out = capsys.readouterr().out
        assert "All disconnected" in out
        assert "bypass" not in out.lower()


# =========================================================================
# IPv6 opt-in helper + emergency path (GH-5 PR#1)
# =========================================================================


class TestIPv6OptInHelper:
    def test_get_ipv6_enabled_true(self):
        from tv.disconnect import get_ipv6_enabled

        assert get_ipv6_enabled({"global": {"ipv6": True}}) is True

    def test_get_ipv6_enabled_false(self):
        from tv.disconnect import get_ipv6_enabled

        assert get_ipv6_enabled({"global": {"ipv6": False}}) is False

    def test_get_ipv6_enabled_missing_default_false(self):
        """Default=False обязательно для backward compat."""
        from tv.disconnect import get_ipv6_enabled

        assert get_ipv6_enabled({}) is False
        assert get_ipv6_enabled({"global": {}}) is False

    def test_emergency_run_skips_restore_ipv6_when_optin(self, mock_net, logger):
        """disconnect.run() при ipv6=true в defs НЕ вызывает restore_ipv6."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs={"global": {"ipv6": True}})

        mock_net.restore_ipv6.assert_not_called()

    def test_emergency_run_restores_ipv6_when_default(self, mock_net, logger):
        """disconnect.run() без ipv6 флага - restore_ipv6 вызывается (backward compat)."""
        with patch("tv.disconnect.proc"):
            run(net=mock_net, log=logger, defs={})

        mock_net.restore_ipv6.assert_called_once()
