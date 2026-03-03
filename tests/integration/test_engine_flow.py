"""Integration tests for Engine lifecycle: prepare -> connect -> reuse.

Real file I/O, real TOML parsing, real Logger. VPN processes and network mocked.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tv.engine import Engine
from tv.logger import Logger
from tv.net import NetManager
from tv.vpn.base import VPNResult


@pytest.fixture
def mock_net() -> MagicMock:
    net = MagicMock(spec=NetManager)
    net.default_gateway.return_value = "192.168.1.1"
    net.interfaces.return_value = {"en0": "192.168.1.7", "lo0": "127.0.0.1"}
    net.check_interface.return_value = True
    net.add_host_route.return_value = True
    net.add_net_route.return_value = True
    net.add_iface_route.return_value = True
    net.setup_dns_resolver.return_value = {}
    net.disable_ipv6.return_value = True
    net.restore_ipv6.return_value = True
    net.delete_host_route.return_value = True
    net.delete_net_route.return_value = True
    net.route_table.return_value = ""
    net.iface_info.return_value = ""
    net.ppp_peer.return_value = ""
    net.resolve_host.return_value = ["1.2.3.4"]
    net.cleanup_dns_resolver.return_value = None
    net.cleanup_local_dns_resolvers.return_value = []
    return net


@pytest.fixture
def project_dir(tmp_path) -> Path:
    """Realistic project dir with defaults.toml, config files, and settings."""
    # defaults.toml
    (tmp_path / "defaults.toml").write_text(
        '[tunnels.openvpn]\n'
        'type = "openvpn"\n'
        'order = 1\n'
        'config_file = "client.ovpn"\n'
        'log = "/tmp/test-openvpn.log"\n'
        '\n'
        '[tunnels.openvpn.checks]\n'
        'http = ["https://google.com"]\n'
        '\n'
        '[tunnels.singbox]\n'
        'type = "singbox"\n'
        'order = 2\n'
        'config_file = "singbox.json"\n'
        'interface = "utun99"\n'
        'log = "/tmp/test-singbox.log"\n'
        '\n'
        '[tunnels.singbox.routes]\n'
        'networks = ["172.18.0.0/16"]\n'
    )

    # VPN config files (content doesn't matter, just needs to exist)
    (tmp_path / "client.ovpn").write_text("remote vpn.test.com 1194")
    (tmp_path / "singbox.json").write_text('{"log":{"level":"info"}}')

    # Saved settings
    settings = {
        "openvpn": {"config_file": "client.ovpn", "targets": []},
        "singbox": {"config_file": "singbox.json", "targets": []},
    }
    (tmp_path / ".vpn-settings.json").write_text(json.dumps(settings))

    return tmp_path


@pytest.fixture
def defs(project_dir) -> dict:
    from tv import defaults as defaults_mod
    return defaults_mod.load(project_dir)


@pytest.fixture
def engine(project_dir, defs, mock_net) -> Engine:
    log_dir = project_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    log = Logger(log_dir / "test.log")
    return Engine(project_dir, defs, net=mock_net, log=log)


# =========================================================================
# Full prepare -> connect cycle
# =========================================================================

class TestFullPrepareConnect:
    def test_prepare_populates_tunnels_from_real_toml(self, engine):
        """prepare() loads tunnels from real defaults.toml file."""
        engine.prepare()

        assert len(engine.tunnels) == 2
        names = [t.name for t in engine.tunnels]
        assert "openvpn" in names
        assert "singbox" in names

    def test_prepare_resolves_config_files(self, engine):
        """Config files from TOML are preserved after prepare()."""
        engine.prepare()

        ovpn = next(t for t in engine.tunnels if t.name == "openvpn")
        sb = next(t for t in engine.tunnels if t.name == "singbox")
        assert ovpn.config_file == "client.ovpn"
        assert sb.config_file == "singbox.json"

    def test_prepare_resolves_routes(self, engine):
        """Routes from TOML are parsed into networks."""
        engine.prepare()

        sb = next(t for t in engine.tunnels if t.name == "singbox")
        assert "172.18.0.0/16" in sb.routes.get("networks", [])

    def test_prepare_saves_settings(self, engine, project_dir):
        """First prepare (no settings) saves .vpn-settings.json."""
        settings_path = project_dir / ".vpn-settings.json"
        settings_path.unlink()

        with patch("tv.ui.wizard_input", return_value=""), \
             patch("tv.ui.wizard_targets", return_value=[]):
            engine.prepare()

        assert settings_path.exists()
        data = json.loads(settings_path.read_text())
        assert "openvpn" in data
        assert "singbox" in data

    def test_connect_all_calls_plugins(self, engine):
        """connect_all creates plugins and calls connect() for each tunnel."""
        engine.prepare()

        with patch("tv.vpn.openvpn.OpenVPNPlugin.connect",
                    return_value=VPNResult(ok=True, pid=100)) as mock_ovpn, \
             patch("tv.vpn.singbox.SingBoxPlugin.connect",
                    return_value=VPNResult(ok=True, pid=200)) as mock_sb:
            engine.connect_all()

        mock_ovpn.assert_called_once()
        mock_sb.assert_called_once()
        assert len(engine.results) == 2
        assert all(r.ok for r in engine.results)

    def test_connect_produces_ordered_results(self, engine):
        """Results match tunnel order from defaults.toml."""
        engine.prepare()

        with patch("tv.vpn.openvpn.OpenVPNPlugin.connect",
                    return_value=VPNResult(ok=True, pid=100, detail="openvpn")), \
             patch("tv.vpn.singbox.SingBoxPlugin.connect",
                    return_value=VPNResult(ok=True, pid=200, detail="singbox")):
            engine.connect_all()

        assert engine.results[0].detail == "openvpn"
        assert engine.results[1].detail == "singbox"


# =========================================================================
# Config file validation
# =========================================================================

class TestConfigNotFound:
    def test_openvpn_missing_config_fails(self, engine, project_dir):
        """OpenVPN connect fails cleanly when config file doesn't exist."""
        engine.prepare()
        # Delete the config file after prepare
        (project_dir / "client.ovpn").unlink()

        with patch("tv.vpn.singbox.SingBoxPlugin.connect",
                    return_value=VPNResult(ok=True)):
            engine.connect_all()

        ovpn_result = engine.results[0]
        assert ovpn_result.ok is False
        assert "config not found" in ovpn_result.detail

    def test_singbox_missing_config_fails(self, engine, project_dir):
        """sing-box connect fails cleanly when config file doesn't exist."""
        engine.prepare()
        (project_dir / "singbox.json").unlink()

        with patch("tv.vpn.openvpn.OpenVPNPlugin.connect",
                    return_value=VPNResult(ok=True)):
            engine.connect_all()

        sb_result = engine.results[1]
        assert sb_result.ok is False
        assert "config not found" in sb_result.detail


# =========================================================================
# Stale PID detection
# =========================================================================

class TestStalePidDetection:
    def test_reuse_when_pid_and_interface_alive(self, engine):
        """PID alive + interface alive = reuse, no connect() call."""
        engine.prepare()

        with patch("tv.vpn.openvpn.OpenVPNPlugin.discover_pid", return_value=None), \
             patch("tv.vpn.singbox.SingBoxPlugin.discover_pid", return_value=999), \
             patch("tv.engine.proc.is_alive", return_value=True), \
             patch("tv.vpn.openvpn.OpenVPNPlugin.connect",
                    return_value=VPNResult(ok=True)), \
             patch("tv.vpn.singbox.SingBoxPlugin.connect") as mock_sb_connect:
            engine.connect_all()

        # sing-box reused (not connected fresh)
        mock_sb_connect.assert_not_called()
        sb_result = engine.results[1]
        assert sb_result.ok is True
        assert sb_result.pid == 999
        assert "already running" in sb_result.detail

    def test_stale_pid_triggers_reconnect(self, engine):
        """PID alive + interface gone = kill stale + reconnect."""
        engine.prepare()

        with patch("tv.vpn.openvpn.OpenVPNPlugin.discover_pid", return_value=None), \
             patch("tv.vpn.singbox.SingBoxPlugin.discover_pid", return_value=888), \
             patch("tv.engine.proc.is_alive", return_value=True), \
             patch("tv.vpn.openvpn.OpenVPNPlugin.connect",
                    return_value=VPNResult(ok=True)), \
             patch("tv.vpn.singbox.SingBoxPlugin.connect",
                    return_value=VPNResult(ok=True, pid=999)) as mock_sb_connect, \
             patch("tv.vpn.singbox.SingBoxPlugin.disconnect") as mock_disc:
            engine.net.check_interface.return_value = False
            engine.connect_all()

        mock_disc.assert_called_once()
        mock_sb_connect.assert_called_once()
        sb_result = engine.results[1]
        assert sb_result.ok is True

    def test_stale_disconnect_failure_still_reconnects(self, engine):
        """If disconnect() throws on stale process, still attempt reconnect."""
        engine.prepare()

        with patch("tv.vpn.openvpn.OpenVPNPlugin.discover_pid", return_value=None), \
             patch("tv.vpn.singbox.SingBoxPlugin.discover_pid", return_value=777), \
             patch("tv.engine.proc.is_alive", return_value=True), \
             patch("tv.vpn.openvpn.OpenVPNPlugin.connect",
                    return_value=VPNResult(ok=True)), \
             patch("tv.vpn.singbox.SingBoxPlugin.connect",
                    return_value=VPNResult(ok=True, pid=111)) as mock_sb_connect, \
             patch("tv.vpn.singbox.SingBoxPlugin.disconnect",
                    side_effect=OSError("kill failed")):
            engine.net.check_interface.return_value = False
            engine.connect_all()

        # Despite disconnect failure, connect was still called
        mock_sb_connect.assert_called_once()
        assert engine.results[1].ok is True


# =========================================================================
# Hooks fire correctly through the flow
# =========================================================================

class TestHooksThroughFlow:
    def test_pre_post_hooks_fire_for_all_tunnels(self, engine):
        """Hooks fire for each tunnel regardless of reuse vs fresh connect."""
        engine.prepare()

        pre_calls = []
        post_calls = []
        engine.on("pre_connect", lambda **kw: pre_calls.append(kw["tunnel"].name))
        engine.on("post_connect", lambda **kw: post_calls.append(kw["tunnel"].name))

        with patch("tv.vpn.openvpn.OpenVPNPlugin.connect",
                    return_value=VPNResult(ok=True)), \
             patch("tv.vpn.singbox.SingBoxPlugin.connect",
                    return_value=VPNResult(ok=True)):
            engine.connect_all()

        assert pre_calls == ["openvpn", "singbox"]
        assert post_calls == ["openvpn", "singbox"]

    def test_hooks_receive_result(self, engine):
        """post_connect hook receives the VPNResult."""
        engine.prepare()

        results = []
        engine.on("post_connect", lambda **kw: results.append(kw["result"]))

        with patch("tv.vpn.openvpn.OpenVPNPlugin.connect",
                    return_value=VPNResult(ok=True, detail="ovpn-ok")), \
             patch("tv.vpn.singbox.SingBoxPlugin.connect",
                    return_value=VPNResult(ok=False, detail="sb-fail")):
            engine.connect_all()

        assert results[0].detail == "ovpn-ok"
        assert results[1].detail == "sb-fail"
