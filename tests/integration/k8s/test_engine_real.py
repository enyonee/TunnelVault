"""Integration tests: full Engine lifecycle with real VPN connections.

Tests the complete tunnelvault flow: prepare -> setup -> connect -> check -> disconnect.
Uses real NetManager and real VPN processes against test servers.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from tv.engine import Engine
from tv.logger import Logger
from tv.net import NetManager


pytestmark = pytest.mark.network


@pytest.fixture
def openvpn_project(tmp_path: Path, openvpn_client_config: Path) -> Path:
    """Project dir with defaults.toml for OpenVPN tunnel."""
    # Copy or symlink client config
    dst = tmp_path / "client.ovpn"
    dst.write_text(openvpn_client_config.read_text())

    (tmp_path / "defaults.toml").write_text(
        "[tunnels.openvpn]\n"
        'type = "openvpn"\n'
        "order = 1\n"
        'config_file = "client.ovpn"\n'
        f'log = "{tmp_path}/openvpn.log"\n'
        "\n"
        "[tunnels.openvpn.checks]\n"
        'ping = [{host = "10.8.0.1"}]\n'
    )

    settings = {"openvpn": {"config_file": "client.ovpn", "targets": []}}
    (tmp_path / ".vpn-settings.json").write_text(json.dumps(settings))

    return tmp_path


@pytest.fixture
def singbox_project(
    tmp_path: Path,
    singbox_client_config: Path,
    singbox_server: str,
    singbox_ss_port: str,
) -> Path:
    """Project dir with defaults.toml for sing-box tunnel."""
    dst = tmp_path / "singbox-client.json"
    dst.write_text(singbox_client_config.read_text())

    (tmp_path / "defaults.toml").write_text(
        "[tunnels.singbox]\n"
        'type = "singbox"\n'
        "order = 1\n"
        'config_file = "singbox-client.json"\n'
        'interface = "tun-test"\n'
        f'log = "{tmp_path}/singbox.log"\n'
        "\n"
        "[tunnels.singbox.checks]\n"
        f'ports = [{{host = "{singbox_server}", port = {singbox_ss_port}}}]\n'
    )

    settings = {"singbox": {"config_file": "singbox-client.json", "targets": []}}
    (tmp_path / ".vpn-settings.json").write_text(json.dumps(settings))

    return tmp_path


class TestEngineOpenVPN:
    """Full Engine lifecycle with real OpenVPN connection."""

    def test_prepare_connect_disconnect(
        self, openvpn_project: Path, real_net: NetManager, test_logger: Logger
    ):
        """Engine can prepare, connect OpenVPN, and disconnect cleanly."""
        import tomli

        with open(openvpn_project / "defaults.toml", "rb") as f:
            defs = tomli.load(f)

        engine = Engine(openvpn_project, defs, net=real_net, log=test_logger)

        # Prepare
        engine.prepare(setup=False)
        assert len(engine.tunnels) == 1
        assert engine.tunnels[0].name == "openvpn"

        # Setup
        engine.setup()

        # Connect
        ifaces_before = set(real_net.interfaces().keys())
        engine.connect_all()
        time.sleep(2)

        # Verify tun interface appeared
        ifaces_after = set(real_net.interfaces().keys())
        new_ifaces = ifaces_after - ifaces_before
        tun_ifaces = [i for i in new_ifaces if i.startswith(("tun", "utun"))]
        assert len(tun_ifaces) > 0, (
            f"No tun interface after connect. Ifaces: {ifaces_after}"
        )

        # Disconnect
        engine.disconnect_all()
        time.sleep(1)

        # Verify cleanup
        ifaces_final = set(real_net.interfaces().keys())
        leftover = [
            i for i in (ifaces_final - ifaces_before) if i.startswith(("tun", "utun"))
        ]
        assert len(leftover) == 0, f"Leftover tun interfaces: {leftover}"

    def test_check_after_connect(
        self, openvpn_project: Path, real_net: NetManager, test_logger: Logger
    ):
        """Health checks pass after successful OpenVPN connection."""
        import tomli

        with open(openvpn_project / "defaults.toml", "rb") as f:
            defs = tomli.load(f)

        engine = Engine(openvpn_project, defs, net=real_net, log=test_logger)
        engine.prepare(setup=False)
        engine.setup()
        engine.connect_all()
        time.sleep(2)

        try:
            results, ext_ip = engine.check_all()

            # Проверяем что ping check к 10.8.0.1 прошёл
            passed = [r for r in results if r.ok]
            assert len(passed) > 0, f"No health checks passed: {results}"

        finally:
            engine.disconnect_all()


class TestEngineSingBox:
    """Full Engine lifecycle with real sing-box connection."""

    def test_prepare_connect_disconnect(
        self, singbox_project: Path, real_net: NetManager, test_logger: Logger
    ):
        """Engine can prepare, connect sing-box, and disconnect cleanly."""
        import tomli

        with open(singbox_project / "defaults.toml", "rb") as f:
            defs = tomli.load(f)

        engine = Engine(singbox_project, defs, net=real_net, log=test_logger)
        engine.prepare(setup=False)
        engine.setup()

        ifaces_before = set(real_net.interfaces().keys())
        engine.connect_all()
        time.sleep(2)

        ifaces_after = set(real_net.interfaces().keys())
        new_ifaces = ifaces_after - ifaces_before
        assert len(new_ifaces) > 0, (
            f"No new interface after connect. Ifaces: {ifaces_after}"
        )

        engine.disconnect_all()
        time.sleep(1)

        ifaces_final = set(real_net.interfaces().keys())
        leftover = ifaces_final - ifaces_before
        assert len(leftover) == 0, f"Leftover interfaces: {leftover}"
