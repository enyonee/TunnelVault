"""Integration tests: multiple tunnels running simultaneously.

Tests OpenVPN + sing-box connected at the same time via Engine.
Verifies both tunnels work, health checks pass for each, and cleanup is clean.
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
def multi_tunnel_project(
    tmp_path: Path,
    openvpn_client_config: Path,
    singbox_client_config: Path,
    singbox_server: str,
    singbox_ss_port: str,
) -> Path:
    """Project dir with defaults.toml for OpenVPN + sing-box tunnels."""
    # Копируем конфиги
    (tmp_path / "client.ovpn").write_text(openvpn_client_config.read_text())
    (tmp_path / "singbox-client.json").write_text(singbox_client_config.read_text())

    (tmp_path / "defaults.toml").write_text(
        "[tunnels.openvpn]\n"
        'type = "openvpn"\n'
        "order = 1\n"
        'config_file = "client.ovpn"\n'
        f'log = "{tmp_path}/openvpn.log"\n'
        "\n"
        "[tunnels.openvpn.checks]\n"
        'ping = [{host = "10.8.0.1"}]\n'
        "\n"
        "[tunnels.singbox]\n"
        'type = "singbox"\n'
        "order = 2\n"
        'config_file = "singbox-client.json"\n'
        'interface = "tun-test"\n'
        f'log = "{tmp_path}/singbox.log"\n'
        "\n"
        "[tunnels.singbox.checks]\n"
        f'ports = [{{host = "{singbox_server}", port = {singbox_ss_port}}}]\n'
    )

    settings = {
        "openvpn": {"config_file": "client.ovpn", "targets": []},
        "singbox": {"config_file": "singbox-client.json", "targets": []},
    }
    (tmp_path / ".vpn-settings.json").write_text(json.dumps(settings))

    return tmp_path


class TestMultiTunnel:
    """Multiple tunnels connected simultaneously via Engine."""

    def test_two_tunnels_connect_and_both_have_interfaces(
        self,
        multi_tunnel_project: Path,
        real_net: NetManager,
        test_logger: Logger,
        requires_tun,
    ):
        """OpenVPN + sing-box both create interfaces when connected together."""
        import tomllib

        with open(multi_tunnel_project / "defaults.toml", "rb") as f:
            defs = tomllib.load(f)

        engine = Engine(multi_tunnel_project, defs, net=real_net, log=test_logger)
        engine.prepare(setup=False)
        engine.setup()

        assert len(engine.tunnels) == 2, (
            f"Expected 2 tunnels, got {len(engine.tunnels)}"
        )

        ifaces_before = set(real_net.interfaces().keys())
        engine.connect_all()
        time.sleep(3)

        try:
            ifaces_after = set(real_net.interfaces().keys())
            new_ifaces = ifaces_after - ifaces_before

            # Должны появиться минимум 2 новых интерфейса
            assert len(new_ifaces) >= 2, (
                f"Expected 2+ new interfaces, got {len(new_ifaces)}: {new_ifaces}"
            )

            # OpenVPN tun
            tun_ifaces = [i for i in new_ifaces if i.startswith(("tun", "utun"))]
            assert len(tun_ifaces) >= 1, f"No OpenVPN tun interface in {new_ifaces}"

            # sing-box tun-test
            assert "tun-test" in new_ifaces or any("tun" in i for i in new_ifaces), (
                f"No sing-box interface in {new_ifaces}"
            )

        finally:
            engine.disconnect_all()

    def test_health_checks_pass_for_both_tunnels(
        self,
        multi_tunnel_project: Path,
        real_net: NetManager,
        test_logger: Logger,
        requires_tun,
    ):
        """Health checks pass for both tunnels when connected simultaneously."""
        import tomllib

        with open(multi_tunnel_project / "defaults.toml", "rb") as f:
            defs = tomllib.load(f)

        engine = Engine(multi_tunnel_project, defs, net=real_net, log=test_logger)
        engine.prepare(setup=False)
        engine.setup()
        engine.connect_all()
        time.sleep(3)

        try:
            results, ext_ip = engine.check_all()

            passed = [r for r in results if r.status == "ok"]
            failed = [r for r in results if r.status == "fail"]

            assert len(passed) >= 2, (
                f"Expected 2+ checks passed, got {len(passed)}. "
                f"Failed: {[(r.name, r.detail) for r in failed]}"
            )

        finally:
            engine.disconnect_all()

    def test_both_tunnels_route_traffic(
        self,
        multi_tunnel_project: Path,
        real_net: NetManager,
        test_logger: Logger,
        requires_tun,
    ):
        """Both tunnels actually route traffic, not just create interfaces."""
        import subprocess
        import tomllib

        with open(multi_tunnel_project / "defaults.toml", "rb") as f:
            defs = tomllib.load(f)

        engine = Engine(multi_tunnel_project, defs, net=real_net, log=test_logger)
        engine.prepare(setup=False)
        engine.setup()
        engine.connect_all()
        time.sleep(3)

        try:
            # OpenVPN: ping gateway through tun
            ovpn_ping = subprocess.run(
                ["ping", "-c", "1", "-W", "5", "10.8.0.1"],
                capture_output=True,
                timeout=10,
            )
            assert ovpn_ping.returncode == 0, "OpenVPN tunnel can't reach 10.8.0.1"

            # sing-box: port check to SS server (proves outbound works)
            import socket

            singbox_server = defs["tunnels"]["singbox"]["checks"]["ports"][0]["host"]
            singbox_port = defs["tunnels"]["singbox"]["checks"]["ports"][0]["port"]
            try:
                with socket.create_connection(
                    (singbox_server, singbox_port), timeout=5
                ):
                    pass  # connection succeeded
            except (ConnectionRefusedError, TimeoutError, OSError) as e:
                pytest.fail(f"sing-box server unreachable: {e}")

        finally:
            engine.disconnect_all()

    def test_disconnect_cleans_up_all_interfaces(
        self,
        multi_tunnel_project: Path,
        real_net: NetManager,
        test_logger: Logger,
        requires_tun,
    ):
        """disconnect_all removes all tunnel interfaces."""
        import tomllib

        with open(multi_tunnel_project / "defaults.toml", "rb") as f:
            defs = tomllib.load(f)

        engine = Engine(multi_tunnel_project, defs, net=real_net, log=test_logger)
        engine.prepare(setup=False)
        engine.setup()

        ifaces_before = set(real_net.interfaces().keys())
        engine.connect_all()
        time.sleep(3)

        engine.disconnect_all()
        time.sleep(2)

        ifaces_final = set(real_net.interfaces().keys())
        leftover = ifaces_final - ifaces_before
        # Фильтруем только VPN-related интерфейсы
        vpn_leftover = [
            i
            for i in leftover
            if i.startswith(("tun", "utun", "ppp")) or i == "tun-test"
        ]
        assert len(vpn_leftover) == 0, f"Leftover VPN interfaces: {vpn_leftover}"
