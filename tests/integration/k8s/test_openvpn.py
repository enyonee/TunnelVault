"""Integration tests: OpenVPN connect/disconnect with real server.

Runs inside privileged K8s pod. OpenVPN server must be running in test-vpn namespace.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tv.logger import Logger
from tv.net import NetManager


pytestmark = pytest.mark.network


class TestOpenVPNConnect:
    """Real OpenVPN connection lifecycle."""

    def test_connect_creates_tun_interface(
        self, openvpn_client_config: Path, test_logger: Logger, real_net: NetManager
    ):
        """OpenVPN creates a tun interface after connect."""
        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            [
                "openvpn",
                "--config",
                str(openvpn_client_config),
                "--log",
                "/tmp/test-openvpn.log",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            # Wait for tun interface to appear (up to 15s)
            new_iface = None
            for _ in range(30):
                time.sleep(0.5)
                ifaces_now = set(real_net.interfaces().keys())
                new = ifaces_now - ifaces_before
                tun_ifaces = [i for i in new if i.startswith(("tun", "utun"))]
                if tun_ifaces:
                    new_iface = tun_ifaces[0]
                    break

            assert new_iface is not None, (
                f"No tun interface appeared. Ifaces: {real_net.interfaces()}"
            )

            # Verify interface has IP in 10.8.0.0/24 range
            info = real_net.iface_info(new_iface)
            assert "10.8.0" in info, f"Expected 10.8.0.x IP, got: {info}"

        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_connect_and_disconnect_cleans_up(
        self, openvpn_client_config: Path, real_net: NetManager
    ):
        """After disconnect, tun interface disappears."""
        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["openvpn", "--config", str(openvpn_client_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for connect
        for _ in range(30):
            time.sleep(0.5)
            ifaces_now = set(real_net.interfaces().keys())
            if ifaces_now - ifaces_before:
                break

        proc.terminate()
        proc.wait(timeout=5)
        time.sleep(1)

        # Interface should be gone
        ifaces_after = set(real_net.interfaces().keys())
        new_ifaces = ifaces_after - ifaces_before
        tun_ifaces = [i for i in new_ifaces if i.startswith(("tun", "utun"))]
        assert len(tun_ifaces) == 0, f"Leftover tun interfaces: {tun_ifaces}"

    def test_routes_pushed_by_server(
        self, openvpn_client_config: Path, real_net: NetManager
    ):
        """Server pushes route 10.99.0.0/24 to client."""
        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["openvpn", "--config", str(openvpn_client_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            # Wait for tun interface
            for _ in range(30):
                time.sleep(0.5)
                ifaces_now = set(real_net.interfaces().keys())
                if ifaces_now - ifaces_before:
                    break

            time.sleep(2)  # дать время на push routes

            route_table = real_net.route_table()
            assert "10.99.0" in route_table, (
                f"Expected pushed route 10.99.0.0/24 in route table:\n{route_table}"
            )

        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_ping_through_vpn(self, openvpn_client_config: Path, real_net: NetManager):
        """Can ping VPN gateway (10.8.0.1) through tunnel."""
        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["openvpn", "--config", str(openvpn_client_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            # Wait for tun interface
            for _ in range(30):
                time.sleep(0.5)
                ifaces_now = set(real_net.interfaces().keys())
                if ifaces_now - ifaces_before:
                    break

            time.sleep(1)

            result = subprocess.run(
                ["ping", "-c", "3", "-W", "2", "10.8.0.1"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                f"Ping to VPN gateway failed:\n{result.stdout}\n{result.stderr}"
            )

        finally:
            proc.terminate()
            proc.wait(timeout=5)
