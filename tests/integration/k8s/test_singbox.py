"""Integration tests: sing-box connect/disconnect with real server.

Runs inside privileged K8s pod. sing-box server must be running in test-vpn namespace.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tv.net import NetManager


pytestmark = pytest.mark.network


@pytest.mark.skip(reason="sing-box tun creation unreliable in K8s containers")
class TestSingBoxConnect:
    """Real sing-box connection lifecycle."""

    def test_connect_creates_tun_interface(
        self, singbox_client_config: Path, real_net: NetManager
    ):
        """sing-box creates a tun interface after connect."""
        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["sing-box", "run", "-c", str(singbox_client_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            new_iface = None
            for _ in range(20):
                time.sleep(0.5)
                ifaces_now = set(real_net.interfaces().keys())
                new = ifaces_now - ifaces_before
                # sing-box creates tun-test (as configured)
                if new:
                    new_iface = list(new)[0]
                    break

            assert new_iface is not None, (
                f"No new interface appeared. Ifaces: {real_net.interfaces()}"
            )

        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_connect_and_disconnect_cleans_up(
        self, singbox_client_config: Path, real_net: NetManager
    ):
        """After disconnect, interface disappears."""
        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["sing-box", "run", "-c", str(singbox_client_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        for _ in range(20):
            time.sleep(0.5)
            ifaces_now = set(real_net.interfaces().keys())
            if ifaces_now - ifaces_before:
                break

        proc.terminate()
        proc.wait(timeout=5)
        time.sleep(1)

        ifaces_after = set(real_net.interfaces().keys())
        new_ifaces = ifaces_after - ifaces_before
        assert len(new_ifaces) == 0, f"Leftover interfaces: {new_ifaces}"

    def test_proxy_connectivity(self, singbox_server: str, singbox_ss_port: str):
        """sing-box server responds on Shadowsocks port."""
        result = subprocess.run(
            ["nc", "-z", "-w", "3", singbox_server, singbox_ss_port],
            capture_output=True,
            timeout=5,
        )
        assert result.returncode == 0, (
            f"Cannot connect to sing-box SS port {singbox_server}:{singbox_ss_port}"
        )
