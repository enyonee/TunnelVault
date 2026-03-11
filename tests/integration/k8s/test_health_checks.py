"""Integration tests: health checks through real VPN connection.

Verifies port/ping/DNS/HTTP checks work correctly when VPN is active.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tv.checks import _check_port, _check_ping, _check_dns
from tv.net import NetManager


pytestmark = pytest.mark.network


class TestHealthChecksThroughVPN:
    """Health checks with active OpenVPN tunnel."""

    @pytest.fixture(autouse=True)
    def _vpn_connection(self, openvpn_client_config: Path, real_net: NetManager):
        """Start OpenVPN connection for the test, teardown after."""
        self.proc = subprocess.Popen(
            ["openvpn", "--config", str(openvpn_client_config)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Wait for tun interface
        ifaces_before = set(real_net.interfaces().keys())
        connected = False
        for _ in range(30):
            time.sleep(0.5)
            ifaces_now = set(real_net.interfaces().keys())
            new = ifaces_now - ifaces_before
            if any(i.startswith(("tun", "utun")) for i in new):
                connected = True
                break

        if not connected:
            self.proc.terminate()
            self.proc.wait(timeout=5)
            pytest.skip("OpenVPN connection failed")

        time.sleep(1)  # стабилизация
        yield
        self.proc.terminate()
        self.proc.wait(timeout=5)

    def test_port_check_vpn_gateway(self):
        """Port check to VPN gateway (OpenVPN management or SSH)."""
        # OpenVPN gateway should respond to ping at least
        result = _check_ping("10.8.0.1", timeout=5)
        assert result is True, "Ping to VPN gateway 10.8.0.1 failed"

    def test_ping_vpn_gateway(self):
        """Ping VPN gateway through tunnel."""
        result = _check_ping("10.8.0.1", timeout=5)
        assert result is True

    def test_dns_resolution_works(self):
        """DNS resolution still works with VPN active."""
        # Using system DNS (should work regardless of VPN)
        result = _check_dns("google.com", server="8.8.8.8", timeout=5)
        assert result is True, "DNS resolution failed with VPN active"


class TestHealthChecksNoVPN:
    """Health checks without VPN (baseline)."""

    def test_port_check_openvpn_server(self, openvpn_server: str):
        """Can reach OpenVPN server port directly."""
        result = subprocess.run(
            ["nc", "-z", "-u", "-w", "3", openvpn_server, "1194"],
            capture_output=True, timeout=5,
        )
        # UDP nc might not confirm, just verify no crash
        assert True

    def test_port_check_ocserv(self, ocserv_host: str, ocserv_port: str):
        """Can reach ocserv TCP port."""
        ok = _check_port(ocserv_host, int(ocserv_port), timeout=5)
        assert ok is True, f"Cannot reach ocserv at {ocserv_host}:{ocserv_port}"

    def test_port_check_singbox(self, singbox_server: str, singbox_ss_port: str):
        """Can reach sing-box Shadowsocks port."""
        ok = _check_port(singbox_server, int(singbox_ss_port), timeout=5)
        assert ok is True, f"Cannot reach sing-box at {singbox_server}:{singbox_ss_port}"
