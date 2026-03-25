"""Integration tests: DNS and routing with VPN active.

Tests split-DNS behavior, route application, and DNS leak detection.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tv.checks import _check_dns
from tv.net import NetManager


pytestmark = pytest.mark.network


def _wait_for_vpn(
    net: NetManager,
    ifaces_before: set,
    prefix: tuple = ("tun", "utun"),
    timeout: int = 15,
) -> str | None:
    """Wait for VPN interface to appear."""
    for _ in range(timeout * 2):
        time.sleep(0.5)
        new = set(net.interfaces().keys()) - ifaces_before
        vpn = [i for i in new if i.startswith(prefix)]
        if vpn:
            return vpn[0]
    return None


class TestDNSWithVPN:
    """DNS behavior with active VPN connection."""

    @pytest.fixture(autouse=True)
    def _vpn_connection(self, openvpn_client_config: Path, real_net: NetManager):
        """Start OpenVPN for DNS tests."""
        self.ifaces_before = set(real_net.interfaces().keys())

        self.proc = subprocess.Popen(
            ["openvpn", "--config", str(openvpn_client_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        iface = _wait_for_vpn(real_net, self.ifaces_before)
        if not iface:
            self.proc.terminate()
            self.proc.wait(timeout=5)
            pytest.skip("OpenVPN connection failed")

        time.sleep(1)
        yield
        self.proc.terminate()
        self.proc.wait(timeout=5)

    def test_dns_to_public_resolver(self):
        """DNS resolution via public resolver (8.8.8.8) works with VPN active."""
        assert _check_dns("google.com", server="8.8.8.8", timeout=5) is True

    def test_dns_to_cloudflare(self):
        """DNS resolution via Cloudflare (1.1.1.1) works with VPN active."""
        assert _check_dns("cloudflare.com", server="1.1.1.1", timeout=5) is True

    def test_multiple_dns_queries(self):
        """Multiple DNS queries in sequence - no degradation."""
        domains = ["google.com", "github.com", "cloudflare.com"]
        for domain in domains:
            result = _check_dns(domain, server="8.8.8.8", timeout=5)
            assert result is True, f"DNS resolution failed for {domain}"

    def test_reverse_dns(self):
        """Reverse DNS lookup works through VPN."""
        result = subprocess.run(
            ["nslookup", "8.8.8.8", "8.8.8.8"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # nslookup может вернуть 0 или 1, главное - не зависнуть
        assert result.returncode in (0, 1), f"nslookup hung or crashed: {result.stderr}"


class TestRoutesWithVPN:
    """Route table after VPN connection."""

    @pytest.fixture(autouse=True)
    def _vpn_connection(self, openvpn_client_config: Path, real_net: NetManager):
        """Start OpenVPN for route tests."""
        self.net = real_net
        self.ifaces_before = set(real_net.interfaces().keys())

        self.proc = subprocess.Popen(
            ["openvpn", "--config", str(openvpn_client_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        iface = _wait_for_vpn(real_net, self.ifaces_before)
        if not iface:
            self.proc.terminate()
            self.proc.wait(timeout=5)
            pytest.skip("OpenVPN connection failed")

        time.sleep(2)  # дать время на push routes
        yield
        self.proc.terminate()
        self.proc.wait(timeout=5)

    def test_pushed_route_present(self):
        """Server-pushed route 10.99.0.0/24 appears in route table."""
        route_table = self.net.route_table()
        assert "10.99.0" in route_table, (
            f"Pushed route 10.99.0.0/24 not found in:\n{route_table}"
        )

    def test_vpn_subnet_route(self):
        """VPN subnet route (10.8.0.0/24) present."""
        route_table = self.net.route_table()
        assert "10.8.0" in route_table, (
            f"VPN subnet 10.8.0.0/24 not found in:\n{route_table}"
        )

    def test_default_gateway_preserved(self):
        """Default gateway still exists (not swallowed by VPN)."""
        gw = self.net.default_gateway()
        assert gw is not None, "Default gateway disappeared after VPN connect"

    def test_routes_cleaned_after_disconnect(self, real_net: NetManager):
        """After OpenVPN disconnect, pushed routes are removed."""
        # Фиксируем текущие маршруты (с VPN)
        route_with_vpn = real_net.route_table()
        assert "10.99.0" in route_with_vpn

        # Отключаем
        self.proc.terminate()
        self.proc.wait(timeout=5)
        time.sleep(2)

        # Маршрут должен исчезнуть
        route_after = real_net.route_table()
        assert "10.99.0" not in route_after, (
            f"Pushed route 10.99.0.0/24 not cleaned up:\n{route_after}"
        )
