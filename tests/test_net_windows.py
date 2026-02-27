"""Tests for tv.net: WindowsNet implementation."""

from __future__ import annotations

import socket
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from tv.net import WindowsNet, create, _cidr_to_mask


@pytest.fixture
def win_net():
    return WindowsNet()


# =========================================================================
# Factory
# =========================================================================

class TestFactory:
    @patch("platform.system", return_value="Windows")
    def test_creates_windows(self, _):
        assert isinstance(create(), WindowsNet)


# =========================================================================
# _cidr_to_mask helper
# =========================================================================

class TestCidrToMask:
    def test_slash_32(self):
        assert _cidr_to_mask(32) == "255.255.255.255"

    def test_slash_24(self):
        assert _cidr_to_mask(24) == "255.255.255.0"

    def test_slash_16(self):
        assert _cidr_to_mask(16) == "255.255.0.0"

    def test_slash_8(self):
        assert _cidr_to_mask(8) == "255.0.0.0"

    def test_slash_0(self):
        assert _cidr_to_mask(0) == "0.0.0.0"

    def test_slash_25(self):
        assert _cidr_to_mask(25) == "255.255.255.128"


# =========================================================================
# Positive: WindowsNet
# =========================================================================

class TestWindowsNet:
    @patch("subprocess.run")
    def test_default_gateway_parses(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "===========================================================================\n"
            "Interface List\n"
            " 12 ...08 00 27 5c 97 41 ...... Intel(R) Adapter\n"
            "===========================================================================\n"
            "\n"
            "IPv4 Route Table\n"
            "===========================================================================\n"
            "Active Routes:\n"
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.5     25\n"
            "        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\n"
            "===========================================================================\n",
            "",
        )
        assert win_net.default_gateway() == "192.168.1.1"

    @patch("subprocess.run")
    def test_interfaces_parses_ipconfig(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "\n"
            "Ethernet adapter Local Area Connection:\n"
            "\n"
            "   Connection-specific DNS Suffix  . :\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.5\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
            "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
            "\n"
            "PPP adapter VPN Connection:\n"
            "\n"
            "   IPv4 Address. . . . . . . . . . . : 10.0.0.2\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.255\n"
            "   Default Gateway . . . . . . . . . :\n",
            "",
        )
        ifaces = win_net.interfaces()
        assert ifaces["Local Area Connection"] == "192.168.1.5"
        assert ifaces["VPN Connection"] == "10.0.0.2"

    @patch("subprocess.run")
    def test_add_host_route(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = win_net.add_host_route("1.2.3.4", "192.168.1.1")
        assert ok is True
        args = mock_run.call_args[0][0]
        assert args == ["route", "ADD", "1.2.3.4", "MASK", "255.255.255.255", "192.168.1.1"]

    @patch("subprocess.run")
    def test_add_net_route(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = win_net.add_net_route("10.0.0.0/8", "192.168.1.1")
        assert ok is True
        args = mock_run.call_args[0][0]
        assert args == ["route", "ADD", "10.0.0.0", "MASK", "255.0.0.0", "192.168.1.1"]

    @patch("subprocess.run")
    def test_add_iface_route(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = win_net.add_iface_route("1.2.3.4", "VPN Connection", host=True)
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "netsh" in args
        assert "1.2.3.4/32" in args
        assert "interface=VPN Connection" in args

    @patch("subprocess.run")
    def test_delete_host_route(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = win_net.delete_host_route("1.2.3.4")
        assert ok is True
        args = mock_run.call_args[0][0]
        assert args == ["route", "DELETE", "1.2.3.4"]

    @patch("subprocess.run")
    def test_delete_net_route(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = win_net.delete_net_route("10.0.0.0/8")
        assert ok is True
        args = mock_run.call_args[0][0]
        assert args == ["route", "DELETE", "10.0.0.0"]

    @patch("subprocess.run")
    def test_route_table(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "IPv4 Route Table\nActive Routes:\n0.0.0.0  0.0.0.0  192.168.1.1\n",
            "",
        )
        table = win_net.route_table()
        assert "Active Routes" in table

    @patch("subprocess.run")
    def test_setup_dns_resolver(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        results = win_net.setup_dns_resolver(["example.local"], ["10.0.0.1"])
        assert results["example.local"] is True
        args = mock_run.call_args[0][0]
        assert args[0] == "powershell"
        assert "Add-DnsClientNrptRule" in args[2]
        assert "tunnelvault" in args[2]

    @patch("subprocess.run")
    def test_cleanup_dns_resolver(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        win_net.cleanup_dns_resolver(["example.local"])
        args = mock_run.call_args[0][0]
        assert args[0] == "powershell"
        assert "Remove-DnsClientNrptRule" in args[2]

    @patch("subprocess.run")
    def test_disable_ipv6(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = win_net.disable_ipv6()
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "Disable-NetAdapterBinding" in args[2]
        assert "ms_tcpip6" in args[2]

    @patch("subprocess.run")
    def test_restore_ipv6(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = win_net.restore_ipv6()
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "Enable-NetAdapterBinding" in args[2]

    @patch("subprocess.run")
    def test_ppp_peer_from_ipconfig(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "\n"
            "PPP adapter VPN:\n"
            "\n"
            "   IPv4 Address. . . . . . . . . . . : 10.0.0.2\n"
            "   Default Gateway . . . . . . . . . : 10.0.0.1\n",
            "",
        )
        assert win_net.ppp_peer("VPN") == "10.0.0.1"

    @patch("subprocess.run")
    def test_check_interface_via_netsh(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "Admin State: Enabled\nConnect state: Connected\n", ""
        )
        assert win_net.check_interface("Ethernet") is True

    @patch("subprocess.run")
    def test_iface_info(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "Configuration for interface 'Ethernet'\nDHCP: Yes\n", ""
        )
        info = win_net.iface_info("Ethernet")
        assert "DHCP" in info


# =========================================================================
# Negative / inverse: WindowsNet failures
# =========================================================================

class TestWindowsNetInverse:
    @patch("subprocess.run")
    def test_no_gateway_returns_none(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert win_net.default_gateway() is None

    @patch("subprocess.run")
    def test_gateway_no_active_routes(self, mock_run, win_net):
        """route PRINT succeeds but no 0.0.0.0 route."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "IPv4 Route Table\nActive Routes:\n127.0.0.0  255.0.0.0  On-link\n", ""
        )
        assert win_net.default_gateway() is None

    @patch("subprocess.run")
    def test_interfaces_empty_on_error(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert win_net.interfaces() == {}

    @patch("subprocess.run")
    def test_add_route_fails(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "The route addition failed")
        assert win_net.add_host_route("1.2.3.4", "192.168.1.1") is False

    @patch("subprocess.run")
    def test_add_net_route_no_cidr(self, mock_run, win_net):
        """Network without /prefix - returns False."""
        assert win_net.add_net_route("10.0.0.0", "192.168.1.1") is False

    @patch("subprocess.run")
    def test_check_interface_not_connected(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "Connect state: Disconnected\n", ""
        )
        # Not connected via netsh, but also not in ipconfig (second call returns empty)
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "Connect state: Disconnected\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),  # ipconfig fallback
        ]
        assert win_net.check_interface("NonExistent") is False

    @patch("subprocess.run")
    def test_ppp_peer_no_gateway(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "\nPPP adapter VPN:\n\n"
            "   IPv4 Address. . . . . . . . . . . : 10.0.0.2\n"
            "   Default Gateway . . . . . . . . . :\n",
            "",
        )
        assert win_net.ppp_peer("VPN") == ""

    @patch("subprocess.run")
    def test_ppp_peer_wrong_adapter(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "\nEthernet adapter LAN:\n\n"
            "   Default Gateway . . . . . . . . . : 192.168.1.1\n",
            "",
        )
        assert win_net.ppp_peer("VPN") == ""

    @patch("subprocess.run")
    def test_route_table_empty_on_error(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert win_net.route_table() == ""

    @patch("subprocess.run")
    def test_iface_info_empty_on_error(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "not found")
        assert win_net.iface_info("NonExistent") == ""

    @patch("subprocess.run")
    def test_cleanup_local_dns_resolvers_empty(self, mock_run, win_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert win_net.cleanup_local_dns_resolvers() == []


# =========================================================================
# resolve_host fallbacks (nslookup + socket)
# =========================================================================

class TestResolveHostFallbacks:
    @patch("shutil.which", return_value=None)
    @patch("socket.getaddrinfo")
    def test_socket_fallback(self, mock_gai, mock_which, win_net):
        """No CLI tools -> socket.getaddrinfo fallback."""
        mock_gai.return_value = [
            (2, 1, 6, '', ('1.2.3.4', 0)),
            (2, 1, 6, '', ('5.6.7.8', 0)),
        ]
        ips = win_net.resolve_host("test.com")
        assert ips == ["1.2.3.4", "5.6.7.8"]

    @patch("shutil.which", return_value=None)
    @patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known"))
    def test_socket_fallback_fails(self, mock_gai, mock_which, win_net):
        """socket.getaddrinfo fails -> empty list."""
        ips = win_net.resolve_host("nonexistent.invalid")
        assert ips == []

    @patch("shutil.which", side_effect=lambda cmd: "/usr/bin/nslookup" if cmd == "nslookup" else None)
    @patch("subprocess.run")
    def test_nslookup_fallback(self, mock_run, mock_which, win_net):
        """nslookup available -> parse output."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "Server:  dns.local\nAddress:  10.0.0.1\n\n"
            "Name:    test.com\nAddress:  1.2.3.4\n",
            "",
        )
        ips = win_net.resolve_host("test.com")
        assert ips == ["1.2.3.4"]

    @patch("shutil.which", side_effect=lambda cmd: "/usr/bin/nslookup" if cmd == "nslookup" else None)
    @patch("subprocess.run")
    def test_nslookup_no_answer(self, mock_run, mock_which, win_net):
        """nslookup fails -> falls through to socket."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "NXDOMAIN")
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name not found")):
            ips = win_net.resolve_host("nonexistent.test")
        assert ips == []
