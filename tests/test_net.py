"""Tests for tv.net: platform-aware networking."""

from __future__ import annotations

import socket
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from tv.net import DarwinNet, LinuxNet, create, NetManager, _run


@pytest.fixture
def darwin_net():
    return DarwinNet()


@pytest.fixture
def linux_net():
    return LinuxNet()


# =========================================================================
# Factory
# =========================================================================

class TestFactory:
    @patch("platform.system", return_value="Darwin")
    def test_creates_darwin(self, _):
        assert isinstance(create(), DarwinNet)

    @patch("platform.system", return_value="Linux")
    def test_creates_linux(self, _):
        assert isinstance(create(), LinuxNet)

    @patch("platform.system", return_value="FreeBSD")
    def test_unknown_os_defaults_to_linux_with_warning(self, _):
        """Неизвестная ОС - LinuxNet как fallback + warning."""
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            net = create()
            assert isinstance(net, LinuxNet)
            assert len(w) == 1
            assert "FreeBSD" in str(w[0].message)


# =========================================================================
# Positive: DarwinNet
# =========================================================================

class TestDarwinNet:
    @patch("subprocess.run")
    def test_default_gateway_parses(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "   route to: default\n   gateway: 192.168.1.1\n   interface: en0\n",
            "",
        )
        assert darwin_net.default_gateway() == "192.168.1.1"

    @patch("subprocess.run")
    def test_check_interface_true(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "ppp0: flags=...", "")
        assert darwin_net.check_interface("ppp0") is True

    @patch("subprocess.run")
    def test_add_host_route_calls_sudo(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        darwin_net.add_host_route("1.2.3.4", "192.168.1.1")
        args = mock_run.call_args[0][0]
        assert args[:2] == ["sudo", "route"]
        assert "1.2.3.4" in args

    @patch("subprocess.run")
    def test_setup_dns_resolver(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        results = darwin_net.setup_dns_resolver(["test.local"], ["10.0.0.1"])
        assert results["test.local"] is True
        # Should call mkdir + tee
        assert mock_run.call_count >= 2


# =========================================================================
# Negative / inverse: DarwinNet failures
# =========================================================================

class TestDarwinNetInverse:
    @patch("subprocess.run")
    def test_no_gateway_returns_none(self, mock_run, darwin_net):
        """Если route -n get default не работает - None."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "route: not found")
        assert darwin_net.default_gateway() is None

    @patch("subprocess.run")
    def test_check_interface_false(self, mock_run, darwin_net):
        """Несуществующий интерфейс - False."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert darwin_net.check_interface("ppp0") is False

    @patch("subprocess.run")
    def test_add_route_fails_returns_false(self, mock_run, darwin_net):
        """Маршрут уже существует - returncode != 0 - False."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "route already exists")
        assert darwin_net.add_host_route("1.2.3.4", "192.168.1.1") is False

    @patch("subprocess.run")
    def test_empty_interfaces_on_error(self, mock_run, darwin_net):
        """ifconfig -a фейлится - пустой dict."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert darwin_net.interfaces() == {}

    @patch("subprocess.run")
    def test_interfaces_parses_ifconfig_a(self, mock_run, darwin_net):
        """ifconfig -a: парсит несколько интерфейсов за один вызов."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
            "\tinet 127.0.0.1 netmask 0xff000000\n"
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tether aa:bb:cc:dd:ee:ff\n"
            "\tinet6 fe80::1%en0\n"
            "\tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255\n"
            "ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n"
            "\tinet 10.0.0.2 --> 10.0.0.1 netmask 0xffffffff\n",
            "",
        )
        ifaces = darwin_net.interfaces()
        assert ifaces["lo0"] == "127.0.0.1"
        assert ifaces["en0"] == "192.168.1.5"
        assert ifaces["ppp0"] == "10.0.0.2"
        # Single subprocess call (not N+1)
        assert mock_run.call_count == 1

    @patch("subprocess.run")
    def test_route_table_empty_on_error(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert darwin_net.route_table() == ""

    @patch("subprocess.run")
    def test_ppp_peer_darwin(self, mock_run, darwin_net):
        """macOS: парсит inet X.X.X.X --> Y.Y.Y.Y."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n"
            "\tinet 10.0.0.2 --> 10.0.0.1 netmask 0xffffffff\n",
            "",
        )
        assert darwin_net.ppp_peer("ppp0") == "10.0.0.1"

    @patch("subprocess.run")
    def test_ppp_peer_darwin_no_peer(self, mock_run, darwin_net):
        """macOS: ifconfig без --> возвращает пустую строку."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
            "\tinet 192.168.1.7 netmask 0xffffff00 broadcast 192.168.1.255\n",
            "",
        )
        assert darwin_net.ppp_peer("en0") == ""

    @patch("subprocess.run")
    def test_ppp_peer_darwin_iface_down(self, mock_run, darwin_net):
        """macOS: интерфейс не существует - пустая строка."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "ifconfig: interface ppp0 does not exist")
        assert darwin_net.ppp_peer("ppp0") == ""


# =========================================================================
# Positive: resolve_host (common to both platforms)
# =========================================================================

class TestResolveHost:
    @patch("shutil.which", return_value="/usr/bin/dig")
    @patch("subprocess.run")
    def test_dig_returns_ips(self, mock_run, _, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "1.2.3.4\n5.6.7.8\n", "")
        ips = darwin_net.resolve_host("test.com")
        assert ips == ["1.2.3.4", "5.6.7.8"]

    @patch("shutil.which", return_value="/usr/bin/dig")
    @patch("subprocess.run")
    def test_dig_filters_non_ip(self, mock_run, _, darwin_net):
        """dig может вернуть CNAME, а не IP."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "alias.cdn.com.\n1.2.3.4\n", ""
        )
        ips = darwin_net.resolve_host("test.com")
        assert ips == ["1.2.3.4"]


# =========================================================================
# Negative / inverse: resolve_host failures
# =========================================================================

class TestResolveHostInverse:
    @patch("socket.getaddrinfo", side_effect=socket.gaierror("not found"))
    @patch("shutil.which", return_value=None)
    def test_no_dns_tools_returns_empty(self, _, __, darwin_net):
        """Нет ни dig, ни host, ни getent, socket fails - пустой список."""
        ips = darwin_net.resolve_host("test.com")
        assert ips == []

    @patch("shutil.which", return_value="/usr/bin/dig")
    @patch("subprocess.run")
    def test_dns_failure_returns_empty(self, mock_run, _, darwin_net):
        """DNS не резолвит - пустой список."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        ips = darwin_net.resolve_host("nonexistent.invalid")
        assert ips == []

    @patch("shutil.which", return_value="/usr/bin/dig")
    @patch("subprocess.run")
    def test_dig_empty_output_returns_empty(self, mock_run, _, darwin_net):
        """dig успешен, но вывод пустой."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "\n", "")
        ips = darwin_net.resolve_host("test.com")
        assert ips == []


# =========================================================================
# _run helper with timeout
# =========================================================================

class TestRunHelper:
    @patch("subprocess.run")
    def test_default_timeout(self, mock_run):
        """_run передаёт timeout по умолчанию."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        _run(["echo", "hi"])
        _, kwargs = mock_run.call_args
        assert kwargs["timeout"] == 10

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["cmd"], 10))
    def test_timeout_returns_fake_result(self, _):
        """TimeoutExpired не crash, возвращает CompletedProcess с rc=-1."""
        r = _run(["sleep", "999"])
        assert r.returncode == -1
        assert r.stderr == "timeout"


# =========================================================================
# DarwinNet._active_network_services
# =========================================================================

class TestActiveNetworkServices:
    @patch("subprocess.run")
    def test_parses_services(self, mock_run, darwin_net):
        """Парсит вывод networksetup."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "An asterisk (*) denotes that a network service is disabled.\n"
            "Wi-Fi\n"
            "Ethernet\n"
            "Thunderbolt Bridge\n",
            "",
        )
        svcs = darwin_net._active_network_services()
        assert "Wi-Fi" in svcs
        assert "Ethernet" in svcs
        assert "Thunderbolt Bridge" in svcs

    @patch("subprocess.run")
    def test_skips_disabled(self, mock_run, darwin_net):
        """Пропускает отключенные сервисы (со звёздочкой)."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "An asterisk (*) denotes that a network service is disabled.\n"
            "Wi-Fi\n"
            "*Bluetooth PAN\n",
            "",
        )
        svcs = darwin_net._active_network_services()
        assert "Wi-Fi" in svcs
        assert "*Bluetooth PAN" not in svcs
        assert "Bluetooth PAN" not in svcs

    @patch("subprocess.run")
    def test_fallback_on_error(self, mock_run, darwin_net):
        """При ошибке networksetup - fallback на Wi-Fi."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        svcs = darwin_net._active_network_services()
        assert svcs == ["Wi-Fi"]


# =========================================================================
# Positive: LinuxNet
# =========================================================================

class TestLinuxNet:
    @patch("subprocess.run")
    def test_default_gateway_parses(self, mock_run, linux_net):
        """Парсит вывод ip route show default."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
            "",
        )
        assert linux_net.default_gateway() == "192.168.1.1"

    @patch("subprocess.run")
    def test_interfaces_parses(self, mock_run, linux_net):
        """Парсит вывод ip -br addr."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "lo               UNKNOWN        127.0.0.1/8\n"
            "eth0             UP             192.168.1.5/24\n"
            "ppp0             UNKNOWN        10.0.0.2/32\n",
            "",
        )
        ifaces = linux_net.interfaces()
        assert ifaces["lo"] == "127.0.0.1"
        assert ifaces["eth0"] == "192.168.1.5"
        assert ifaces["ppp0"] == "10.0.0.2"

    @patch("subprocess.run")
    def test_check_interface_true(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "2: eth0: ...", "")
        assert linux_net.check_interface("eth0") is True

    @patch("subprocess.run")
    def test_add_host_route_calls_ip(self, mock_run, linux_net):
        """Linux: ip route add IP/32 via GW."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        linux_net.add_host_route("1.2.3.4", "192.168.1.1")
        args = mock_run.call_args[0][0]
        assert args[:2] == ["sudo", "ip"]
        assert "1.2.3.4/32" in args
        assert "192.168.1.1" in args

    @patch("subprocess.run")
    def test_add_net_route(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = linux_net.add_net_route("10.0.0.0/8", "192.168.1.1")
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "10.0.0.0/8" in args

    @patch("subprocess.run")
    def test_add_iface_route_host(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = linux_net.add_iface_route("1.2.3.4", "utun99", host=True)
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "1.2.3.4/32" in args
        assert "utun99" in args

    @patch("subprocess.run")
    def test_add_iface_route_net(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = linux_net.add_iface_route("172.18.0.0/16", "utun99", host=False)
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "172.18.0.0/16" in args

    @patch("subprocess.run")
    def test_setup_dns_resolver_with_resolvectl(self, mock_run, linux_net):
        """Linux: resolvectl для DNS через ppp0 (default)."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch("shutil.which", return_value="/usr/bin/resolvectl"):
            results = linux_net.setup_dns_resolver(["test.local"], ["10.0.0.1"])
        assert results["test.local"] is True
        # Verify ppp0 used as default interface
        link_call = mock_run.call_args_list[0]
        assert link_call[0][0] == ["ip", "link", "show", "ppp0"]

    @patch("subprocess.run")
    def test_setup_dns_custom_interface(self, mock_run, linux_net):
        """Linux: resolvectl с custom interface (tun0, utun99)."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch("shutil.which", return_value="/usr/bin/resolvectl"):
            results = linux_net.setup_dns_resolver(["alpha.local"], ["10.0.1.1"], "tun0")
        assert results["alpha.local"] is True
        # Verify tun0 used instead of ppp0
        link_call = mock_run.call_args_list[0]
        assert link_call[0][0] == ["ip", "link", "show", "tun0"]
        dns_call = mock_run.call_args_list[1]
        assert "tun0" in dns_call[0][0]

    @patch("subprocess.run")
    def test_cleanup_dns_custom_interface(self, mock_run, linux_net):
        """cleanup_dns_resolver uses custom interface."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch("shutil.which", return_value="/usr/bin/resolvectl"):
            linux_net.cleanup_dns_resolver(["alpha.local"], "tun0")
        args = mock_run.call_args[0][0]
        assert "tun0" in args

    @patch("subprocess.run")
    def test_disable_ipv6(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = linux_net.disable_ipv6()
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "net.ipv6.conf.all.disable_ipv6=1" in args

    @patch("subprocess.run")
    def test_restore_ipv6(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = linux_net.restore_ipv6()
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "net.ipv6.conf.all.disable_ipv6=0" in args

    @patch("subprocess.run")
    def test_delete_host_route(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = linux_net.delete_host_route("1.2.3.4")
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "1.2.3.4/32" in args

    @patch("subprocess.run")
    def test_delete_net_route(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = linux_net.delete_net_route("10.0.0.0/8")
        assert ok is True
        args = mock_run.call_args[0][0]
        assert "10.0.0.0/8" in args

    @patch("subprocess.run")
    def test_route_table_uses_ip_route(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "default via 192.168.1.1 dev eth0\n10.0.0.0/8 via 10.0.0.1 dev ppp0\n", ""
        )
        table = linux_net.route_table()
        assert "default" in table
        assert "10.0.0.0/8" in table


# =========================================================================
# Negative / inverse: LinuxNet failures
# =========================================================================

class TestLinuxNetInverse:
    @patch("subprocess.run")
    def test_no_gateway_returns_none(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert linux_net.default_gateway() is None

    @patch("subprocess.run")
    def test_no_via_in_output_returns_none(self, mock_run, linux_net):
        """ip route output без 'via' (link-local маршрут)."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "default dev ppp0 scope link\n", ""
        )
        assert linux_net.default_gateway() is None

    @patch("subprocess.run")
    def test_empty_interfaces_on_error(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert linux_net.interfaces() == {}

    @patch("subprocess.run")
    def test_check_interface_false(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "Device not found")
        assert linux_net.check_interface("ppp0") is False

    @patch("subprocess.run")
    def test_add_route_fails(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 2, "", "RTNETLINK: File exists")
        assert linux_net.add_host_route("1.2.3.4", "192.168.1.1") is False

    @patch("subprocess.run")
    def test_route_table_fallback_to_netstat(self, mock_run, linux_net):
        """ip route фейлится - fallback на netstat."""
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 1, "", ""),  # ip route fails
            subprocess.CompletedProcess([], 0, "Kernel IP routing table\ndefault gw 192.168.1.1\n", ""),
        ]
        table = linux_net.route_table()
        assert "default" in table

    @patch("subprocess.run")
    def test_route_table_empty_on_all_fail(self, mock_run, linux_net):
        """ip route и netstat фейлятся - пустая строка."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert linux_net.route_table() == ""

    @patch("subprocess.run")
    def test_setup_dns_no_resolvectl(self, mock_run, linux_net):
        """Без resolvectl - все домены False."""
        with patch("shutil.which", return_value=None):
            results = linux_net.setup_dns_resolver(["test.local"], ["10.0.0.1"])
        assert results["test.local"] is False

    @patch("subprocess.run")
    def test_setup_dns_no_ppp0(self, mock_run, linux_net):
        """resolvectl есть, но ppp0 нет - все домены False."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "Device not found")
        with patch("shutil.which", return_value="/usr/bin/resolvectl"):
            results = linux_net.setup_dns_resolver(["test.local"], ["10.0.0.1"])
        assert results["test.local"] is False

    @patch("subprocess.run")
    def test_setup_dns_custom_iface_not_found(self, mock_run, linux_net):
        """Custom interface not found - all domains False."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "Device not found")
        with patch("shutil.which", return_value="/usr/bin/resolvectl"):
            results = linux_net.setup_dns_resolver(["test.local"], ["10.0.0.1"], "utun99")
        assert results["test.local"] is False

    @patch("subprocess.run")
    def test_ppp_peer_linux_ip_addr(self, mock_run, linux_net):
        """Linux: парсит peer из ip addr show."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0,
            "4: ppp0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>\n"
            "    inet 10.0.0.2 peer 10.0.0.1/32 scope global ppp0\n",
            "",
        )
        assert linux_net.ppp_peer("ppp0") == "10.0.0.1"

    @patch("subprocess.run")
    def test_ppp_peer_linux_ifconfig_fallback(self, mock_run, linux_net):
        """Linux: ip addr не работает - fallback на ifconfig P-t-P."""
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 1, "", ""),  # ip addr fails
            subprocess.CompletedProcess(
                [], 0,
                "ppp0 Link encap:Point-to-Point Protocol\n"
                "inet addr:10.0.0.2  P-t-P:10.0.0.1  Mask:255.255.255.255\n",
                "",
            ),
        ]
        assert linux_net.ppp_peer("ppp0") == "10.0.0.1"

    @patch("subprocess.run")
    def test_ppp_peer_linux_no_peer(self, mock_run, linux_net):
        """Linux: ip addr без peer и ifconfig без P-t-P - пустая строка."""
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 0, "2: eth0: <BROADCAST>\n    inet 192.168.1.5/24\n", ""),
            subprocess.CompletedProcess([], 1, "", ""),
        ]
        assert linux_net.ppp_peer("eth0") == ""

    @patch("subprocess.run")
    def test_ppp_peer_linux_iface_not_found(self, mock_run, linux_net):
        """Linux: интерфейс не существует - пустая строка."""
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 1, "", "Device not found"),
            subprocess.CompletedProcess([], 1, "", ""),
        ]
        assert linux_net.ppp_peer("ppp0") == ""
