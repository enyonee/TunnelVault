"""Tests for tv.net: platform-aware networking."""

from __future__ import annotations

import socket
import subprocess
from unittest.mock import patch

import pytest

from tv.net import (
    DarwinNet,
    LinuxNet,
    create,
    _run,
    _gateway_covering_domain,
    _PUBLIC_DNS_FALLBACK,
)


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
            [],
            0,
            "   route to: default\n   gateway: 192.168.1.1\n   interface: en0\n",
            "",
        )
        assert darwin_net.default_gateway() == "192.168.1.1"

    @patch("subprocess.run")
    def test_check_interface_true(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "ppp0: flags=...", ""
        )
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
        mock_run.return_value = subprocess.CompletedProcess(
            [], 1, "", "route: not found"
        )
        assert darwin_net.default_gateway() is None

    @patch("subprocess.run")
    def test_check_interface_false(self, mock_run, darwin_net):
        """Несуществующий интерфейс - False."""
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "")
        assert darwin_net.check_interface("ppp0") is False

    @patch("subprocess.run")
    def test_add_route_fails_returns_false(self, mock_run, darwin_net):
        """Маршрут уже существует - returncode != 0 - False."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 1, "", "route already exists"
        )
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
            [],
            0,
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
            [],
            0,
            "ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n"
            "\tinet 10.0.0.2 --> 10.0.0.1 netmask 0xffffffff\n",
            "",
        )
        assert darwin_net.ppp_peer("ppp0") == "10.0.0.1"

    @patch("subprocess.run")
    def test_ppp_peer_darwin_no_peer(self, mock_run, darwin_net):
        """macOS: ifconfig без --> возвращает пустую строку."""
        mock_run.return_value = subprocess.CompletedProcess(
            [],
            0,
            "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
            "\tinet 192.168.1.7 netmask 0xffffff00 broadcast 192.168.1.255\n",
            "",
        )
        assert darwin_net.ppp_peer("en0") == ""

    @patch("subprocess.run")
    def test_ppp_peer_darwin_iface_down(self, mock_run, darwin_net):
        """macOS: интерфейс не существует - пустая строка."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 1, "", "ifconfig: interface ppp0 does not exist"
        )
        assert darwin_net.ppp_peer("ppp0") == ""


# =========================================================================
# Positive: resolve_host (common to both platforms)
# =========================================================================


class TestResolveHost:
    @patch("shutil.which", return_value="/usr/bin/dig")
    @patch("subprocess.run")
    def test_dig_returns_ips(self, mock_run, _, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "1.2.3.4\n5.6.7.8\n", ""
        )
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
            [],
            0,
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
            [],
            0,
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
            [],
            0,
            "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
            "",
        )
        assert linux_net.default_gateway() == "192.168.1.1"

    @patch("subprocess.run")
    def test_interfaces_parses(self, mock_run, linux_net):
        """Парсит вывод ip -br addr."""
        mock_run.return_value = subprocess.CompletedProcess(
            [],
            0,
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
    def test_setup_dns_resolver_no_interface_returns_false(self, mock_run, linux_net):
        """Linux: без interface resolvectl не вызывается, все домены False."""
        results = linux_net.setup_dns_resolver(["test.local"], ["10.0.0.1"])
        assert results["test.local"] is False
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_setup_dns_custom_interface(self, mock_run, linux_net):
        """Linux: resolvectl с custom interface (tun0, utun99)."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch("shutil.which", return_value="/usr/bin/resolvectl"):
            results = linux_net.setup_dns_resolver(
                ["alpha.local"], ["10.0.1.1"], "tun0"
            )
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
            [],
            0,
            "default via 192.168.1.1 dev eth0\n10.0.0.0/8 via 10.0.0.1 dev ppp0\n",
            "",
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
        mock_run.return_value = subprocess.CompletedProcess(
            [], 1, "", "Device not found"
        )
        assert linux_net.check_interface("ppp0") is False

    @patch("subprocess.run")
    def test_add_route_fails(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 2, "", "RTNETLINK: File exists"
        )
        assert linux_net.add_host_route("1.2.3.4", "192.168.1.1") is False

    @patch("subprocess.run")
    def test_route_table_fallback_to_netstat(self, mock_run, linux_net):
        """ip route фейлится - fallback на netstat."""
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 1, "", ""),  # ip route fails
            subprocess.CompletedProcess(
                [], 0, "Kernel IP routing table\ndefault gw 192.168.1.1\n", ""
            ),
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
        mock_run.return_value = subprocess.CompletedProcess(
            [], 1, "", "Device not found"
        )
        with patch("shutil.which", return_value="/usr/bin/resolvectl"):
            results = linux_net.setup_dns_resolver(["test.local"], ["10.0.0.1"])
        assert results["test.local"] is False

    @patch("subprocess.run")
    def test_setup_dns_custom_iface_not_found(self, mock_run, linux_net):
        """Custom interface not found - all domains False."""
        mock_run.return_value = subprocess.CompletedProcess(
            [], 1, "", "Device not found"
        )
        with patch("shutil.which", return_value="/usr/bin/resolvectl"):
            results = linux_net.setup_dns_resolver(
                ["test.local"], ["10.0.0.1"], "utun99"
            )
        assert results["test.local"] is False

    @patch("subprocess.run")
    def test_ppp_peer_linux_ip_addr(self, mock_run, linux_net):
        """Linux: парсит peer из ip addr show."""
        mock_run.return_value = subprocess.CompletedProcess(
            [],
            0,
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
                [],
                0,
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
            subprocess.CompletedProcess(
                [], 0, "2: eth0: <BROADCAST>\n    inet 192.168.1.5/24\n", ""
            ),
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


# =========================================================================
# IPv6 primitives (PR#2)
# =========================================================================


class TestDarwinIPv6:
    """macOS IPv6 routes: 'route add -inet6 <target> -interface <iface>'.

    ВАЖНО: add_iface_route6 НЕ использует ppp_peer (IPv4-only) - сразу
    -interface utunN прямо. macOS ядро находит next-hop через интерфейс.
    """

    @patch("subprocess.run")
    def test_add_host_route6(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = darwin_net.add_host_route6("2001:db8::1", "fe80::1")
        assert ok
        args = mock_run.call_args[0][0]
        assert args == [
            "sudo",
            "route",
            "add",
            "-inet6",
            "-host",
            "2001:db8::1",
            "fe80::1",
        ]

    @patch("subprocess.run")
    def test_add_net_route6(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = darwin_net.add_net_route6("2001:db8::/32", "fe80::1")
        assert ok
        args = mock_run.call_args[0][0]
        assert "-inet6" in args and "-net" in args and "2001:db8::/32" in args

    @patch("subprocess.run")
    def test_add_iface_route6_tun_uses_interface_flag(self, mock_run, darwin_net):
        """IPv6 на utun* идёт через -interface (НЕ ppp_peer, который IPv4-only)."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = darwin_net.add_iface_route6("2001:db8::/32", "utun99", host=False)
        assert ok
        args = mock_run.call_args[0][0]
        assert args == [
            "sudo",
            "route",
            "add",
            "-inet6",
            "-net",
            "2001:db8::/32",
            "-interface",
            "utun99",
        ]

    @patch("subprocess.run")
    def test_add_iface_route6_host(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        darwin_net.add_iface_route6("2001:db8::1", "utun99", host=True)
        args = mock_run.call_args[0][0]
        assert "-host" in args and "2001:db8::1" in args

    @patch("subprocess.run")
    def test_delete_host_route6(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = darwin_net.delete_host_route6("2001:db8::1")
        assert ok
        args = mock_run.call_args[0][0]
        assert args == ["sudo", "route", "delete", "-inet6", "-host", "2001:db8::1"]

    @patch("subprocess.run")
    def test_delete_net_route6(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        darwin_net.delete_net_route6("2001:db8::/32")
        args = mock_run.call_args[0][0]
        assert args == ["sudo", "route", "delete", "-inet6", "-net", "2001:db8::/32"]

    @patch("subprocess.run")
    def test_set_dns6_writes_resolver_file(self, mock_run, darwin_net):
        """IPv6 nameserver без скобок: 'nameserver 2001:db8::1'."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        results = darwin_net.set_dns6(["test.local"], ["2001:db8::1"])
        assert results["test.local"] is True
        # Проверим что tee получил правильный content (IPv6 без brackets)
        tee_call = next(c for c in mock_run.call_args_list if "tee" in c[0][0])
        content = tee_call.kwargs.get("input", "")
        assert "nameserver 2001:db8::1" in content
        assert "[" not in content  # без скобок

    @patch("subprocess.run")
    def test_set_dns6_empty_nameservers_noop(self, mock_run, darwin_net):
        """Пустой nameservers - no-op, нет subprocess calls (защита M7)."""
        results = darwin_net.set_dns6(["test.local"], [])
        assert results == {"test.local": False}
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_set_dns6_empty_domains_noop(self, mock_run, darwin_net):
        results = darwin_net.set_dns6([], ["2001:db8::1"])
        assert results == {}


class TestLinuxIPv6:
    """Linux IPv6: 'ip -6 route replace' (не add - безопаснее при существующем ::/0 от RA)."""

    @patch("subprocess.run")
    def test_add_host_route6_via_ip6_replace(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = linux_net.add_host_route6("2001:db8::1", "fe80::1")
        assert ok
        args = mock_run.call_args[0][0]
        assert args == [
            "sudo",
            "ip",
            "-6",
            "route",
            "replace",
            "2001:db8::1/128",
            "via",
            "fe80::1",
        ]

    @patch("subprocess.run")
    def test_add_net_route6_replace(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        linux_net.add_net_route6("2001:db8::/32", "fe80::1")
        args = mock_run.call_args[0][0]
        assert "replace" in args and "2001:db8::/32" in args
        assert "via" in args and "fe80::1" in args

    @patch("subprocess.run")
    def test_add_iface_route6_dev(self, mock_run, linux_net):
        """ip -6 route replace <cidr> dev <iface> - обходит RA-conflict."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        linux_net.add_iface_route6("2001:db8::/32", "tun0", host=False)
        args = mock_run.call_args[0][0]
        assert args == [
            "sudo",
            "ip",
            "-6",
            "route",
            "replace",
            "2001:db8::/32",
            "dev",
            "tun0",
        ]

    @patch("subprocess.run")
    def test_add_iface_route6_host_uses_128(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        linux_net.add_iface_route6("2001:db8::1", "tun0", host=True)
        args = mock_run.call_args[0][0]
        assert "2001:db8::1/128" in args

    @patch("subprocess.run")
    def test_delete_host_route6_uses_128(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        linux_net.delete_host_route6("2001:db8::1")
        args = mock_run.call_args[0][0]
        assert args == ["sudo", "ip", "-6", "route", "del", "2001:db8::1/128"]

    @patch("subprocess.run")
    def test_delete_net_route6(self, mock_run, linux_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        linux_net.delete_net_route6("2001:db8::/32")
        args = mock_run.call_args[0][0]
        assert args == ["sudo", "ip", "-6", "route", "del", "2001:db8::/32"]

    @patch("tv.net.shutil.which", return_value="/usr/bin/resolvectl")
    @patch("subprocess.run")
    def test_set_dns6_resolvectl(self, mock_run, mock_which, linux_net):
        """resolvectl принимает IPv6 nameservers без кавычек."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        results = linux_net.set_dns6(["test.local"], ["2001:db8::1"], "tun0")
        assert results["test.local"] is True
        # Проверим что resolvectl dns tun0 2001:db8::1 (без кавычек)
        dns_call = next(
            c
            for c in mock_run.call_args_list
            if "resolvectl" in c[0][0] and "dns" in c[0][0]
        )
        args = dns_call[0][0]
        assert "2001:db8::1" in args
        # Без quoting - IPv6 адрес прямо как аргумент
        assert "'2001:db8::1'" not in args

    @patch("subprocess.run")
    def test_set_dns6_empty_nameservers_noop(self, mock_run, linux_net):
        """Защита M7: пустой nameservers - no-op (иначе resolvectl СБРАСЫВАЕТ DNS)."""
        results = linux_net.set_dns6(["test.local"], [], "tun0")
        assert results == {"test.local": False}
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_set_dns6_no_interface_noop(self, mock_run, linux_net):
        results = linux_net.set_dns6(["test.local"], ["2001:db8::1"], "")
        assert results == {"test.local": False}
        mock_run.assert_not_called()

    @patch("tv.net.shutil.which", return_value=None)
    @patch("subprocess.run")
    def test_set_dns6_no_resolvectl_noop(self, mock_run, mock_which, linux_net):
        results = linux_net.set_dns6(["test.local"], ["2001:db8::1"], "tun0")
        assert results == {"test.local": False}
        mock_run.assert_not_called()


class TestIPv6Defaults:
    """NetManager ABC: defaults для IPv6 методов - backward compat для stub реализаций."""

    def test_add_host_route6_default_false(self):
        """Базовый класс: add_host_route6 возвращает False (no-op)."""
        # Используем DarwinNet, но вызовем через super(), чтобы проверить ABC default.
        # Проще: создадим mock класс на базе NetManager без переопределения IPv6.
        from tv.net import NetManager

        class MinimalNet(NetManager):
            def default_gateway(self):
                return None

            def interfaces(self):
                return {}

            def check_interface(self, name):
                return False

            def add_host_route(self, ip, gateway):
                return False

            def add_net_route(self, net, gateway):
                return False

            def add_iface_route(self, target, iface, host=True):
                return False

            def setup_dns_resolver(self, domains, nameservers, interface=""):
                return {}

            def cleanup_dns_resolver(self, domains, interface=""):
                return None

            def disable_ipv6(self):
                return False

            def restore_ipv6(self):
                return False

            def delete_host_route(self, ip):
                return False

            def delete_net_route(self, net):
                return False

            def route_table(self, lines=None):
                return ""

            def iface_info(self, name):
                return ""

            def ppp_peer(self, name):
                return ""

        n = MinimalNet()
        assert n.add_host_route6("2001:db8::1", "fe80::1") is False
        assert n.add_net_route6("2001:db8::/32", "fe80::1") is False
        assert n.add_iface_route6("2001:db8::/32", "tun0") is False
        assert n.delete_host_route6("2001:db8::1") is False
        assert n.delete_net_route6("2001:db8::/32") is False
        assert n.set_dns6(["test.local"], ["2001:db8::1"]) == {"test.local": False}


# =========================================================================
# Layer 1: gateway DNS carve-out (openconnect/fortivpn cold-start fix)
# =========================================================================


class TestGatewayCoveringDomain:
    """Pure helper: определяет попадает ли шлюз под собственный DNS-домен туннеля."""

    def test_strict_subdomain_matches(self):
        assert (
            _gateway_covering_domain("vpn.new-mmc.com", ["new-mmc.com"])
            == "new-mmc.com"
        )

    def test_picks_from_multiple_domains(self):
        assert (
            _gateway_covering_domain(
                "vpn.new-mmc.com", ["asup.local", "nmmc.local", "new-mmc.com"]
            )
            == "new-mmc.com"
        )

    def test_picks_longest_most_specific(self):
        # host под обоими доменами — берём более специфичный
        assert (
            _gateway_covering_domain(
                "vpn.a.new-mmc.com", ["new-mmc.com", "a.new-mmc.com"]
            )
            == "a.new-mmc.com"
        )

    def test_exact_match_returns_none(self):
        # шлюз == сам домен: более специфичный резолвер не написать
        assert _gateway_covering_domain("new-mmc.com", ["new-mmc.com"]) is None

    def test_not_covered_returns_none(self):
        assert _gateway_covering_domain("vpn.example.org", ["new-mmc.com"]) is None

    def test_empty_gateway_returns_none(self):
        assert _gateway_covering_domain("", ["new-mmc.com"]) is None

    def test_case_and_trailing_dot_insensitive(self):
        assert (
            _gateway_covering_domain("VPN.New-MMC.com.", ["NEW-MMC.COM"])
            == "new-mmc.com"
        )

    def test_partial_suffix_not_matched(self):
        # 'evil-new-mmc.com' НЕ поддомен 'new-mmc.com' (нет точки-границы)
        assert _gateway_covering_domain("evilnew-mmc.com", ["new-mmc.com"]) is None


class TestSystemDnsServers:
    """Парсер scutil --dns: глобальный резолвер, минуя scoped-блоки туннелей."""

    SCUTIL = """DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.0.1
  nameserver[1] : 192.168.0.2
  if_index : 14 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

resolver #3
  domain   : new-mmc.com
  nameserver[0] : 10.11.1.101
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 10.99.99.99
  if_index : 14 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
"""

    @patch("subprocess.run")
    def test_returns_global_resolver_only(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, self.SCUTIL, "")
        # только глобальный resolver #1; scoped (domain: / new-mmc.com / scoped-секция) выкинуты
        assert darwin_net.system_dns_servers() == ["192.168.0.1", "192.168.0.2"]

    @patch("subprocess.run")
    def test_scutil_failure_returns_empty(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "err")
        assert darwin_net.system_dns_servers() == []


class TestCarveoutNameservers:
    """Выбор DNS для резолва шлюза: система → шлюз → публичный, минус внутренние."""

    def test_prefers_system_dns_excluding_internal(self, darwin_net):
        with patch.object(
            darwin_net,
            "system_dns_servers",
            return_value=["192.168.0.1", "10.11.1.101"],
        ):
            # внутренний 10.11.1.101 исключён, чтобы не замкнуть круг
            assert darwin_net._carveout_nameservers(["10.11.1.101"]) == ["192.168.0.1"]

    def test_falls_back_to_gateway(self, darwin_net):
        with (
            patch.object(darwin_net, "system_dns_servers", return_value=[]),
            patch.object(darwin_net, "default_gateway", return_value="192.168.1.1"),
        ):
            assert darwin_net._carveout_nameservers(["10.11.1.101"]) == ["192.168.1.1"]

    def test_falls_back_to_public(self, darwin_net):
        with (
            patch.object(darwin_net, "system_dns_servers", return_value=[]),
            patch.object(darwin_net, "default_gateway", return_value=None),
        ):
            assert darwin_net._carveout_nameservers(["10.11.1.101"]) == list(
                _PUBLIC_DNS_FALLBACK
            )


def _tee_input_for(mock_run, path: str) -> str | None:
    """Найти input= для вызова `sudo tee <path>` среди зафиксированных вызовов."""
    for call in mock_run.call_args_list:
        cmd = call.args[0] if call.args else call.kwargs.get("args")
        if cmd and cmd[:2] == ["sudo", "tee"] and cmd[-1] == path:
            return call.kwargs.get("input")
    return None


class TestSetupDnsResolverCarveout:
    @patch("subprocess.run")
    def test_writes_gateway_carveout_file(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(
            darwin_net, "_carveout_nameservers", return_value=["192.168.0.1"]
        ):
            darwin_net.setup_dns_resolver(
                ["new-mmc.com"],
                ["10.11.1.101", "10.0.0.12"],
                gateway_host="vpn.new-mmc.com",
            )
        # домен туннеля -> внутренний DNS
        dom = _tee_input_for(mock_run, "/etc/resolver/new-mmc.com")
        assert dom is not None and "10.11.1.101" in dom
        # более специфичный резолвер шлюза -> системный DNS, БЕЗ внутреннего
        gw = _tee_input_for(mock_run, "/etc/resolver/vpn.new-mmc.com")
        assert gw is not None
        assert "192.168.0.1" in gw
        assert "10.11.1.101" not in gw
        assert "# tunnelvault" in gw

    @patch("subprocess.run")
    def test_no_carveout_when_gateway_not_covered(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(
            darwin_net, "_carveout_nameservers", return_value=["192.168.0.1"]
        ) as carve:
            darwin_net.setup_dns_resolver(
                ["new-mmc.com"],
                ["10.11.1.101"],
                gateway_host="vpn.example.org",
            )
        # шлюз вне домена туннеля — carve-out не пишется
        assert _tee_input_for(mock_run, "/etc/resolver/vpn.example.org") is None
        carve.assert_not_called()


class TestWriteGatewayCarveout:
    """Standalone carve-out для бутстрапа (до connect), engine._setup_gateway_carveouts."""

    @patch("subprocess.run")
    def test_writes_only_gateway_not_internal_domain(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(
            darwin_net, "_carveout_nameservers", return_value=["192.168.1.1"]
        ):
            ok = darwin_net.write_gateway_carveout(
                "vpn.new-mmc.com", ["new-mmc.com"], ["10.11.1.101", "10.0.0.12"]
            )
        assert ok is True
        # пишется ТОЛЬКО carve-out шлюза на системный DNS...
        gw = _tee_input_for(mock_run, "/etc/resolver/vpn.new-mmc.com")
        assert gw is not None and "192.168.1.1" in gw and "10.11.1.101" not in gw
        assert "# tunnelvault" in gw
        # ...и НЕ пишется резолвер внутреннего домена туннеля (это делает connect).
        assert _tee_input_for(mock_run, "/etc/resolver/new-mmc.com") is None

    @patch("subprocess.run")
    def test_noop_when_gateway_not_under_tunnel_domain(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        ok = darwin_net.write_gateway_carveout(
            "vpn.example.org", ["new-mmc.com"], ["10.11.1.101"]
        )
        assert ok is False
        assert _tee_input_for(mock_run, "/etc/resolver/vpn.example.org") is None

    def test_base_default_is_noop(self):
        # Linux/Windows: ловушки нет, carve-out не нужен.
        from tv.net import LinuxNet

        assert (
            LinuxNet().write_gateway_carveout(
                "vpn.new-mmc.com", ["new-mmc.com"], ["10.11.1.101"]
            )
            is False
        )

    @patch("subprocess.run")
    def test_flush_dns_reloads_mdnsresponder(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        darwin_net.flush_dns()
        cmds = [
            c.args[0] if c.args else c.kwargs.get("args")
            for c in mock_run.call_args_list
        ]
        assert ["sudo", "dscacheutil", "-flushcache"] in cmds
        assert ["sudo", "killall", "-HUP", "mDNSResponder"] in cmds

    @patch("subprocess.run")
    def test_no_carveout_without_gateway_host(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        darwin_net.setup_dns_resolver(["new-mmc.com"], ["10.11.1.101"])
        # обычный вызов без gateway_host: только домен, без лишних файлов
        assert _tee_input_for(mock_run, "/etc/resolver/new-mmc.com") is not None


class TestCleanupDnsResolverCarveout:
    @patch("subprocess.run")
    def test_removes_gateway_carveout_file(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        darwin_net.cleanup_dns_resolver(["new-mmc.com"], gateway_host="vpn.new-mmc.com")
        rm_cmd = mock_run.call_args_list[-1].args[0]
        assert rm_cmd[:3] == ["sudo", "rm", "-f"]
        assert "/etc/resolver/new-mmc.com" in rm_cmd
        assert "/etc/resolver/vpn.new-mmc.com" in rm_cmd

    @patch("subprocess.run")
    def test_no_gateway_file_when_not_covered(self, mock_run, darwin_net):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        darwin_net.cleanup_dns_resolver(["new-mmc.com"], gateway_host="vpn.example.org")
        rm_cmd = mock_run.call_args_list[-1].args[0]
        assert "/etc/resolver/vpn.example.org" not in rm_cmd


# =========================================================================
# Layer 2: cold-start cleanup of orphaned tunnelvault resolvers
# =========================================================================


class TestCleanupLocalDnsResolvers:
    def _seed(self, tmp_path):
        (tmp_path / "new-mmc.com").write_text("# tunnelvault\nnameserver 10.11.1.101\n")
        (tmp_path / "vpn.new-mmc.com").write_text(
            "# tunnelvault\n# gateway carve-out\nnameserver 192.168.0.1\n"
        )
        (tmp_path / "corp.example").write_text(
            "# some other tool\nnameserver 9.9.9.9\n"
        )

    @patch("subprocess.run")
    def test_removes_only_marked(self, mock_run, darwin_net, tmp_path, monkeypatch):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self._seed(tmp_path)
        monkeypatch.setattr(
            "tv.net.cfg.paths.resolver_dir", str(tmp_path), raising=False
        )
        cleaned = darwin_net.cleanup_local_dns_resolvers()
        assert set(cleaned) == {"new-mmc.com", "vpn.new-mmc.com"}
        assert "corp.example" not in cleaned  # чужой файл не тронут

    @patch("subprocess.run")
    def test_keep_protects_alive_tunnel(
        self, mock_run, darwin_net, tmp_path, monkeypatch
    ):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self._seed(tmp_path)
        monkeypatch.setattr(
            "tv.net.cfg.paths.resolver_dir", str(tmp_path), raising=False
        )
        cleaned = darwin_net.cleanup_local_dns_resolvers(
            keep={"new-mmc.com", "vpn.new-mmc.com"}
        )
        assert cleaned == []  # оба защищены keep

    @patch("subprocess.run")
    def test_missing_resolver_dir_returns_empty(
        self, mock_run, darwin_net, tmp_path, monkeypatch
    ):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        monkeypatch.setattr(
            "tv.net.cfg.paths.resolver_dir", str(tmp_path / "nope"), raising=False
        )
        assert darwin_net.cleanup_local_dns_resolvers() == []
