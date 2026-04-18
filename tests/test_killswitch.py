"""Tests for tv.killswitch: kill switch enable/disable and engine integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


from tv.killswitch import (
    DarwinKillSwitch,
    LinuxKillSwitch,
    WindowsKillSwitch,
    _build_pf_rules,
    _PF_ANCHOR,
    _IPTABLES_CHAIN,
    _IPTABLES_CHAIN_IN,
    _WIN_RULE_PREFIX,
    _is_valid_ip,
    _is_valid_ipv4,
    _is_valid_ipv6,
    _is_valid_network,
    _is_valid_ipv4_network,
    _is_valid_ipv6_network,
    _is_valid_iface,
    _sanitize_ips,
    _sanitize_networks,
    _sanitize_ifaces,
    _split_by_family,
    _split_networks_by_family,
    create,
)


# =========================================================================
# Input sanitization
# =========================================================================


class TestSanitization:
    def test_valid_ips(self):
        assert _is_valid_ip("1.2.3.4")
        assert _is_valid_ip("192.168.1.1")
        assert _is_valid_ip("255.255.255.255")

    def test_invalid_ips(self):
        assert not _is_valid_ip("1.2.3.4/32")
        assert not _is_valid_ip("not-an-ip")
        assert not _is_valid_ip("1.2.3.4; pass out all")
        assert not _is_valid_ip("")
        assert not _is_valid_ip("10.0.0.0/8")

    def test_valid_networks(self):
        assert _is_valid_network("10.0.0.0/8")
        assert _is_valid_network("192.168.1.0/24")
        assert _is_valid_network("0.0.0.0/0")

    def test_invalid_networks(self):
        assert not _is_valid_network("not-a-network")
        assert not _is_valid_network("10.0.0.0; DROP TABLE")
        assert not _is_valid_network("")

    def test_valid_ifaces(self):
        assert _is_valid_iface("utun99")
        assert _is_valid_iface("tun0")
        assert _is_valid_iface("ppp0")
        assert _is_valid_iface("en0")

    def test_invalid_ifaces(self):
        assert not _is_valid_iface("tun0; rm -rf /")
        assert not _is_valid_iface("tun 0")
        assert not _is_valid_iface("")
        assert not _is_valid_iface("tun\n0")

    def test_sanitize_ips_filters(self):
        result = _sanitize_ips(["1.2.3.4", "bad; stuff", "5.6.7.8"])
        assert result == ["1.2.3.4", "5.6.7.8"]

    def test_sanitize_networks_filters(self):
        result = _sanitize_networks(["10.0.0.0/8", "bad", "192.168.0.0/16"])
        assert result == ["10.0.0.0/8", "192.168.0.0/16"]

    def test_sanitize_ifaces_filters(self):
        result = _sanitize_ifaces(["utun99", "bad iface", "tun0"])
        assert result == ["utun99", "tun0"]

    # ---- IPv6 support (pre-existing regression fix + new helpers) ----

    def test_is_valid_ip_accepts_ipv4_and_ipv6(self):
        """_is_valid_ip принимает IPv4 И IPv6. Фикс критичного бага:
        при IPv6 VPN server адресе _sanitize_ips выкидывал его, killswitch
        блокировал VPN handshake."""
        assert _is_valid_ip("1.2.3.4")
        assert _is_valid_ip("2001:db8::1")
        assert _is_valid_ip("fe80::1")
        assert _is_valid_ip("::1")
        assert _is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        # Не принимает CIDR и мусор
        assert not _is_valid_ip("2001:db8::/32")
        assert not _is_valid_ip("1.2.3.4/32")
        assert not _is_valid_ip("not-an-ip")
        assert not _is_valid_ip("")

    def test_is_valid_ipv4_strict(self):
        assert _is_valid_ipv4("1.2.3.4")
        assert not _is_valid_ipv4("2001:db8::1")
        assert not _is_valid_ipv4("::1")

    def test_is_valid_ipv6_strict(self):
        assert _is_valid_ipv6("2001:db8::1")
        assert _is_valid_ipv6("::1")
        assert _is_valid_ipv6("fe80::1")
        assert not _is_valid_ipv6("1.2.3.4")

    def test_is_valid_network_accepts_ipv4_and_ipv6(self):
        assert _is_valid_network("10.0.0.0/8")
        assert _is_valid_network("2001:db8::/32")
        assert _is_valid_network("fe80::/10")
        assert _is_valid_network("::/0")
        assert not _is_valid_network("not-a-net")

    def test_is_valid_ipv4_network_strict(self):
        assert _is_valid_ipv4_network("10.0.0.0/8")
        assert not _is_valid_ipv4_network("2001:db8::/32")

    def test_is_valid_ipv6_network_strict(self):
        assert _is_valid_ipv6_network("2001:db8::/32")
        assert _is_valid_ipv6_network("::/0")
        assert not _is_valid_ipv6_network("10.0.0.0/8")

    def test_sanitize_ips_accepts_ipv6(self):
        """После фикса IPv6 VPN server IP больше не выкидывается."""
        result = _sanitize_ips(["1.2.3.4", "2001:db8::1", "bad"])
        assert result == ["1.2.3.4", "2001:db8::1"]

    def test_sanitize_networks_accepts_ipv6(self):
        result = _sanitize_networks(["10.0.0.0/8", "2001:db8::/32", "bad"])
        assert result == ["10.0.0.0/8", "2001:db8::/32"]

    def test_split_by_family(self):
        v4, v6 = _split_by_family(["1.2.3.4", "2001:db8::1", "5.6.7.8", "::1"])
        assert v4 == ["1.2.3.4", "5.6.7.8"]
        assert v6 == ["2001:db8::1", "::1"]

    def test_split_by_family_empty(self):
        v4, v6 = _split_by_family([])
        assert v4 == [] and v6 == []

    def test_split_networks_by_family(self):
        v4, v6 = _split_networks_by_family(
            ["10.0.0.0/8", "2001:db8::/32", "192.168.0.0/16", "fe80::/10"]
        )
        assert v4 == ["10.0.0.0/8", "192.168.0.0/16"]
        assert v6 == ["2001:db8::/32", "fe80::/10"]


# =========================================================================
# pf rule generation
# =========================================================================


class TestBuildPfRules:
    def test_basic_rules(self):
        rules = _build_pf_rules(
            vpn_interfaces=["utun99"],
            vpn_server_ips=["1.2.3.4"],
            bypass_ips=["5.6.7.8"],
            bypass_networks=["10.0.0.0/8"],
        )
        # Outbound
        assert "pass quick on lo0 all" in rules
        assert "pass out quick inet proto { tcp, udp } to 1.2.3.4" in rules
        assert "pass out quick inet to 5.6.7.8" in rules
        assert "pass out quick inet to 10.0.0.0/8" in rules
        assert "pass quick on utun99 all" in rules
        assert "block out inet all" in rules
        # Inbound
        assert "pass in quick inet proto { tcp, udp } from 1.2.3.4" in rules
        assert "block in inet all" in rules

    def test_dhcp_allowed(self):
        rules = _build_pf_rules(
            vpn_interfaces=[],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
        )
        assert "port 68 to any port 67" in rules

    def test_localhost_dns_allowed(self):
        rules = _build_pf_rules(
            vpn_interfaces=[],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
        )
        assert "to 127.0.0.1 port 53" in rules

    def test_multiple_interfaces(self):
        rules = _build_pf_rules(
            vpn_interfaces=["utun99", "utun100", "tun0"],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
        )
        assert "pass quick on utun99 all" in rules
        assert "pass quick on utun100 all" in rules
        assert "pass quick on tun0 all" in rules

    def test_empty_lists(self):
        rules = _build_pf_rules(
            vpn_interfaces=[],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
        )
        # Should still have loopback, DHCP, DNS, and block (both directions)
        assert "pass quick on lo0 all" in rules
        assert "block out inet all" in rules
        assert "block in inet all" in rules

    # ---- IPv6 rules (PR#2, only when ipv6_enabled=True) ----

    def test_ipv6_disabled_by_default(self):
        """Backward compat: ipv6_enabled=False (default) - нет inet6 rules."""
        rules = _build_pf_rules(
            vpn_interfaces=["utun99"],
            vpn_server_ips=["1.2.3.4"],
            bypass_ips=[],
            bypass_networks=[],
        )
        assert "inet6" not in rules
        assert "block out inet6" not in rules

    def test_ipv6_enabled_adds_block(self):
        rules = _build_pf_rules(
            vpn_interfaces=["utun99"],
            vpn_server_ips=["1.2.3.4"],
            bypass_ips=[],
            bypass_networks=[],
            ipv6_enabled=True,
        )
        assert "block out inet6 all" in rules
        assert "block in inet6 all" in rules

    def test_ipv6_enabled_allow_server(self):
        rules = _build_pf_rules(
            vpn_interfaces=["utun99"],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
            ipv6_enabled=True,
            vpn_server_ips6=["2001:db8::1"],
        )
        assert "pass out quick inet6 proto { tcp, udp } to 2001:db8::1" in rules
        assert "pass in quick inet6 proto { tcp, udp } from 2001:db8::1" in rules

    def test_ipv6_enabled_allow_bypass_net(self):
        rules = _build_pf_rules(
            vpn_interfaces=[],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
            ipv6_enabled=True,
            bypass_networks6=["2001:db8::/32"],
        )
        assert "pass out quick inet6 to 2001:db8::/32" in rules

    def test_ipv6_dhcpv6_and_loopback_dns(self):
        rules = _build_pf_rules(
            vpn_interfaces=[],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
            ipv6_enabled=True,
        )
        # DHCPv6 ports 546/547
        assert "port 546 to any port 547" in rules
        assert "port 547 to any port 546" in rules
        # IPv6 loopback DNS
        assert "to ::1 port 53" in rules


# =========================================================================
# Darwin (pf) kill switch
# =========================================================================


class TestDarwinKillSwitch:
    @patch("tv.killswitch._run")
    def test_enable_loads_rules(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = DarwinKillSwitch()

        # Mock reading /etc/pf.conf
        pf_content = "# Default pf.conf\n"
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.read = MagicMock(return_value=pf_content)
            mock_open.return_value.readlines = MagicMock(return_value=[pf_content])

            ok = ks.enable(
                vpn_interfaces=["utun99"],
                vpn_server_ips=["1.2.3.4"],
                bypass_ips=[],
                bypass_networks=[],
            )

        assert ok
        assert ks.active
        # Check pfctl was called with anchor load
        pfctl_calls = [
            c
            for c in mock_run.call_args_list
            if any("pfctl" in str(a) for a in c.args[0])
        ]
        assert len(pfctl_calls) >= 1

    @patch("tv.killswitch._run")
    def test_enable_ipv6_kwarg_passes_through(self, mock_run):
        """ipv6_enabled=True раздельные inet/inet6 rules в pfctl ruleset."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = DarwinKillSwitch()

        pf_content = "# Default pf.conf\n"
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.read = MagicMock(return_value=pf_content)
            mock_open.return_value.readlines = MagicMock(return_value=[pf_content])

            ok = ks.enable(
                vpn_interfaces=["utun99"],
                vpn_server_ips=["1.2.3.4", "2001:db8::1"],
                bypass_ips=[],
                bypass_networks=["10.0.0.0/8", "2001:db8::/32"],
                ipv6_enabled=True,
            )
        assert ok
        # Проверим что pfctl -f stdin получил и inet и inet6 rules
        stdin_input = None
        for c in mock_run.call_args_list:
            if c.kwargs.get("input") and "pfctl" in str(c.args[0]):
                stdin_input = c.kwargs["input"]
                break
        assert stdin_input is not None
        assert "to 1.2.3.4" in stdin_input  # IPv4 server
        assert "to 2001:db8::1" in stdin_input  # IPv6 server
        assert "block out inet6 all" in stdin_input

    @patch("tv.killswitch._run")
    def test_enable_ipv6_default_false(self, mock_run):
        """Default ipv6_enabled=False - нет IPv6 rules (backward compat)."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = DarwinKillSwitch()
        pf_content = "# Default pf.conf\n"
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.read = MagicMock(return_value=pf_content)
            mock_open.return_value.readlines = MagicMock(return_value=[pf_content])

            ks.enable(
                vpn_interfaces=["utun99"],
                vpn_server_ips=["1.2.3.4"],
                bypass_ips=[],
                bypass_networks=[],
            )
        stdin_input = next(
            c.kwargs["input"]
            for c in mock_run.call_args_list
            if c.kwargs.get("input") and "pfctl" in str(c.args[0])
        )
        assert "inet6" not in stdin_input

    @patch("tv.killswitch._run")
    def test_disable_flushes_anchor(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = DarwinKillSwitch()
        ks._active = True

        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            mock_open.return_value.readlines = MagicMock(return_value=[])

            ok = ks.disable()

        assert ok
        assert not ks.active
        # Should flush the anchor
        flush_calls = [
            c
            for c in mock_run.call_args_list
            if "-F" in c.args[0] and _PF_ANCHOR in c.args[0]
        ]
        assert len(flush_calls) == 1


# =========================================================================
# Linux (iptables) kill switch
# =========================================================================


class TestLinuxKillSwitch:
    @patch("tv.killswitch._run")
    def test_enable_creates_chain(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()

        ok = ks.enable(
            vpn_interfaces=["tun0"],
            vpn_server_ips=["1.2.3.4"],
            bypass_ips=["5.6.7.8"],
            bypass_networks=["10.0.0.0/8"],
        )

        assert ok
        assert ks.active

        # Verify both chains created (OUTPUT + INPUT)
        chain_calls = [
            c
            for c in mock_run.call_args_list
            if "-N" in c.args[0]
            and (_IPTABLES_CHAIN in c.args[0] or _IPTABLES_CHAIN_IN in c.args[0])
        ]
        assert len(chain_calls) == 2

        # Verify OUTPUT and INPUT jumps
        jump_calls = [
            c
            for c in mock_run.call_args_list
            if "-I" in c.args[0] and ("OUTPUT" in c.args[0] or "INPUT" in c.args[0])
        ]
        assert len(jump_calls) == 2

        # Verify DROP rules (one per chain)
        drop_calls = [
            c
            for c in mock_run.call_args_list
            if "-j" in c.args[0] and "DROP" in c.args[0]
        ]
        assert len(drop_calls) == 2

    @patch("tv.killswitch._run")
    def test_enable_allows_loopback(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()

        ks.enable(
            vpn_interfaces=[],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
        )

        lo_calls = [
            c
            for c in mock_run.call_args_list
            if "-o" in c.args[0] and "lo" in c.args[0]
        ]
        assert len(lo_calls) >= 1

    @patch("tv.killswitch.shutil.which", return_value=None)
    @patch("tv.killswitch._run")
    def test_disable_removes_chain(self, mock_run, mock_which):
        """Без ip6tables (which=None): только IPv4 chain cleanup.

        С ip6tables (реальная Linux) также чистится ip6tables - это покрыто
        test_disable_also_cleans_ip6tables_if_available."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()
        ks._active = True

        ok = ks.disable()

        assert ok
        assert not ks.active

        # Только IPv4 iptables -X вызовы (ip6tables skipped т.к. which=None)
        delete_calls = [
            c
            for c in mock_run.call_args_list
            if c.args[0][:2] == ["sudo", "iptables"]
            and "-X" in c.args[0]
            and (_IPTABLES_CHAIN in c.args[0] or _IPTABLES_CHAIN_IN in c.args[0])
        ]
        assert len(delete_calls) == 2

    @patch("tv.killswitch.shutil.which", return_value="/usr/sbin/ip6tables")
    @patch("tv.killswitch._run")
    def test_disable_also_cleans_ip6tables_if_available(self, mock_run, mock_which):
        """disable() всегда чистит ip6tables если утилита доступна - избегаем
        dangling rules если раньше был enable(ipv6_enabled=True)."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()
        ks._active = True
        ks.disable()
        ip6_x = [
            c
            for c in mock_run.call_args_list
            if c.args[0][:2] == ["sudo", "ip6tables"] and "-X" in c.args[0]
        ]
        assert len(ip6_x) == 2

    @patch("tv.killswitch.shutil.which", return_value="/usr/sbin/ip6tables")
    @patch("tv.killswitch._run")
    def test_enable_ipv6_creates_ip6tables_chain(self, mock_run, mock_which):
        """ipv6_enabled=True + ip6tables доступен -> ip6tables chains."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()

        ok = ks.enable(
            vpn_interfaces=["tun0"],
            vpn_server_ips=["1.2.3.4", "2001:db8::1"],
            bypass_ips=[],
            bypass_networks=[],
            ipv6_enabled=True,
        )
        assert ok

        # Проверим что ip6tables -N (создание chain) вызван
        ip6_create = [
            c
            for c in mock_run.call_args_list
            if "ip6tables" in c.args[0] and "-N" in c.args[0]
        ]
        assert len(ip6_create) == 2  # OUTPUT + INPUT chains

        # Проверим что IPv6 server IP попал в ip6tables allow
        ip6_server = [
            c
            for c in mock_run.call_args_list
            if "ip6tables" in c.args[0]
            and "2001:db8::1" in c.args[0]
            and "ACCEPT" in c.args[0]
        ]
        assert len(ip6_server) >= 1

        # IPv4 server НЕ должен попадать в ip6tables
        ip6_v4 = [
            c
            for c in mock_run.call_args_list
            if "ip6tables" in c.args[0] and "1.2.3.4" in c.args[0]
        ]
        assert len(ip6_v4) == 0

    @patch("tv.killswitch.ui")
    @patch("tv.killswitch.shutil.which", return_value=None)
    @patch("tv.killswitch._run")
    def test_enable_ipv6_missing_ip6tables_warns(self, mock_run, mock_which, mock_ui):
        """M6: ip6tables отсутствует + ipv6_enabled=True -> visible ui.warn."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()

        ok = ks.enable(
            vpn_interfaces=["tun0"],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
            ipv6_enabled=True,
        )
        assert ok  # IPv4 killswitch всё равно работает
        # ui.warn вызван с сообщением про ip6tables
        assert mock_ui.warn.called
        warn_arg = mock_ui.warn.call_args[0][0]
        assert "ip6tables missing" in warn_arg

    @patch("tv.killswitch.shutil.which", return_value=None)
    @patch("tv.killswitch._run")
    def test_enable_ipv6_false_no_ip6tables_calls(self, mock_run, mock_which):
        """ipv6_enabled=False (default) - нет ip6tables calls даже если which вернёт что-то."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()
        ks.enable(
            vpn_interfaces=["tun0"],
            vpn_server_ips=["1.2.3.4"],
            bypass_ips=[],
            bypass_networks=[],
        )
        ip6_calls = [c for c in mock_run.call_args_list if "ip6tables" in c.args[0]]
        # Может быть только disable() flush - но в enable flow никаких ip6tables
        # (mock_which return_value=None, не dostapan)
        assert len(ip6_calls) == 0

    @patch("tv.killswitch._run")
    def test_enable_cleans_previous_first(self, mock_run):
        """Enable should flush any existing chain before creating new one."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()

        ks.enable(
            vpn_interfaces=["tun0"],
            vpn_server_ips=[],
            bypass_ips=[],
            bypass_networks=[],
        )

        # Flush should come before create
        all_args = [c.args[0] for c in mock_run.call_args_list]
        flush_idx = next(
            i for i, a in enumerate(all_args) if "-F" in a and _IPTABLES_CHAIN in a
        )
        create_idx = next(
            i for i, a in enumerate(all_args) if "-N" in a and _IPTABLES_CHAIN in a
        )
        assert flush_idx < create_idx


# =========================================================================
# Windows (netsh) kill switch
# =========================================================================


class TestWindowsKillSwitch:
    @patch("tv.killswitch._run")
    def test_enable_creates_rules(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = WindowsKillSwitch()

        ok = ks.enable(
            vpn_interfaces=[],
            vpn_server_ips=["1.2.3.4"],
            bypass_ips=[],
            bypass_networks=[],
        )

        assert ok
        assert ks.active

        # Verify block rules (outbound + inbound)
        block_calls = [
            c
            for c in mock_run.call_args_list
            if "Block" in str(c.args[0])
            and "add" in c.args[0]
            and _WIN_RULE_PREFIX in str(c.args[0])
        ]
        assert len(block_calls) == 2  # BlockAll (out) + BlockAllIn (in)

    @patch("tv.killswitch._run")
    def test_disable_removes_rules(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = WindowsKillSwitch()
        ks._active = True

        ok = ks.disable()

        assert ok
        assert not ks.active

        # Verify delete calls for all rule types
        delete_calls = [c for c in mock_run.call_args_list if "delete" in c.args[0]]
        assert len(delete_calls) >= 2  # BlockAll + at least AllowLoopback

    @patch("tv.killswitch._run")
    def test_enable_loopback6_always_allowed(self, mock_run):
        """M9: ::1/128 всегда разрешён независимо от ipv6_enabled."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = WindowsKillSwitch()
        ks.enable(
            vpn_interfaces=[],
            vpn_server_ips=["1.2.3.4"],
            bypass_ips=[],
            bypass_networks=[],
            ipv6_enabled=False,
        )
        loopback6 = [
            c for c in mock_run.call_args_list if "remoteip=::1/128" in c.args[0]
        ]
        assert len(loopback6) == 2  # out + in

    @patch("tv.killswitch._run")
    def test_enable_ipv6_vpn_server(self, mock_run):
        """ipv6_enabled=True + IPv6 VPN server -> AllowVPNServers6 rule."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = WindowsKillSwitch()
        ks.enable(
            vpn_interfaces=[],
            vpn_server_ips=["1.2.3.4", "2001:db8::1"],
            bypass_ips=[],
            bypass_networks=[],
            ipv6_enabled=True,
        )
        v6_rules = [
            c for c in mock_run.call_args_list if "remoteip=2001:db8::1" in c.args[0]
        ]
        assert len(v6_rules) >= 1
        # IPv4 server отдельно
        v4_rules = [
            c for c in mock_run.call_args_list if "remoteip=1.2.3.4" in c.args[0]
        ]
        assert len(v4_rules) >= 1

    @patch("tv.killswitch._run")
    def test_enable_ipv6_disabled_no_vpn6_rules(self, mock_run):
        """ipv6_enabled=False - нет ADD AllowVPNServers6 (delete допустим для idempotent cleanup)."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = WindowsKillSwitch()
        ks.enable(
            vpn_interfaces=[],
            vpn_server_ips=["1.2.3.4", "2001:db8::1"],
            bypass_ips=[],
            bypass_networks=[],
            ipv6_enabled=False,
        )
        # Фильтруем только add rule (не delete - тот часть idempotent cleanup)
        v6_server_add = [
            c
            for c in mock_run.call_args_list
            if "AllowVPNServers6" in str(c.args[0]) and "add" in c.args[0]
        ]
        assert len(v6_server_add) == 0

    @patch("tv.killswitch._run")
    def test_disable_removes_ipv6_rules(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = WindowsKillSwitch()
        ks._active = True
        ks.disable()
        # Проверим что IPv6 suffix-правила перечислены в delete
        all_delete_names = [
            str(c.args[0]) for c in mock_run.call_args_list if "delete" in c.args[0]
        ]
        joined = " ".join(all_delete_names)
        assert "AllowLoopback6" in joined
        assert "AllowVPNServers6" in joined


# =========================================================================
# Factory
# =========================================================================


class TestBackwardCompat:
    """AC8 invariant: все существующие вызовы enable() БЕЗ ipv6_enabled
    работают идентично pre-PR. ipv6_enabled default False - нет IPv6 rules."""

    @patch("tv.killswitch._run")
    def test_linux_enable_no_ipv6_kwarg_works(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()
        ok = ks.enable(
            vpn_interfaces=["tun0"],
            vpn_server_ips=["1.2.3.4"],
            bypass_ips=[],
            bypass_networks=[],
        )
        assert ok
        # Нет ip6tables calls
        ip6_calls = [c for c in mock_run.call_args_list if "ip6tables" in c.args[0]]
        assert len(ip6_calls) == 0

    @patch("tv.killswitch._run")
    def test_windows_enable_no_ipv6_kwarg_works(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = WindowsKillSwitch()
        ok = ks.enable(
            vpn_interfaces=[],
            vpn_server_ips=["1.2.3.4"],
            bypass_ips=[],
            bypass_networks=[],
        )
        assert ok
        # Только ADD AllowVPNServers6 не должно быть (delete - idempotent cleanup)
        v6_server_add = [
            c
            for c in mock_run.call_args_list
            if "AllowVPNServers6" in str(c.args[0]) and "add" in c.args[0]
        ]
        assert len(v6_server_add) == 0


class TestFactory:
    @patch("tv.killswitch.platform.system", return_value="Darwin")
    def test_darwin(self, _):
        ks = create()
        assert isinstance(ks, DarwinKillSwitch)

    @patch("tv.killswitch.platform.system", return_value="Linux")
    def test_linux(self, _):
        ks = create()
        assert isinstance(ks, LinuxKillSwitch)

    @patch("tv.killswitch.platform.system", return_value="Windows")
    def test_windows(self, _):
        ks = create()
        assert isinstance(ks, WindowsKillSwitch)


# =========================================================================
# Engine integration
# =========================================================================


class TestEngineIntegration:
    """Test kill switch integration with Engine lifecycle."""

    def test_setup_enables_kill_switch_when_configured(self, tmp_dir, mock_net, logger):
        """Engine.setup() should enable kill switch if [global].kill_switch = true."""
        defs = {
            "global": {
                "kill_switch": True,
                "vpn_server_routes": {"hosts": ["1.2.3.4"]},
            },
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                },
            },
        }
        _write_toml(tmp_dir, defs)

        from tv.engine import Engine

        engine = Engine(tmp_dir, defs, net=mock_net, log=logger)
        engine.prepare()

        with patch.object(
            engine._killswitch, "enable", return_value=True
        ) as mock_enable:
            with patch("tv.engine.time.sleep"):
                engine.setup()

            mock_enable.assert_called_once()
            args = mock_enable.call_args
            assert "utun99" in args.kwargs["vpn_interfaces"]
            assert "1.2.3.4" in args.kwargs["vpn_server_ips"]

    def test_setup_skips_kill_switch_when_not_configured(
        self, tmp_dir, mock_net, logger
    ):
        """Engine.setup() should NOT enable kill switch if not in config."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                },
            },
        }
        _write_toml(tmp_dir, defs)

        from tv.engine import Engine

        engine = Engine(tmp_dir, defs, net=mock_net, log=logger)
        engine.prepare()

        with patch.object(engine._killswitch, "enable") as mock_enable:
            with patch("tv.engine.time.sleep"):
                engine.setup()

            mock_enable.assert_not_called()

    def test_disconnect_disables_kill_switch(self, tmp_dir, mock_net, logger):
        """Engine.disconnect_all() should disable kill switch."""
        defs = {
            "global": {"kill_switch": True},
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                },
            },
        }
        _write_toml(tmp_dir, defs)

        from tv.engine import Engine

        engine = Engine(tmp_dir, defs, net=mock_net, log=logger)
        engine.prepare()

        # Simulate active kill switch
        engine._killswitch._active = True

        with patch.object(engine._killswitch, "disable") as mock_disable:
            engine.disconnect_all()
            mock_disable.assert_called_once()

    def test_disconnect_skips_when_not_active(self, tmp_dir, mock_net, logger):
        """disconnect_all() should not call disable if kill switch was never enabled."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                },
            },
        }
        _write_toml(tmp_dir, defs)

        from tv.engine import Engine

        engine = Engine(tmp_dir, defs, net=mock_net, log=logger)
        engine.prepare()

        with patch.object(engine._killswitch, "disable") as mock_disable:
            engine.disconnect_all()
            mock_disable.assert_not_called()


# =========================================================================
# Config parsing
# =========================================================================


class TestConfigParsing:
    def test_get_kill_switch_enabled_true(self):
        from tv.disconnect import get_kill_switch_enabled

        defs = {"global": {"kill_switch": True}}
        assert get_kill_switch_enabled(defs) is True

    def test_get_kill_switch_enabled_false(self):
        from tv.disconnect import get_kill_switch_enabled

        defs = {"global": {"kill_switch": False}}
        assert get_kill_switch_enabled(defs) is False

    def test_get_kill_switch_missing(self):
        from tv.disconnect import get_kill_switch_enabled

        assert get_kill_switch_enabled({}) is False
        assert get_kill_switch_enabled({"global": {}}) is False


# =========================================================================
# Helpers
# =========================================================================


def _write_toml(tmp_dir, defs):
    """Write minimal config.toml for engine tests."""
    import tomlkit

    doc = tomlkit.document()
    if "tunnels" in defs:
        t_section = tomlkit.table(is_super_table=True)
        for name, tdata in defs["tunnels"].items():
            t_table = tomlkit.table()
            for k, v in tdata.items():
                if isinstance(v, dict):
                    sub = tomlkit.table()
                    for sk, sv in v.items():
                        sub[sk] = sv
                    t_table[k] = sub
                else:
                    t_table[k] = v
            t_section[name] = t_table
        doc["tunnels"] = t_section
    (tmp_dir / "config.toml").write_text(tomlkit.dumps(doc))
