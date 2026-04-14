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
    _is_valid_network,
    _is_valid_iface,
    _sanitize_ips,
    _sanitize_networks,
    _sanitize_ifaces,
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

    @patch("tv.killswitch._run")
    def test_disable_removes_chain(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        ks = LinuxKillSwitch()
        ks._active = True

        ok = ks.disable()

        assert ok
        assert not ks.active

        # Verify both chains deleted
        delete_calls = [
            c
            for c in mock_run.call_args_list
            if "-X" in c.args[0]
            and (_IPTABLES_CHAIN in c.args[0] or _IPTABLES_CHAIN_IN in c.args[0])
        ]
        assert len(delete_calls) == 2

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


# =========================================================================
# Factory
# =========================================================================


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
