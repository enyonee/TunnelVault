"""Tests for tv.defaults: TOML config loader and tunnel parsing."""

from __future__ import annotations


import pytest

from unittest.mock import patch

from tv.defaults import (
    load,
    parse_tunnels,
    validate_config_files,
    _migrate_fortivpn_to_openconnect,
)
from tv.vpn.base import TunnelConfig


# =========================================================================
# Positive: loading config.toml
# =========================================================================


class TestLoadDefaults:
    def test_loads_valid_toml(self, tmp_path):
        """Loads valid config.toml with [tunnels.*] section."""
        toml = tmp_path / "config.toml"
        toml.write_text(
            "[tunnels.openvpn]\n"
            'type = "openvpn"\n'
            "order = 1\n"
            'config_file = "client.ovpn"\n'
        )
        data = load(tmp_path)
        assert data["tunnels"]["openvpn"]["type"] == "openvpn"
        assert data["tunnels"]["openvpn"]["config_file"] == "client.ovpn"

    def test_loads_with_global_section(self, tmp_path):
        """Loads tunnels + global section."""
        toml = tmp_path / "config.toml"
        toml.write_text(
            "[tunnels.openvpn]\n"
            'type = "openvpn"\n'
            "\n"
            "[global.vpn_server_routes]\n"
            'hosts = ["1.2.3.4"]\n'
            'resolve = ["vpn.test.com"]\n'
        )
        data = load(tmp_path)
        assert data["tunnels"]["openvpn"]["type"] == "openvpn"
        assert data["global"]["vpn_server_routes"]["hosts"] == ["1.2.3.4"]

    def test_preserves_arrays_of_tables(self, tmp_path):
        """Inline table arrays are parsed."""
        toml = tmp_path / "config.toml"
        toml.write_text(
            "[tunnels.vpn1]\n"
            'type = "fortivpn"\n'
            "\n"
            "[tunnels.vpn1.checks]\n"
            'ports = [{host = "1.2.3.4", port = 80}]\n'
        )
        data = load(tmp_path)
        assert data["tunnels"]["vpn1"]["checks"]["ports"][0]["host"] == "1.2.3.4"
        assert data["tunnels"]["vpn1"]["checks"]["ports"][0]["port"] == 80


# =========================================================================
# Negative / inverse: load failures
# =========================================================================


class TestLoadDefaultsInverse:
    def test_missing_file_exits(self, tmp_path):
        """No config.toml -> sys.exit(1)."""
        with pytest.raises(SystemExit):
            load(tmp_path)

    def test_invalid_toml_exits(self, tmp_path):
        """Invalid TOML -> sys.exit(1)."""
        toml = tmp_path / "config.toml"
        toml.write_text("this is not [valid toml !!!!")
        with pytest.raises(SystemExit):
            load(tmp_path)

    def test_missing_tunnels_section_exits(self, tmp_path):
        """No [tunnels] section -> sys.exit(1)."""
        toml = tmp_path / "config.toml"
        toml.write_text('[global]\nsome_key = "value"\n')
        with pytest.raises(SystemExit):
            load(tmp_path)

    def test_empty_toml_exits(self, tmp_path):
        """Empty file -> no tunnels section -> sys.exit(1)."""
        toml = tmp_path / "config.toml"
        toml.write_text("")
        with pytest.raises(SystemExit):
            load(tmp_path)


# =========================================================================
# --setup: load with setup=True
# =========================================================================


class TestLoadSetup:
    def test_setup_copies_example_when_missing(self, tmp_path):
        """setup=True + no config.toml + example exists -> copies example."""
        example = tmp_path / "config.toml.example"
        example.write_text(
            '[tunnels.openvpn]\ntype = "openvpn"\nconfig_file = "client.ovpn"\n'
        )
        data = load(tmp_path, setup=True)
        assert (tmp_path / "config.toml").exists()
        assert data["tunnels"]["openvpn"]["type"] == "openvpn"

    def test_setup_exits_when_no_example(self, tmp_path):
        """setup=True + no config.toml + no example -> sys.exit(1)."""
        with pytest.raises(SystemExit):
            load(tmp_path, setup=True)

    def test_setup_loads_existing_file(self, tmp_path):
        """setup=True + config.toml exists -> loads normally."""
        toml = tmp_path / "config.toml"
        toml.write_text('[tunnels.openvpn]\ntype = "openvpn"\n')
        data = load(tmp_path, setup=True)
        assert data["tunnels"]["openvpn"]["type"] == "openvpn"

    def test_no_setup_still_exits_on_missing(self, tmp_path):
        """setup=False + no config.toml -> sys.exit(1) (unchanged behavior)."""
        (tmp_path / "config.toml.example").write_text('[tunnels.x]\ntype="openvpn"\n')
        with pytest.raises(SystemExit):
            load(tmp_path, setup=False)


# =========================================================================
# parse_tunnels: auto-log and validation
# =========================================================================


class TestParseTunnelsAutoLog:
    def test_auto_log_path_generated(self):
        """Tunnel without explicit log gets logs/{type}-{name}.log."""
        defs = {"tunnels": {"vpn1": {"type": "openvpn", "order": 1}}}
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 1
        assert tunnels[0].log == "logs/openvpn-vpn1.log"

    def test_explicit_log_preserved(self):
        """Tunnel with explicit log keeps it."""
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "order": 1,
                    "log": "/var/log/my.log",
                }
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].log == "/var/log/my.log"

    def test_two_tunnels_get_unique_logs(self):
        """Two same-type tunnels get different auto-generated log paths."""
        defs = {
            "tunnels": {
                "vpn1": {"type": "openvpn", "order": 1},
                "home": {"type": "openvpn", "order": 2},
            }
        }
        tunnels = parse_tunnels(defs)
        logs = [t.log for t in tunnels]
        assert len(set(logs)) == 2
        assert "logs/openvpn-vpn1.log" in logs
        assert "logs/openvpn-home.log" in logs

    def test_disabled_tunnels_excluded(self):
        """Disabled tunnels are filtered out."""
        defs = {
            "tunnels": {
                "active": {"type": "openvpn", "order": 1},
                "inactive": {"type": "openvpn", "order": 2, "enabled": False},
            }
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 1
        assert tunnels[0].name == "active"

    def test_extra_fields_collected(self):
        """Unknown fields go into tc.extra (deepcopied)."""
        defs = {
            "tunnels": {
                "gw": {
                    "type": "openvpn",
                    "order": 1,
                    "custom_gateway": "10.0.0.1",
                    "custom_flag": True,
                }
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].extra == {"custom_gateway": "10.0.0.1", "custom_flag": True}


class TestParseTunnelsValidation:
    def test_duplicate_interface_rejected(self):
        """Two tunnels with same interface -> ValueError."""
        defs = {
            "tunnels": {
                "a": {"type": "fortivpn", "order": 1, "interface": "ppp0"},
                "b": {"type": "fortivpn", "order": 2, "interface": "ppp0"},
            }
        }
        with pytest.raises(ValueError, match="same interface"):
            parse_tunnels(defs)

    def test_duplicate_log_rejected(self):
        """Two tunnels with same log path -> ValueError."""
        defs = {
            "tunnels": {
                "a": {"type": "fortivpn", "order": 1, "log": "/tmp/shared.log"},
                "b": {"type": "openvpn", "order": 2, "log": "/tmp/shared.log"},
            }
        }
        with pytest.raises(ValueError, match="same log"):
            parse_tunnels(defs)

    def test_different_interfaces_ok(self):
        """Two tunnels with different interfaces pass validation."""
        defs = {
            "tunnels": {
                "a": {"type": "fortivpn", "order": 1, "interface": "ppp0"},
                "b": {"type": "fortivpn", "order": 2, "interface": "ppp1"},
            }
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 2

    def test_no_interface_no_conflict(self):
        """Tunnels without explicit interface don't conflict."""
        defs = {
            "tunnels": {
                "a": {"type": "fortivpn", "order": 1},
                "b": {"type": "fortivpn", "order": 2},
            }
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 2


# =========================================================================
# Multi-instance: config_file defaults
# =========================================================================


class TestConfigFileDefaults:
    def test_single_openvpn_backward_compat(self):
        """One openvpn without config_file -> client.ovpn."""
        defs = {"tunnels": {"vpn": {"type": "openvpn", "order": 1}}}
        tunnels = parse_tunnels(defs)
        assert tunnels[0].config_file == "client.ovpn"

    def test_single_singbox_backward_compat(self):
        """One singbox without config_file -> singbox.json."""
        defs = {"tunnels": {"sb": {"type": "singbox", "order": 1}}}
        tunnels = parse_tunnels(defs)
        assert tunnels[0].config_file == "singbox.json"

    def test_explicit_config_preserved(self):
        """Explicit config_file not overwritten by default."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "custom.json",
                }
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].config_file == "custom.json"

    def test_fortivpn_no_default_config(self):
        """FortiVPN has no config_file default (uses temp config)."""
        defs = {"tunnels": {"f": {"type": "fortivpn", "order": 1}}}
        tunnels = parse_tunnels(defs)
        assert tunnels[0].config_file == ""

    def test_two_openvpn_same_config_rejected(self):
        """Two openvpn without config_file -> both get client.ovpn -> ValueError."""
        defs = {
            "tunnels": {
                "a": {"type": "openvpn", "order": 1},
                "b": {"type": "openvpn", "order": 2},
            }
        }
        tunnels = parse_tunnels(defs)
        with pytest.raises(ValueError, match="same config_file"):
            validate_config_files(tunnels)

    def test_two_singbox_same_config_rejected(self):
        """Two singbox without config_file -> both get singbox.json -> ValueError."""
        defs = {
            "tunnels": {
                "a": {"type": "singbox", "order": 1},
                "b": {"type": "singbox", "order": 2},
            }
        }
        tunnels = parse_tunnels(defs)
        with pytest.raises(ValueError, match="same config_file"):
            validate_config_files(tunnels)

    def test_two_singbox_different_configs_ok(self):
        """Two singbox with different config_file -> ok."""
        defs = {
            "tunnels": {
                "a": {"type": "singbox", "order": 1, "config_file": "sb1.json"},
                "b": {"type": "singbox", "order": 2, "config_file": "sb2.json"},
            }
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 2
        assert tunnels[0].config_file == "sb1.json"
        assert tunnels[1].config_file == "sb2.json"

    def test_cross_type_same_config_ok(self):
        """singbox + openvpn with same filename -> ok (different processes)."""
        defs = {
            "tunnels": {
                "a": {"type": "singbox", "order": 1, "config_file": "shared.conf"},
                "b": {"type": "openvpn", "order": 2, "config_file": "shared.conf"},
            }
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 2


# =========================================================================
# Multi-instance: singbox interface auto-assignment
# =========================================================================


class TestSingboxInterfaceAssignment:
    def test_single_singbox_gets_utun99(self):
        """One singbox without interface -> utun99 (backward compat)."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "sb.json",
                }
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].interface == "utun99"

    def test_two_singbox_get_unique_interfaces(self):
        """Two singbox without interface -> utun99, utun100."""
        defs = {
            "tunnels": {
                "a": {"type": "singbox", "order": 1, "config_file": "a.json"},
                "b": {"type": "singbox", "order": 2, "config_file": "b.json"},
            }
        }
        tunnels = parse_tunnels(defs)
        ifaces = [t.interface for t in tunnels]
        assert ifaces == ["utun99", "utun100"]

    def test_three_singbox_sequential(self):
        """Three singbox -> utun99, utun100, utun101."""
        defs = {
            "tunnels": {
                "a": {"type": "singbox", "order": 1, "config_file": "a.json"},
                "b": {"type": "singbox", "order": 2, "config_file": "b.json"},
                "c": {"type": "singbox", "order": 3, "config_file": "c.json"},
            }
        }
        tunnels = parse_tunnels(defs)
        ifaces = [t.interface for t in tunnels]
        assert ifaces == ["utun99", "utun100", "utun101"]

    def test_explicit_plus_auto_no_collision(self):
        """Explicit utun99 + auto -> auto skips to utun100."""
        defs = {
            "tunnels": {
                "a": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "a.json",
                    "interface": "utun99",
                },
                "b": {"type": "singbox", "order": 2, "config_file": "b.json"},
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].interface == "utun99"
        assert tunnels[1].interface == "utun100"

    def test_explicit_interface_preserved(self):
        """Explicit interface is never overwritten."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "sb.json",
                    "interface": "utun42",
                }
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].interface == "utun42"

    def test_non_singbox_not_assigned(self):
        """FortiVPN/OpenVPN don't get auto-assigned interface."""
        defs = {
            "tunnels": {
                "f": {"type": "fortivpn", "order": 1},
                "o": {"type": "openvpn", "order": 2},
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].interface == ""
        assert tunnels[1].interface == ""

    def test_mixed_types_singbox_only_gets_iface(self):
        """Mixed tunnels: only singbox gets auto-assigned interface."""
        defs = {
            "tunnels": {
                "f": {"type": "fortivpn", "order": 1},
                "s": {"type": "singbox", "order": 2, "config_file": "sb.json"},
                "o": {"type": "openvpn", "order": 3},
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].interface == ""  # fortivpn
        assert tunnels[1].interface == "utun99"  # singbox
        assert tunnels[2].interface == ""  # openvpn

    def test_custom_base_interface(self):
        """Custom singbox_interface in [app.defaults] used as base."""
        from tv.app_config import cfg

        cfg.defaults.singbox_interface = "tun0"
        defs = {
            "tunnels": {
                "a": {"type": "singbox", "order": 1, "config_file": "a.json"},
                "b": {"type": "singbox", "order": 2, "config_file": "b.json"},
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].interface == "tun0"
        assert tunnels[1].interface == "tun1"

    def test_cross_type_interface_collision_avoided(self):
        """Explicit non-singbox interface 'utun99' -> singbox auto skips to utun100."""
        defs = {
            "tunnels": {
                "f": {"type": "fortivpn", "order": 1, "interface": "utun99"},
                "s": {"type": "singbox", "order": 2, "config_file": "sb.json"},
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].interface == "utun99"  # fortivpn explicit
        assert tunnels[1].interface == "utun100"  # singbox auto, skipped utun99


# =========================================================================
# Multi-instance: xray interface auto-assignment
# =========================================================================


class TestXrayInterfaceAssignment:
    def test_single_xray_gets_utun98(self):
        """Один xray без interface -> utun98 (своя база, не пересекается с singbox)."""
        defs = {
            "tunnels": {
                "x": {
                    "type": "xray",
                    "order": 1,
                    "config_file": "xray.json",
                }
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].interface == "utun98"

    def test_xray_and_singbox_coexist_on_defaults(self):
        """xray и singbox вместе: каждый на своей базе (utun98 / utun99)."""
        defs = {
            "tunnels": {
                "x": {"type": "xray", "order": 1, "config_file": "xray.json"},
                "s": {"type": "singbox", "order": 2, "config_file": "sb.json"},
            }
        }
        tunnels = parse_tunnels(defs)
        ifaces = {t.name: t.interface for t in tunnels}
        assert ifaces["x"] == "utun98"
        assert ifaces["s"] == "utun99"

    def test_xray_proxy_mode_skipped(self):
        """xray c mode=proxy не получает interface (proxy-inbound без TUN)."""
        defs = {
            "tunnels": {
                "x": {
                    "type": "xray",
                    "order": 1,
                    "config_file": "xray.json",
                    "mode": "proxy",
                }
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0].interface == ""


# =========================================================================
# _auto_config_file tracking on TunnelConfig
# =========================================================================


class TestConfigFileAutoApplied:
    def test_auto_applied_tracked(self):
        """Tunnels without explicit config_file get _auto_config_file=True."""
        defs = {"tunnels": {"sb": {"type": "singbox", "order": 1}}}
        tunnels = parse_tunnels(defs)
        assert tunnels[0]._auto_config_file is True

    def test_explicit_not_tracked(self):
        """Tunnels with explicit config_file have _auto_config_file=False."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "custom.json",
                }
            }
        }
        tunnels = parse_tunnels(defs)
        assert tunnels[0]._auto_config_file is False

    def test_fortivpn_not_tracked(self):
        """FortiVPN has no default config_file, _auto_config_file=False."""
        defs = {"tunnels": {"f": {"type": "fortivpn", "order": 1}}}
        tunnels = parse_tunnels(defs)
        assert tunnels[0]._auto_config_file is False

    def test_independent_between_calls(self):
        """Each parse_tunnels call returns fresh TunnelConfig instances."""
        defs1 = {"tunnels": {"sb": {"type": "singbox", "order": 1}}}
        t1 = parse_tunnels(defs1)
        assert t1[0]._auto_config_file is True

        defs2 = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "x.json",
                }
            }
        }
        t2 = parse_tunnels(defs2)
        assert t2[0]._auto_config_file is False


# =========================================================================
# validate_config_files: deferred validation
# =========================================================================


class TestValidateConfigFiles:
    def test_unique_configs_pass(self):
        """Different config_files within same type pass validation."""
        tunnels = [
            TunnelConfig(name="a", type="singbox", config_file="a.json"),
            TunnelConfig(name="b", type="singbox", config_file="b.json"),
        ]
        validate_config_files(tunnels)  # no error

    def test_duplicate_configs_rejected(self):
        """Same config_file within same type raises ValueError."""
        tunnels = [
            TunnelConfig(name="a", type="singbox", config_file="sb.json"),
            TunnelConfig(name="b", type="singbox", config_file="sb.json"),
        ]
        with pytest.raises(ValueError, match="same config_file"):
            validate_config_files(tunnels)

    def test_cross_type_same_config_ok(self):
        """Same config_file across different types is allowed."""
        tunnels = [
            TunnelConfig(name="a", type="singbox", config_file="shared.conf"),
            TunnelConfig(name="b", type="openvpn", config_file="shared.conf"),
        ]
        validate_config_files(tunnels)  # no error


# =========================================================================
# FortiVPN -> OpenConnect migration on macOS
# =========================================================================


class TestMigrateFortivpnToOpenconnect:
    """_migrate_fortivpn_to_openconnect on macOS."""

    @patch("tv.defaults.platform.system", return_value="Darwin")
    def test_type_changed_to_openconnect(self, _mock):
        """type=fortivpn becomes type=openconnect on macOS."""
        tunnels = [
            TunnelConfig(
                name="corp",
                type="fortivpn",
                auth={"host": "vpn.corp.com", "port": "443", "login": "u", "pass": "p"},
            )
        ]
        _migrate_fortivpn_to_openconnect(tunnels)
        assert tunnels[0].type == "openconnect"

    @patch("tv.defaults.platform.system", return_value="Darwin")
    def test_protocol_fortinet_added(self, _mock):
        """protocol=fortinet is set."""
        tunnels = [
            TunnelConfig(name="corp", type="fortivpn", auth={"host": "vpn.test"})
        ]
        _migrate_fortivpn_to_openconnect(tunnels)
        assert tunnels[0].auth["protocol"] == "fortinet"

    @patch("tv.defaults.platform.system", return_value="Darwin")
    def test_trusted_cert_dropped_and_auto_mode_set(self, _mock):
        """trusted_cert dropped (incompatible format), cert_mode=auto set."""
        tunnels = [
            TunnelConfig(
                name="corp",
                type="fortivpn",
                auth={"host": "vpn.test", "trusted_cert": "aabbccdd1234"},
            )
        ]
        _migrate_fortivpn_to_openconnect(tunnels)
        assert "trusted_cert" not in tunnels[0].auth
        assert tunnels[0].auth["cert_mode"] == "auto"

    @patch("tv.defaults.platform.system", return_value="Darwin")
    def test_existing_servercert_preserved(self, _mock):
        """Existing servercert kept, cert_mode=auto not forced."""
        tunnels = [
            TunnelConfig(
                name="corp",
                type="fortivpn",
                auth={"host": "vpn.test", "servercert": "pin-sha256:existing=="},
            )
        ]
        _migrate_fortivpn_to_openconnect(tunnels)
        assert tunnels[0].auth["servercert"] == "pin-sha256:existing=="

    @patch("tv.defaults.platform.system", return_value="Darwin")
    def test_fallback_gateway_removed(self, _mock):
        """fallback_gateway extra param removed (not applicable to openconnect)."""
        tunnels = [
            TunnelConfig(
                name="corp",
                type="fortivpn",
                auth={"host": "vpn.test"},
                extra={"fallback_gateway": "10.0.0.1"},
            )
        ]
        _migrate_fortivpn_to_openconnect(tunnels)
        assert "fallback_gateway" not in tunnels[0].extra

    @patch("tv.defaults.platform.system", return_value="Linux")
    def test_no_migration_on_linux(self, _mock):
        """type=fortivpn stays on Linux."""
        tunnels = [
            TunnelConfig(name="corp", type="fortivpn", auth={"host": "vpn.test"})
        ]
        _migrate_fortivpn_to_openconnect(tunnels)
        assert tunnels[0].type == "fortivpn"

    @patch("tv.defaults.platform.system", return_value="Darwin")
    def test_other_types_untouched(self, _mock):
        """Non-fortivpn tunnels not affected."""
        tunnels = [
            TunnelConfig(name="sb", type="singbox"),
            TunnelConfig(name="ovpn", type="openvpn"),
            TunnelConfig(name="corp", type="fortivpn", auth={"host": "vpn.test"}),
        ]
        _migrate_fortivpn_to_openconnect(tunnels)
        assert tunnels[0].type == "singbox"
        assert tunnels[1].type == "openvpn"
        assert tunnels[2].type == "openconnect"

    @patch("tv.defaults.platform.system", return_value="Darwin")
    def test_existing_servercert_skips_auto_mode(self, _mock):
        """If servercert already set, cert_mode=auto not forced."""
        tunnels = [
            TunnelConfig(
                name="corp",
                type="fortivpn",
                auth={
                    "host": "vpn.test",
                    "trusted_cert": "old_cert",
                    "servercert": "pin-sha256:existing==",
                },
            )
        ]
        _migrate_fortivpn_to_openconnect(tunnels)
        assert tunnels[0].auth["servercert"] == "pin-sha256:existing=="
        assert "trusted_cert" not in tunnels[0].auth
