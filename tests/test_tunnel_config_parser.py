"""Tests for parse_tunnels() - v3 [tunnels.*] format."""

from __future__ import annotations


from tv.defaults import parse_tunnels


# ---------------------------------------------------------------------------
# V3 format ([tunnels.*] sections)
# ---------------------------------------------------------------------------


class TestParseTunnels:
    def test_basic_tunnel(self):
        defs = {
            "tunnels": {
                "openvpn": {
                    "type": "openvpn",
                    "order": 1,
                    "config_file": "client.ovpn",
                    "log": "/tmp/openvpn.log",
                },
            },
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 1
        t = tunnels[0]
        assert t.name == "openvpn"
        assert t.type == "openvpn"
        assert t.order == 1
        assert t.config_file == "client.ovpn"

    def test_ordering(self):
        defs = {
            "tunnels": {
                "singbox": {"type": "singbox", "order": 3},
                "openvpn": {"type": "openvpn", "order": 1},
                "fortivpn": {"type": "fortivpn", "order": 2},
            },
        }
        tunnels = parse_tunnels(defs)
        assert [t.name for t in tunnels] == ["openvpn", "fortivpn", "singbox"]

    def test_enabled_filter(self):
        defs = {
            "tunnels": {
                "active": {"type": "openvpn", "order": 1},
                "disabled": {"type": "fortivpn", "order": 2, "enabled": False},
            },
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 1
        assert tunnels[0].name == "active"

    def test_missing_type_skipped(self):
        defs = {
            "tunnels": {
                "good": {"type": "openvpn", "order": 1},
                "bad": {"order": 2},  # no type!
            },
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 1
        assert tunnels[0].name == "good"

    def test_routes_and_dns(self):
        defs = {
            "tunnels": {
                "forti": {
                    "type": "fortivpn",
                    "routes": {"networks": ["10.0.0.0/8"]},
                    "dns": {"nameservers": ["10.0.1.1"], "domains": ["alpha.local"]},
                },
            },
        }
        t = parse_tunnels(defs)[0]
        assert t.routes == {"networks": ["10.0.0.0/8"]}
        assert t.dns["nameservers"] == ["10.0.1.1"]

    def test_auth_section(self):
        defs = {
            "tunnels": {
                "forti": {
                    "type": "fortivpn",
                    "auth": {"host": "vpn.test.local", "port": "44333"},
                },
            },
        }
        t = parse_tunnels(defs)[0]
        assert t.auth["host"] == "vpn.test.local"

    def test_checks_section(self):
        defs = {
            "tunnels": {
                "forti": {
                    "type": "fortivpn",
                    "checks": {
                        "ports": [{"host": "10.0.0.1", "port": 8080}],
                        "ping": [{"host": "10.0.0.1", "label": "gw"}],
                    },
                },
            },
        }
        t = parse_tunnels(defs)[0]
        assert len(t.checks["ports"]) == 1
        assert t.checks["ports"][0]["port"] == 8080

    def test_extra_fields(self):
        defs = {
            "tunnels": {
                "vpn": {
                    "type": "openvpn",
                    "custom_gateway": "169.254.2.1",
                    "custom_thing": "foo",
                },
            },
        }
        t = parse_tunnels(defs)[0]
        assert t.extra["custom_gateway"] == "169.254.2.1"
        assert t.extra["custom_thing"] == "foo"

    def test_interface_field(self):
        defs = {
            "tunnels": {
                "singbox": {
                    "type": "singbox",
                    "interface": "utun99",
                },
            },
        }
        t = parse_tunnels(defs)[0]
        assert t.interface == "utun99"

    def test_empty_tunnels_section(self):
        defs = {"tunnels": {}}
        assert parse_tunnels(defs) == []

    def test_no_tunnels_key(self):
        """Missing tunnels key returns empty list."""
        defs = {"global": {"some": "value"}}
        assert parse_tunnels(defs) == []

    def test_all_disabled(self):
        defs = {
            "tunnels": {
                "a": {"type": "openvpn", "enabled": False},
                "b": {"type": "fortivpn", "enabled": False},
            },
        }
        assert parse_tunnels(defs) == []

    def test_non_dict_value_skipped(self):
        """Non-dict values in tunnels section are silently skipped."""
        defs = {
            "tunnels": {
                "valid": {"type": "openvpn"},
                "invalid_string": "not a dict",
            },
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_default_order_zero(self):
        defs = {
            "tunnels": {
                "a": {"type": "openvpn"},
                "b": {"type": "singbox"},
            },
        }
        tunnels = parse_tunnels(defs)
        assert all(t.order == 0 for t in tunnels)

    def test_same_order_stable(self):
        """Same order values should not crash (stable sort)."""
        defs = {
            "tunnels": {
                "a": {"type": "openvpn", "order": 1},
                "b": {"type": "singbox", "order": 1},
            },
        }
        tunnels = parse_tunnels(defs)
        assert len(tunnels) == 2

    def test_deepcopy_isolation(self):
        """Parsed TunnelConfig dicts are independent from original defs."""
        defs = {
            "tunnels": {
                "forti": {
                    "type": "fortivpn",
                    "routes": {"networks": ["10.0.0.0/8"]},
                    "dns": {"nameservers": ["10.0.1.1"]},
                },
            },
        }
        tunnels = parse_tunnels(defs)
        # Mutate the TunnelConfig
        tunnels[0].routes["networks"].append("172.16.0.0/12")
        tunnels[0].dns["extra_key"] = "added"
        # Original defs unchanged
        assert defs["tunnels"]["forti"]["routes"]["networks"] == ["10.0.0.0/8"]
        assert "extra_key" not in defs["tunnels"]["forti"]["dns"]
