"""Tests for tv.validate module."""

from __future__ import annotations

import platform

from tv import validate


class TestValidate:
    def test_valid_config(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "config_file": "client.ovpn",
                    "routes": {
                        "networks": ["10.0.0.0/8"],
                    },
                    "dns": {
                        "domains": ["test.local"],
                        "nameservers": ["10.0.0.1"],
                    },
                    "checks": {
                        "ports": [{"host": "10.0.0.1", "port": 443}],
                    },
                },
            },
        }
        assert validate.run(defs, tmp_dir) is True
        out = capsys.readouterr().out
        assert "valid" in out

    def test_unknown_type(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {"type": "zerotier"},
            },
        }
        assert validate.run(defs, tmp_dir) is False
        out = capsys.readouterr().out
        assert "zerotier" in out

    def test_missing_type(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {"config_file": "test.ovpn"},
            },
        }
        assert validate.run(defs, tmp_dir) is False
        out = capsys.readouterr().out
        assert "type" in out

    def test_missing_config_file(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "config_file": "nonexistent.ovpn",
                },
            },
        }
        validate.run(defs, tmp_dir)
        out = capsys.readouterr().out
        # Missing file is a warning, not error
        assert "nonexistent.ovpn" in out

    def test_absolute_config_file(self, tmp_dir, capsys):
        # Use platform-appropriate absolute path
        abs_path = (
            "C:\\openvpn\\client.ovpn"
            if platform.system() == "Windows"
            else "/etc/openvpn/client.ovpn"
        )
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "config_file": abs_path,
                },
            },
        }
        assert validate.run(defs, tmp_dir) is False
        out = capsys.readouterr().out
        assert "absolute path" in out

    def test_invalid_route_target(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "routes": {
                        "targets": ["not a valid target!"],
                    },
                },
            },
        }
        assert validate.run(defs, tmp_dir) is False
        out = capsys.readouterr().out
        assert "routes.targets" in out

    def test_duplicate_config_file(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "config_file": "client.ovpn",
                },
                "vpn2": {
                    "type": "openvpn",
                    "config_file": "client.ovpn",
                },
            },
        }
        assert validate.run(defs, tmp_dir) is False
        out = capsys.readouterr().out
        assert "already used" in out

    def test_dns_without_nameservers(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "dns": {
                        "domains": ["test.local"],
                    },
                },
            },
        }
        # Warning, not error
        result = validate.run(defs, tmp_dir)
        out = capsys.readouterr().out
        assert "nameservers" in out
        assert result is True  # warnings don't fail

    def test_empty_tunnels(self, tmp_dir, capsys):
        defs = {"tunnels": {}}
        validate.run(defs, tmp_dir)
        out = capsys.readouterr().out
        assert "No [tunnels.*]" in out

    def test_network_without_cidr(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "routes": {
                        "networks": ["10.0.0.1"],
                    },
                },
            },
        }
        assert validate.run(defs, tmp_dir) is False
        out = capsys.readouterr().out
        assert "cidr" in out.lower() or "CIDR" in out

    def test_checks_port_missing_host(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "checks": {
                        "ports": [{"port": 443}],
                    },
                },
            },
        }
        assert validate.run(defs, tmp_dir) is False
        out = capsys.readouterr().out
        assert "host" in out

    def test_checks_port_missing_port(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {
                    "type": "openvpn",
                    "checks": {
                        "ports": [{"host": "10.0.0.1"}],
                    },
                },
            },
        }
        assert validate.run(defs, tmp_dir) is False
        out = capsys.readouterr().out
        assert "port" in out

    def test_bypass_suffix_without_dot(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {"type": "openvpn"},
            },
            "global": {
                "bypass": {
                    "domain_suffix": ["ru"],
                },
            },
        }
        result = validate.run(defs, tmp_dir)
        out = capsys.readouterr().out
        assert "does not start with dot" in out
        assert result is True  # warning only

    def test_vpn_server_routes_invalid_host(self, tmp_dir, capsys):
        defs = {
            "tunnels": {
                "vpn1": {"type": "openvpn"},
            },
            "global": {
                "vpn_server_routes": {
                    "hosts": ["not valid!"],
                },
            },
        }
        assert validate.run(defs, tmp_dir) is False
        out = capsys.readouterr().out
        assert "vpn_server_routes" in out
