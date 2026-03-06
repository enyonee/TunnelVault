"""Integration tests for config loading and resolution flows.

Real file I/O, real TOML parsing. No network required.
"""

from __future__ import annotations

from unittest.mock import patch

import tomlkit

from tv import defaults as defaults_mod
from tv.app_config import cfg
from tv.config import (
    resolve_tunnel_params,
    resolve_tunnel_routes,
    save_tunnel_settings,
)
from tv.vpn.base import TunnelConfig
from tv.vpn.fortivpn import FortiVPNPlugin
from tv.vpn.openvpn import OpenVPNPlugin


def _write_toml(path, tunnels: dict) -> None:
    """Write minimal config.toml for tests."""
    doc = tomlkit.document()
    t_section = tomlkit.table(is_super_table=True)
    for name, data in tunnels.items():
        t_table = tomlkit.table()
        for k, v in data.items():
            if isinstance(v, dict):
                sub = tomlkit.table()
                for sk, sv in v.items():
                    sub[sk] = sv
                t_table[k] = sub
            else:
                t_table[k] = v
        t_section[name] = t_table
    doc["tunnels"] = t_section
    (path / cfg.paths.defaults_file).write_text(tomlkit.dumps(doc))


# =========================================================================
# config.toml: load with --setup
# =========================================================================


class TestDefaultsSetupFlow:
    def test_setup_creates_defaults_from_example(self, tmp_path):
        """--setup with no config.toml copies from example, parses result."""
        example = tmp_path / "config.toml.example"
        example.write_text(
            "[tunnels.openvpn]\n"
            'type = "openvpn"\n'
            "order = 1\n"
            'config_file = "client.ovpn"\n'
            "\n"
            "[tunnels.singbox]\n"
            'type = "singbox"\n'
            "order = 2\n"
            'config_file = "singbox.json"\n'
            'interface = "utun99"\n'
        )

        data = defaults_mod.load(tmp_path, setup=True)

        # File was created
        created = tmp_path / "config.toml"
        assert created.exists()
        assert created.read_text() == example.read_text()

        # Data parsed correctly
        assert "openvpn" in data["tunnels"]
        assert "singbox" in data["tunnels"]
        assert data["tunnels"]["singbox"]["interface"] == "utun99"

    def test_setup_loads_existing_file_unchanged(self, tmp_path):
        """--setup with existing config.toml loads it, doesn't overwrite."""
        toml = tmp_path / "config.toml"
        content = '[tunnels.forti]\ntype = "fortivpn"\norder = 1\n'
        toml.write_text(content)

        data = defaults_mod.load(tmp_path, setup=True)

        assert data["tunnels"]["forti"]["type"] == "fortivpn"
        # File unchanged
        assert toml.read_text() == content


# =========================================================================
# Settings save/load round-trip via TOML
# =========================================================================


class TestSettingsRoundTrip:
    def test_save_and_reload(self, tmp_path):
        """save_tunnel_settings writes to config.toml, reload preserves data."""
        _write_toml(tmp_path, {
            "openvpn": {"type": "openvpn"},
            "fortivpn": {"type": "fortivpn"},
        })
        tunnels = [
            TunnelConfig(
                name="openvpn",
                type="openvpn",
                config_file="client.ovpn",
                routes={"targets": ["10.0.0.0/8"], "networks": ["10.0.0.0/8"]},
            ),
            TunnelConfig(
                name="fortivpn",
                type="fortivpn",
                auth={"host": "vpn.example.com", "port": "443", "login": "user"},
                routes={"targets": ["192.168.0.0/16"], "networks": ["192.168.0.0/16"]},
            ),
        ]

        save_tunnel_settings(tunnels, tmp_path)

        config_path = tmp_path / cfg.paths.defaults_file
        assert config_path.exists()

        doc = tomlkit.parse(config_path.read_text())
        assert doc["tunnels"]["openvpn"]["config_file"] == "client.ovpn"
        assert doc["tunnels"]["fortivpn"]["auth"]["host"] == "vpn.example.com"
        assert doc["tunnels"]["fortivpn"]["auth"]["login"] == "user"
        assert doc["tunnels"]["openvpn"]["routes"]["targets"] == ["10.0.0.0/8"]


# =========================================================================
# FortiVPN cert: unreachable server shows hint
# =========================================================================


class TestFortiCertUnreachable:
    def test_unreachable_shows_warning_and_hint(self, capsys):
        """When cert generation fails, show warning + hint, don't block."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={"host": "vpn.example.com", "port": "443", "cert_mode": "auto"},
        )

        with patch("tv.vpn.fortivpn.generate_cert", return_value=""):
            FortiVPNPlugin.post_resolve_params(tc, quiet=False)

        out = capsys.readouterr().out
        assert "vpn.example.com:443" in out
        assert "unreachable" in out.lower() or "недоступен" in out.lower()
        # trusted_cert not set - connect will proceed without verification
        assert not tc.auth.get("trusted_cert")

    def test_toml_cert_used_without_regeneration(self):
        """Cert in TOML (from previous wizard save) used without regeneration."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={
                "host": "vpn.example.com", "port": "443",
                "cert_mode": "auto", "trusted_cert": "aabbcc112233",
            },
        )
        with patch("tv.vpn.fortivpn.generate_cert") as mock_gen:
            FortiVPNPlugin.post_resolve_params(tc, quiet=True)
        mock_gen.assert_not_called()
        assert tc.auth["trusted_cert"] == "aabbcc112233"


# =========================================================================
# Full resolve_tunnel_params flow with real files
# =========================================================================


class TestResolveParamsWithFiles:
    def test_openvpn_config_file_from_toml(self, tmp_path):
        """OpenVPN config_file from TOML is resolved correctly."""
        tc = TunnelConfig(name="openvpn", type="openvpn", config_file="my.ovpn")
        resolve_tunnel_params(tc, OpenVPNPlugin, tmp_path, quiet=True)
        assert tc.config_file == "my.ovpn"

    def test_fortivpn_auth_from_toml(self, tmp_path):
        """FortiVPN auth params from TOML used directly."""
        tc = TunnelConfig(
            name="fortivpn", type="fortivpn",
            auth={
                "host": "vpn.corp.com", "port": "10443",
                "login": "admin", "pass": "secret123",
                "cert_mode": "manual", "trusted_cert": "deadbeef",
            },
        )
        resolve_tunnel_params(tc, FortiVPNPlugin, tmp_path, quiet=True)
        assert tc.auth["host"] == "vpn.corp.com"
        assert tc.auth["port"] == "10443"
        assert tc.auth["login"] == "admin"
        assert tc.auth["pass"] == "secret123"
        assert tc.auth["trusted_cert"] == "deadbeef"


# =========================================================================
# resolve_tunnel_routes with real targets
# =========================================================================


class TestResolveRoutesFlow:
    def test_toml_targets_parsed_to_networks(self):
        """TOML targets with CIDRs are parsed into routes.networks."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": ["192.168.0.0/16", "10.0.0.0/8"]},
        )
        resolve_tunnel_routes(tc, quiet=True)
        assert "192.168.0.0/16" in tc.routes["networks"]
        assert "10.0.0.0/8" in tc.routes["networks"]

    def test_toml_targets_loaded(self):
        """Targets in TOML (from wizard save) loaded without wizard."""
        tc = TunnelConfig(
            name="forti", type="fortivpn",
            routes={"targets": ["172.16.0.0/12"]},
        )
        resolve_tunnel_routes(tc, quiet=True)
        assert "172.16.0.0/12" in tc.routes["networks"]

    def test_empty_targets_means_native_routing(self):
        """Empty targets list = native routing (no custom routes)."""
        tc = TunnelConfig(
            name="openvpn", type="openvpn",
            routes={"targets": []},
        )
        resolve_tunnel_routes(tc, quiet=True)
        assert tc.routes.get("networks", []) == []
        assert tc.routes.get("hosts", []) == []

    def test_ip_target_becomes_host(self):
        """Bare IP target (no CIDR) becomes a host route."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": ["192.168.1.1"]},
        )
        resolve_tunnel_routes(tc, quiet=True)
        assert "192.168.1.1" in tc.routes.get("hosts", [])
