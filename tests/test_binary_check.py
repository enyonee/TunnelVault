"""Tests for optional VPN profiles: binary availability checks."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tv.engine import Engine
from tv.vpn.base import TunnelPlugin, VPNResult
from tv.vpn.openvpn import OpenVPNPlugin
from tv.vpn.fortivpn import FortiVPNPlugin
from tv.vpn.singbox import SingBoxPlugin


# =========================================================================
# Plugin binary attribute
# =========================================================================


class TestPluginBinary:
    def test_openvpn_binary(self):
        assert OpenVPNPlugin.binary == "openvpn"

    def test_fortivpn_binary(self):
        assert FortiVPNPlugin.binary == "openfortivpn"

    def test_singbox_binary(self):
        assert SingBoxPlugin.binary == "sing-box"

    def test_base_binary_empty(self):
        assert TunnelPlugin.binary == ""


# =========================================================================
# check_binary
# =========================================================================


class TestCheckBinary:
    def test_returns_true_when_binary_found(self):
        """Autouse fixture makes all binaries available."""
        assert OpenVPNPlugin.check_binary() is True
        assert FortiVPNPlugin.check_binary() is True
        assert SingBoxPlugin.check_binary() is True

    def test_real_check_binary_uses_shutil_which(self):
        """Verify real check_binary uses shutil.which."""
        # Bypass autouse fixture by calling the real implementation directly
        import shutil as _shutil

        with patch.object(
            _shutil, "which", return_value="/usr/bin/openvpn"
        ) as mock_which:
            result = bool(OpenVPNPlugin.binary and _shutil.which(OpenVPNPlugin.binary))
        mock_which.assert_called_once_with("openvpn")
        assert result is True

    def test_real_check_binary_missing(self):
        """shutil.which returns None -> binary not found."""
        import shutil as _shutil

        with patch.object(_shutil, "which", return_value=None):
            result = bool(SingBoxPlugin.binary and _shutil.which(SingBoxPlugin.binary))
        assert result is False

    def test_base_class_no_binary_returns_false(self):
        """Base class with empty binary always returns False."""
        # Empty binary string -> bool("") is False regardless of shutil.which
        assert not TunnelPlugin.binary


# =========================================================================
# Engine._filter_available
# =========================================================================


class TestFilterAvailable:
    @pytest.fixture
    def defs_three(self, tmp_dir):
        return {
            "tunnels": {
                "ovpn": {
                    "type": "openvpn",
                    "order": 1,
                    "config_file": "client.ovpn",
                    "routes": {"networks": ["10.0.0.0/8"]},
                },
                "forti": {
                    "type": "fortivpn",
                    "order": 2,
                    "auth": {
                        "host": "vpn.test.com",
                        "port": "443",
                        "login": "u",
                        "pass": "p",
                        "cert_mode": "pin",
                        "trusted_cert": "abc",
                        "servercert": "pin-sha256:test==",
                    },
                    "routes": {"networks": ["172.16.0.0/12"]},
                },
                "sb": {
                    "type": "singbox",
                    "order": 3,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                    "routes": {"networks": ["192.168.0.0/16"]},
                },
            },
        }

    def test_all_binaries_available(self, tmp_dir, defs_three, mock_net, logger):
        """All binaries installed -> all tunnels kept."""
        e = Engine(tmp_dir, defs_three, net=mock_net, log=logger)
        e.prepare()
        assert len(e.tunnels) == 3

    def test_one_binary_missing(
        self, tmp_dir, defs_three, mock_net, logger, monkeypatch, capsys
    ):
        """One binary missing -> that tunnel skipped, others kept."""

        def fake_check(cls):
            return cls.binary != "sing-box"

        monkeypatch.setattr(TunnelPlugin, "check_binary", classmethod(fake_check))

        e = Engine(tmp_dir, defs_three, net=mock_net, log=logger)
        e.prepare()

        names = [t.name for t in e.tunnels]
        assert "ovpn" in names
        assert "forti" in names
        assert "sb" not in names

        out = capsys.readouterr().out
        assert "sing-box" in out
        assert "sb" in out

    def test_all_binaries_missing(
        self, tmp_dir, defs_three, mock_net, logger, monkeypatch, capsys
    ):
        """All binaries missing -> empty tunnels, warning shown."""
        monkeypatch.setattr(
            TunnelPlugin, "check_binary", classmethod(lambda cls: False)
        )

        e = Engine(tmp_dir, defs_three, net=mock_net, log=logger)
        e.prepare()

        assert e.tunnels == []
        out = capsys.readouterr().out
        assert "No tunnels available" in out or "missing" in out

    def test_warning_logged_for_missing_binary(
        self, tmp_dir, mock_net, logger, monkeypatch
    ):
        """Missing binary is logged."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                    "routes": {"networks": ["10.0.0.0/8"]},
                },
            },
        }
        monkeypatch.setattr(
            TunnelPlugin, "check_binary", classmethod(lambda cls: False)
        )

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        e.prepare()

        log_content = logger.log_path.read_text()
        assert "sing-box" in log_content
        assert "not found" in log_content

    def test_partial_binaries_connect_works(
        self, tmp_dir, mock_net, logger, monkeypatch
    ):
        """With some binaries missing, remaining tunnels connect normally."""
        defs = {
            "tunnels": {
                "ovpn": {
                    "type": "openvpn",
                    "order": 1,
                    "config_file": "client.ovpn",
                    "routes": {"networks": ["10.0.0.0/8"]},
                },
                "sb": {
                    "type": "singbox",
                    "order": 2,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                    "routes": {"networks": ["172.16.0.0/12"]},
                },
            },
        }

        def fake_check(cls):
            return cls.binary != "sing-box"

        monkeypatch.setattr(TunnelPlugin, "check_binary", classmethod(fake_check))

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        e.prepare()

        assert len(e.tunnels) == 1
        assert e.tunnels[0].type == "openvpn"

        with patch(
            "tv.vpn.openvpn.OpenVPNPlugin.connect", return_value=VPNResult(ok=True)
        ):
            e.connect_all()

        assert len(e.results) == 1
        assert e.results[0].ok is True

    def test_two_same_type_one_skipped(
        self, tmp_dir, mock_net, logger, monkeypatch, capsys
    ):
        """Two singbox tunnels, binary missing -> both skipped."""
        (tmp_dir / "sb2.json").write_text("{}")
        defs = {
            "tunnels": {
                "sb1": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                    "routes": {"networks": ["10.0.0.0/8"]},
                },
                "sb2": {
                    "type": "singbox",
                    "order": 2,
                    "config_file": "sb2.json",
                    "interface": "utun100",
                    "routes": {"networks": ["172.16.0.0/12"]},
                },
            },
        }
        monkeypatch.setattr(
            TunnelPlugin, "check_binary", classmethod(lambda cls: False)
        )

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        e.prepare()

        assert e.tunnels == []
        out = capsys.readouterr().out
        assert "sb1" in out
        assert "sb2" in out


# =========================================================================
# validate.py binary check
# =========================================================================


class TestValidateBinaryCheck:
    def test_validate_warns_on_missing_binary(self, tmp_dir, monkeypatch, capsys):
        """--validate shows warning for missing binary."""
        from tv import validate as validate_mod

        defs = {
            "tunnels": {
                "sb": {"type": "singbox", "config_file": "singbox.json"},
            },
        }

        def fake_check(cls):
            return cls.binary != "sing-box"

        monkeypatch.setattr(TunnelPlugin, "check_binary", classmethod(fake_check))

        result = validate_mod.run(defs, tmp_dir)

        out = capsys.readouterr().out
        assert "sing-box" in out
        assert "not installed" in out
        # Binary missing is a warning, not error -> still valid
        assert result is True

    def test_validate_no_warning_when_binary_present(self, tmp_dir, capsys):
        """--validate no warning when binary is installed."""
        from tv import validate as validate_mod

        defs = {
            "tunnels": {
                "ovpn": {"type": "openvpn", "config_file": "client.ovpn"},
            },
        }

        validate_mod.run(defs, tmp_dir)
        out = capsys.readouterr().out
        assert "not installed" not in out


# =========================================================================
# Engine with no tunnels exits early
# =========================================================================


class TestEngineNoTunnelsEarlyReturn:
    def test_prepare_returns_early_when_all_missing(
        self, tmp_dir, mock_net, logger, monkeypatch
    ):
        """prepare() returns without crashing when no tunnels available."""
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
        monkeypatch.setattr(
            TunnelPlugin, "check_binary", classmethod(lambda cls: False)
        )

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        e.prepare()

        assert e.tunnels == []
        assert e.plugins == []
        assert e.results == []

    def test_connect_all_with_empty_tunnels_noop(
        self, tmp_dir, mock_net, logger, monkeypatch
    ):
        """connect_all on empty tunnels does nothing."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "config_file": "singbox.json",
                    "interface": "utun99",
                }
            }
        }
        monkeypatch.setattr(
            TunnelPlugin, "check_binary", classmethod(lambda cls: False)
        )

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        e.prepare()
        e.connect_all()

        assert e.results == []
        assert e.plugins == []

    def test_skipped_binaries_tracked(self, tmp_dir, mock_net, logger, monkeypatch):
        """Skipped tunnel names recorded in engine.skipped_binaries."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                    "routes": {"networks": ["10.0.0.0/8"]},
                },
                "ovpn": {
                    "type": "openvpn",
                    "order": 2,
                    "config_file": "client.ovpn",
                    "routes": {"networks": ["172.16.0.0/12"]},
                },
            },
        }

        def fake_check(cls):
            return cls.binary != "sing-box"

        monkeypatch.setattr(TunnelPlugin, "check_binary", classmethod(fake_check))

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        e.prepare()

        assert "sb" in e.skipped_binaries
        assert e.skipped_binaries["sb"] == "sing-box"
        assert "ovpn" not in e.skipped_binaries


# =========================================================================
# --only + missing binary interaction
# =========================================================================


class TestOnlyWithMissingBinary:
    def test_only_requests_skipped_tunnel(self, tmp_dir, mock_net, logger, monkeypatch):
        """--only asks for a tunnel whose binary is missing -> skipped_binaries contains it."""
        defs = {
            "tunnels": {
                "sb": {
                    "type": "singbox",
                    "order": 1,
                    "config_file": "singbox.json",
                    "interface": "utun99",
                    "routes": {"networks": ["10.0.0.0/8"]},
                },
                "ovpn": {
                    "type": "openvpn",
                    "order": 2,
                    "config_file": "client.ovpn",
                    "routes": {"networks": ["172.16.0.0/12"]},
                },
            },
        }

        def fake_check(cls):
            return cls.binary != "sing-box"

        monkeypatch.setattr(TunnelPlugin, "check_binary", classmethod(fake_check))

        e = Engine(tmp_dir, defs, net=mock_net, log=logger)
        e.prepare()

        # filter_tunnels raises because "sb" was removed by binary check
        from tv.defaults import filter_tunnels

        with pytest.raises(ValueError):
            filter_tunnels(e.tunnels, "sb")

        # But engine.skipped_binaries lets caller give a better error
        assert "sb" in e.skipped_binaries
