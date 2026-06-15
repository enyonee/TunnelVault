"""Tests for tv.config: saving to TOML, param resolution, tunnel resolve."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tv.app_config import cfg
from tv.config import (
    SetupRequiredError,
    all_required_set,
    save_tunnel_settings,
    resolve_tunnel_params,
    resolve_tunnel_routes,
    resolve_log_dir,
    resolve_log_paths,
    ensure_log_dir,
    prepare_log_files,
    _resolve_param,
    _get_param_value,
    _set_param_value,
)
from tv.vpn.cert import generate_cert_sha256 as _generate_cert
from tv.vpn.base import TunnelConfig, ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.fortivpn import FortiVPNPlugin
from tv.vpn.openvpn import OpenVPNPlugin


def _write_toml(path: Path, tunnels: dict) -> None:
    """Write minimal config.toml for save_tunnel_settings tests."""
    import tomlkit

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
    target = path / cfg.paths.defaults_file
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(tomlkit.dumps(doc))


# =========================================================================
# Positive: settings save to config.toml
# =========================================================================


class TestSaveTunnelSettings:
    def test_saves_per_tunnel(self, tmp_dir: Path):
        _write_toml(
            tmp_dir,
            {
                "fortivpn": {"type": "fortivpn"},
                "openvpn": {"type": "openvpn"},
            },
        )
        tunnels = [
            TunnelConfig(
                name="fortivpn",
                type="fortivpn",
                auth={
                    "host": "vpn.test.local",
                    "port": "44333",
                    "login": "user",
                    "pass": "secret",
                    "cert_mode": "auto",
                    "trusted_cert": "abc123",
                },
            ),
            TunnelConfig(
                name="openvpn",
                type="openvpn",
                config_file="client.ovpn",
            ),
        ]
        save_tunnel_settings(tunnels, tmp_dir)
        import tomlkit

        doc = tomlkit.parse((tmp_dir / cfg.paths.defaults_file).read_text())
        assert doc["tunnels"]["fortivpn"]["auth"]["host"] == "vpn.test.local"
        assert doc["tunnels"]["openvpn"]["config_file"] == "client.ovpn"

    @pytest.mark.skipif(
        __import__("platform").system() == "Windows",
        reason="Unix file permissions not supported on Windows",
    )
    def test_file_permissions_600(self, tmp_dir: Path):
        _write_toml(tmp_dir, {"openvpn": {"type": "openvpn"}})
        tunnels = [TunnelConfig(name="openvpn", type="openvpn", config_file="c.ovpn")]
        save_tunnel_settings(tunnels, tmp_dir)
        path = tmp_dir / cfg.paths.defaults_file
        mode = oct(path.stat().st_mode & 0o777)
        assert mode == "0o600"

    def test_skips_unknown_plugin(self, tmp_dir: Path):
        _write_toml(tmp_dir, {"custom": {"type": "wireguard"}})
        tunnels = [TunnelConfig(name="custom", type="wireguard")]
        save_tunnel_settings(tunnels, tmp_dir)
        import tomlkit

        doc = tomlkit.parse((tmp_dir / cfg.paths.defaults_file).read_text())
        # Unknown plugin has no schema, nothing saved
        assert "auth" not in doc["tunnels"]["custom"]

    def test_saves_targets_and_dns(self, tmp_dir: Path):
        _write_toml(tmp_dir, {"forti": {"type": "fortivpn"}})
        tunnels = [
            TunnelConfig(
                name="forti",
                type="fortivpn",
                routes={"targets": ["*.alpha.local", "10.0.0.0/8"]},
                dns={"nameservers": ["10.0.1.1"]},
            ),
        ]
        save_tunnel_settings(tunnels, tmp_dir)
        import tomlkit

        doc = tomlkit.parse((tmp_dir / cfg.paths.defaults_file).read_text())
        assert doc["tunnels"]["forti"]["routes"]["targets"] == [
            "*.alpha.local",
            "10.0.0.0/8",
        ]
        assert doc["tunnels"]["forti"]["dns"]["nameservers"] == ["10.0.1.1"]

    def test_saves_empty_targets_native_routing(self, tmp_dir: Path):
        """Empty targets (native routing) saved to remember user choice."""
        _write_toml(tmp_dir, {"forti": {"type": "fortivpn"}})
        tunnels = [
            TunnelConfig(
                name="forti",
                type="fortivpn",
                routes={"targets": []},
            ),
        ]
        save_tunnel_settings(tunnels, tmp_dir)
        import tomlkit

        doc = tomlkit.parse((tmp_dir / cfg.paths.defaults_file).read_text())
        assert doc["tunnels"]["forti"]["routes"]["targets"] == []


# =========================================================================
# all_required_set
# =========================================================================


class TestAllRequiredSet:
    def test_all_set(self):
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={"host": "h", "login": "u", "pass": "p"},
        )
        assert all_required_set([tc]) is True

    def test_missing_required(self):
        tc = TunnelConfig(name="fortivpn", type="fortivpn")
        assert all_required_set([tc]) is False

    def test_no_schema_ok(self):
        tc = TunnelConfig(name="custom", type="unknown_type")
        assert all_required_set([tc]) is True


# =========================================================================
# Positive: param resolution
# =========================================================================


class TestResolveParam:
    def test_env_wins(self):
        with patch.dict(os.environ, {"VPN_TEST": "from_env"}):
            result = _resolve_param("test", env_name="VPN_TEST")
        assert result == "from_env"


# =========================================================================
# Negative / inverse: param resolution edge cases
# =========================================================================


class TestResolveParamInverse:
    def test_env_empty_string_not_treated_as_value(self):
        with patch.dict(os.environ, {"VPN_EMPTY": ""}):
            with patch("tv.ui.wizard_input", return_value="wizard_val"):
                result = _resolve_param("test", env_name="VPN_EMPTY")
        assert result == "wizard_val"

    @patch("tv.ui.wizard_input", return_value="wizard_input")
    def test_falls_to_wizard_when_all_empty(self, mock_wizard):
        result = _resolve_param("test", env_name="NOPE")
        assert result == "wizard_input"
        mock_wizard.assert_called_once()

    @patch("tv.ui.wizard_input", return_value="")
    def test_wizard_empty_returns_default(self, mock_wizard):
        result = _resolve_param("test", env_name="NOPE", default="def_val")
        assert result == ""  # wizard_input mock returns ""


# =========================================================================
# Certificate generation
# =========================================================================


class TestGenerateCert:
    @patch("subprocess.Popen")
    def test_returns_empty_on_timeout(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = TimeoutError()
        mock_proc.kill.return_value = None
        mock_popen.return_value = mock_proc
        result = _generate_cert("host", "443")
        assert result == ""

    @patch("subprocess.Popen")
    def test_returns_empty_on_oserror(self, mock_popen):
        mock_popen.side_effect = FileNotFoundError("openssl")
        result = _generate_cert("host", "443")
        assert result == ""

    @patch("subprocess.Popen")
    def test_returns_empty_when_x509_has_no_output(self, mock_popen):
        """If x509 produces no DER output (server unreachable), return empty."""
        s_client = MagicMock()
        s_client.stdout = MagicMock()
        s_client.stdin = MagicMock()
        x509 = MagicMock()
        x509.communicate.return_value = (b"", b"")  # empty DER
        x509.stdout = MagicMock()
        mock_popen.side_effect = [s_client, x509]
        result = _generate_cert("host", "443")
        assert result == ""


# =========================================================================
# ConfigParam get/set helpers
# =========================================================================


class TestConfigParamHelpers:
    @pytest.mark.parametrize(
        "target,key,label,tc_kw,expected",
        [
            ("auth", "host", "Host", {"auth": {"host": "vpn.com"}}, "vpn.com"),
            (
                "config_file",
                "config_file",
                "Config",
                {"config_file": "test.ovpn"},
                "test.ovpn",
            ),
            ("extra", "gw", "GW", {"extra": {"gw": "1.2.3.4"}}, "1.2.3.4"),
        ],
    )
    def test_get_param(self, target, key, label, tc_kw, expected):
        tc = TunnelConfig(**tc_kw)
        param = ConfigParam(key, label, target=target)
        assert _get_param_value(tc, param) == expected

    @pytest.mark.parametrize(
        "target,key,label,value,check",
        [
            ("auth", "host", "Host", "vpn.com", lambda tc: tc.auth["host"]),
            (
                "config_file",
                "config_file",
                "Config",
                "test.ovpn",
                lambda tc: tc.config_file,
            ),
            ("extra", "gw", "GW", "1.2.3.4", lambda tc: tc.extra["gw"]),
        ],
    )
    def test_set_param(self, target, key, label, value, check):
        tc = TunnelConfig()
        param = ConfigParam(key, label, target=target)
        _set_param_value(tc, param, value)
        assert check(tc) == value


# =========================================================================
# resolve_tunnel_params - plugin-driven resolution
# =========================================================================


class TestResolveTunnelParams:
    def test_toml_value_used_first(self):
        """TOML value already in TunnelConfig -> no wizard needed."""
        tc = TunnelConfig(
            name="openvpn",
            type="openvpn",
            config_file="my.ovpn",
        )
        resolve_tunnel_params(tc, OpenVPNPlugin, Path("/tmp"))
        assert tc.config_file == "my.ovpn"

    def test_env_fills_missing(self):
        """ENV fills when TOML value missing."""
        tc = TunnelConfig(name="openvpn", type="openvpn")
        with patch.dict(os.environ, {"VPN_OVPN_CONFIG": "env.ovpn"}):
            resolve_tunnel_params(tc, OpenVPNPlugin, Path("/tmp"))
        assert tc.config_file == "env.ovpn"

    def test_toml_auth_used(self):
        """Auth values from TOML (wizard-saved on previous run) used directly."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "user",
                "pass": "secret",
                "cert_mode": "manual",
                "trusted_cert": "abc123",
            },
        )
        resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"))
        assert tc.auth["host"] == "vpn.com"
        assert tc.auth["login"] == "user"
        assert tc.auth["pass"] == "secret"

    def test_toml_auth_not_overwritten_by_env(self):
        """TOML auth values take priority (ENV checked only when TOML empty)."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "toml-host",
                "port": "44333",
                "login": "toml-user",
                "pass": "toml-pass",
                "cert_mode": "manual",
                "trusted_cert": "toml-cert",
            },
        )
        with patch.dict(os.environ, {"VPN_FORTI_HOST": "env-host"}):
            resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"))
        assert tc.auth["host"] == "toml-host"

    def test_empty_schema_noop(self):
        """Plugin with no config_schema -> no-op."""
        tc = TunnelConfig(name="custom", type="custom")

        class NoSchemaPlugin(TunnelPlugin):
            def connect(self):
                return VPNResult()

            @property
            def process_name(self):
                return "custom"

        resolve_tunnel_params(tc, NoSchemaPlugin, Path("/tmp"))
        assert tc.auth == {}

    @patch("tv.vpn.fortivpn.generate_cert_sha256", return_value="generated_cert_abc")
    def test_forti_auto_cert_generated(self, mock_cert):
        """cert_mode=auto triggers cert generation."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "cert_mode": "auto",
            },
        )
        resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"))
        assert tc.auth["trusted_cert"] == "generated_cert_abc"
        mock_cert.assert_called_once_with("vpn.com", "443")

    def test_forti_manual_cert_no_generation(self):
        """cert_mode=manual does NOT trigger cert generation."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "cert_mode": "manual",
                "trusted_cert": "manual_cert",
            },
        )
        with patch("tv.vpn.fortivpn.generate_cert_sha256") as mock_cert:
            resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"))
        mock_cert.assert_not_called()
        assert tc.auth["trusted_cert"] == "manual_cert"

    def test_forti_auto_cert_from_env(self):
        """cert_mode=auto with VPN_TRUSTED_CERT env -> uses env, no generation."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "cert_mode": "auto",
            },
        )
        with (
            patch.dict(os.environ, {"VPN_TRUSTED_CERT": "env_cert_value"}),
            patch("tv.vpn.fortivpn.generate_cert_sha256") as mock_cert,
        ):
            resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"))
        mock_cert.assert_not_called()
        assert tc.auth["trusted_cert"] == "env_cert_value"

    def test_forti_auto_cert_from_toml(self):
        """cert_mode=auto with trusted_cert in TOML -> uses it, no generation."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "cert_mode": "auto",
                "trusted_cert": "toml_cert_value",
            },
        )
        with patch("tv.vpn.fortivpn.generate_cert_sha256") as mock_cert:
            resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"))
        mock_cert.assert_not_called()
        assert tc.auth["trusted_cert"] == "toml_cert_value"


# =========================================================================
# resolve_tunnel_routes
# =========================================================================


class TestResolveTunnelRoutes:
    def test_targets_from_toml(self):
        """Targets in TOML routes -> parsed into networks/hosts/dns."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": ["*.alpha.local", "10.0.0.0/8", "192.168.1.1"]},
            dns={"nameservers": ["10.0.1.1"]},
        )
        resolve_tunnel_routes(tc)
        assert "10.0.0.0/8" in tc.routes["networks"]
        assert "192.168.1.1" in tc.routes["hosts"]
        assert "alpha.local" in tc.dns["domains"]

    @patch("tv.ui.wizard_targets", return_value=["172.16.0.0/12", "1.2.3.4"])
    def test_wizard_fallback(self, mock_wizard):
        """No targets anywhere -> wizard asks."""
        tc = TunnelConfig(name="forti", type="fortivpn")
        resolve_tunnel_routes(tc)
        mock_wizard.assert_called_once_with("forti")
        assert "172.16.0.0/12" in tc.routes["networks"]
        assert "1.2.3.4" in tc.routes["hosts"]

    def test_advanced_mode_skips_wizard(self):
        """Existing networks in TOML -> wizard not called."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"networks": ["10.0.0.0/8"]},
        )
        with patch("tv.ui.wizard_targets") as mock_wizard:
            resolve_tunnel_routes(tc)
        mock_wizard.assert_not_called()
        assert tc.routes["networks"] == ["10.0.0.0/8"]

    def test_advanced_mode_hosts_skips_wizard(self):
        """Existing hosts in TOML -> wizard not called."""
        tc = TunnelConfig(
            name="sb",
            type="singbox",
            routes={"hosts": ["1.2.3.4"]},
        )
        with patch("tv.ui.wizard_targets") as mock_wizard:
            resolve_tunnel_routes(tc)
        mock_wizard.assert_not_called()

    @patch("tv.ui.wizard_targets", return_value=[])
    def test_empty_wizard_input_noop(self, mock_wizard):
        """Empty wizard input -> no routes added, targets=[] saved."""
        tc = TunnelConfig(name="forti", type="fortivpn")
        resolve_tunnel_routes(tc)
        assert tc.routes.get("networks") is None
        assert tc.routes.get("hosts") is None
        assert tc.routes["targets"] == []

    def test_toml_empty_targets_skips_wizard(self):
        """targets=[] in TOML (native routing saved from wizard) -> wizard NOT called."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": []},
        )
        with patch("tv.ui.wizard_targets") as mock_wizard:
            resolve_tunnel_routes(tc)
        mock_wizard.assert_not_called()
        assert tc.routes["targets"] == []

    def test_toml_targets_loaded(self):
        """Targets from TOML (wizard-saved) loaded without wizard."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": ["10.0.0.0/8", "192.168.1.0/24"]},
        )
        with patch("tv.ui.wizard_targets") as mock_wizard:
            resolve_tunnel_routes(tc)
        mock_wizard.assert_not_called()
        assert "10.0.0.0/8" in tc.routes["networks"]

    @patch("tv.ui.wizard_nameservers", return_value=["10.0.1.1"])
    def test_wizard_asks_nameservers_for_wildcards(self, mock_ns):
        """Wildcard targets + no nameservers -> wizard asks for DNS servers."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": ["*.alpha.local", "10.0.0.0/8"]},
        )
        resolve_tunnel_routes(tc)
        mock_ns.assert_called_once_with(["alpha.local"])
        assert tc.dns["nameservers"] == ["10.0.1.1"]

    def test_existing_nameservers_not_overwritten(self):
        """Existing DNS nameservers -> wizard not called."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": ["*.alpha.local"]},
            dns={"nameservers": ["10.0.1.1"]},
        )
        with patch("tv.ui.wizard_nameservers") as mock_ns:
            resolve_tunnel_routes(tc)
        mock_ns.assert_not_called()
        assert tc.dns["nameservers"] == ["10.0.1.1"]

    def test_saves_targets_back(self):
        """Original targets stored in routes for saving."""
        targets = ["*.alpha.local", "10.0.0.0/8"]
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": targets},
            dns={"nameservers": ["10.0.1.1"]},
        )
        resolve_tunnel_routes(tc)
        assert tc.routes["targets"] == targets

    @patch("tv.ui.wizard_nameservers", return_value=["10.0.1.1"])
    def test_toml_domains_prompt_nameservers(self, mock_ns):
        """Domains in TOML (not from targets) -> wizard asks for nameservers."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"networks": ["10.0.0.0/8"]},  # advanced mode
            dns={"domains": ["alpha.local"]},  # domains but no nameservers
        )
        resolve_tunnel_routes(tc)
        mock_ns.assert_called_once_with(["alpha.local"])
        assert tc.dns["nameservers"] == ["10.0.1.1"]

    def test_toml_domains_with_nameservers_no_prompt(self):
        """Domains + nameservers in TOML -> wizard NOT called."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"networks": ["10.0.0.0/8"]},
            dns={"domains": ["alpha.local"], "nameservers": ["10.0.1.1"]},
        )
        with patch("tv.ui.wizard_nameservers") as mock_ns:
            resolve_tunnel_routes(tc)
        mock_ns.assert_not_called()


# =========================================================================
# prompt=False params (non-interactive resolution)
# =========================================================================


class TestSilentParams:
    def test_fallback_gw_from_env(self):
        """fallback_gateway resolved from ENV without wizard prompt."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "cert_mode": "manual",
                "trusted_cert": "cert",
            },
        )
        with patch.dict(os.environ, {"VPN_FORTI_FALLBACK_GW": "10.0.0.1"}):
            resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"))
        assert tc.extra["fallback_gateway"] == "10.0.0.1"

    def test_fallback_gw_from_toml(self):
        """fallback_gateway in TOML extra -> used as-is."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "cert_mode": "manual",
                "trusted_cert": "cert",
            },
            extra={"fallback_gateway": "10.0.0.1"},
        )
        resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"))
        assert tc.extra["fallback_gateway"] == "10.0.0.1"

    def test_fallback_gw_not_prompted(self):
        """fallback_gateway with no value -> NOT prompted in wizard."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "cert_mode": "manual",
                "trusted_cert": "cert",
            },
        )
        with patch("tv.config.ui.wizard_input") as mock_wizard:
            resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"))
        # wizard_input should NOT be called for fallback_gateway
        for call in mock_wizard.call_args_list:
            assert "Fallback" not in call.args[0]


# =========================================================================
# Quiet mode (all required params set -> quiet)
# =========================================================================


class TestResolveParamQuiet:
    def test_quiet_uses_env(self):
        """quiet=True: ENV value used without prints."""
        with patch.dict(os.environ, {"VPN_TEST": "from_env"}):
            result = _resolve_param("test", env_name="VPN_TEST", quiet=True)
        assert result == "from_env"

    def test_quiet_uses_default(self):
        """quiet=True: default value used without wizard."""
        result = _resolve_param("test", env_name="NOPE", default="def_val", quiet=True)
        assert result == "def_val"

    def test_quiet_raises_on_missing(self):
        """quiet=True: no value anywhere -> SetupRequiredError."""
        with pytest.raises(SetupRequiredError, match="--setup"):
            _resolve_param("Логин", env_name="NOPE", quiet=True)


class TestResolveTunnelRoutesQuiet:
    def test_quiet_skips_wizard(self):
        """quiet=True: no wizard, defaults to native routing."""
        tc = TunnelConfig(name="forti", type="fortivpn")
        with patch("tv.ui.wizard_targets") as mock_wiz:
            resolve_tunnel_routes(tc, quiet=True)
        mock_wiz.assert_not_called()
        assert tc.routes["targets"] == []

    def test_quiet_uses_toml_targets(self):
        """quiet=True: TOML targets resolved without prints."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": ["10.0.0.0/8"]},
        )
        resolve_tunnel_routes(tc, quiet=True)
        assert "10.0.0.0/8" in tc.routes["networks"]

    def test_quiet_uses_toml_routes(self):
        """quiet=True: TOML networks used without prints."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"networks": ["10.0.0.0/8"]},
        )
        resolve_tunnel_routes(tc, quiet=True)
        assert tc.routes["networks"] == ["10.0.0.0/8"]


class TestResolveParamsQuiet:
    def test_quiet_resolves_from_toml(self):
        """quiet=True: params resolved from TOML without prints/wizard."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "user",
                "pass": "secret",
                "cert_mode": "manual",
                "trusted_cert": "abc123",
            },
        )
        resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"), quiet=True)
        assert tc.auth["host"] == "vpn.com"
        assert tc.auth["login"] == "user"

    def test_quiet_raises_on_missing_required(self):
        """quiet=True: required param missing -> SetupRequiredError."""
        tc = TunnelConfig(name="fortivpn", type="fortivpn")
        with pytest.raises(SetupRequiredError):
            resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"), quiet=True)


# =========================================================================
# Setup mode (--setup): wizard shown with current values as defaults
# =========================================================================


class TestResolveTunnelParamsSetup:
    @patch("tv.ui.wizard_input", return_value="")
    def test_setup_shows_wizard_for_toml_values(self, mock_wizard):
        """setup=True: TOML values shown in wizard with current as default."""
        tc = TunnelConfig(
            name="openvpn",
            type="openvpn",
            config_file="my.ovpn",
        )
        resolve_tunnel_params(tc, OpenVPNPlugin, Path("/tmp"), setup=True)
        # wizard_input called for the config_file param
        mock_wizard.assert_called()

    @patch("tv.ui.wizard_input", return_value="new.ovpn")
    def test_setup_overrides_toml_value(self, mock_wizard):
        """setup=True: user types new value -> overrides TOML."""
        tc = TunnelConfig(
            name="openvpn",
            type="openvpn",
            config_file="old.ovpn",
        )
        resolve_tunnel_params(tc, OpenVPNPlugin, Path("/tmp"), setup=True)
        assert tc.config_file == "new.ovpn"

    @patch("tv.ui.wizard_input", return_value="new_user")
    def test_setup_shows_wizard_for_auth_params(self, mock_wizard):
        """setup=True: auth values shown in wizard instead of silently accepted."""
        tc = TunnelConfig(
            name="fortivpn",
            type="fortivpn",
            auth={
                "host": "vpn.com",
                "port": "443",
                "login": "old_user",
                "pass": "secret",
                "cert_mode": "manual",
                "trusted_cert": "abc123",
            },
        )
        resolve_tunnel_params(tc, FortiVPNPlugin, Path("/tmp"), setup=True)
        # wizard_input called for each promptable param
        assert mock_wizard.call_count >= 1


class TestResolveTunnelRoutesSetup:
    @patch("tv.ui.wizard_targets", return_value=["172.16.0.0/12"])
    def test_setup_shows_wizard_for_toml_targets(self, mock_wizard):
        """setup=True: wizard called even when targets in TOML."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": ["10.0.0.0/8"]},
        )
        resolve_tunnel_routes(tc, setup=True)
        mock_wizard.assert_called_once_with("forti", default=["10.0.0.0/8"])
        assert "172.16.0.0/12" in tc.routes["networks"]

    @patch("tv.ui.wizard_targets", return_value=[])
    def test_setup_keeps_empty_on_enter(self, mock_wizard):
        """setup=True: empty wizard input -> native routing."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"targets": ["10.0.0.0/8"]},
        )
        resolve_tunnel_routes(tc, setup=True)
        assert tc.routes["targets"] == []

    def test_setup_skips_wizard_for_advanced_routes(self):
        """setup=True: advanced mode (explicit networks) not overridden by wizard."""
        tc = TunnelConfig(
            name="forti",
            type="fortivpn",
            routes={"networks": ["10.0.0.0/8"]},
        )
        with patch("tv.ui.wizard_targets") as mock_wiz:
            resolve_tunnel_routes(tc, setup=True)
        mock_wiz.assert_not_called()


# =========================================================================
# Log directory and file management
# =========================================================================


class TestResolveLogDir:
    def test_relative_resolves_to_script_dir(self, tmp_dir):
        """Relative log_dir resolves against script_dir."""
        cfg.paths.log_dir = "logs"
        result = resolve_log_dir(tmp_dir)
        assert result == tmp_dir / "logs"

    def test_absolute_stays_absolute(self, tmp_dir):
        """Absolute log_dir is returned as-is."""
        abs_path = str(tmp_dir / "custom_logs")
        cfg.paths.log_dir = abs_path
        result = resolve_log_dir(tmp_dir)
        assert result == Path(abs_path)


class TestEnsureLogDir:
    def test_creates_directory(self, tmp_dir):
        """Creates log directory if it doesn't exist."""
        cfg.paths.log_dir = "logs"
        result = ensure_log_dir(tmp_dir)
        assert result.exists()
        assert result.is_dir()
        assert result == tmp_dir / "logs"

    def test_existing_dir_no_error(self, tmp_dir):
        """No error if directory already exists."""
        (tmp_dir / "logs").mkdir()
        cfg.paths.log_dir = "logs"
        result = ensure_log_dir(tmp_dir)
        assert result.exists()


class TestResolveLogPaths:
    def test_relative_paths_resolved(self, tmp_dir):
        """Relative log paths are resolved against script_dir."""
        cfg.paths.log_dir = "logs"
        tunnels = [
            TunnelConfig(name="t1", type="openvpn", log="logs/openvpn-t1.log"),
        ]
        resolve_log_paths(tunnels, tmp_dir)
        assert tunnels[0].log == str(tmp_dir / "logs" / "openvpn-t1.log")

    def test_absolute_paths_unchanged(self, tmp_dir):
        """Absolute log paths are not modified."""
        cfg.paths.log_dir = "logs"
        abs_log = str(tmp_dir / "my.log")
        tunnels = [
            TunnelConfig(name="t1", type="openvpn", log=abs_log),
        ]
        resolve_log_paths(tunnels, tmp_dir)
        assert tunnels[0].log == abs_log

    def test_empty_log_skipped(self, tmp_dir):
        """Tunnels without log field are skipped."""
        cfg.paths.log_dir = "logs"
        tunnels = [TunnelConfig(name="t1", type="openvpn", log="")]
        resolve_log_paths(tunnels, tmp_dir)
        assert tunnels[0].log == ""


class TestPrepareLogFiles:
    def test_creates_empty_readable_files(self, tmp_dir):
        """Pre-creates log files."""
        log_path = tmp_dir / "logs" / "test.log"
        tunnels = [TunnelConfig(name="t", log=str(log_path))]
        prepare_log_files(tunnels)
        assert log_path.exists()
        assert log_path.read_bytes() == b""
        if __import__("platform").system() != "Windows":
            mode = log_path.stat().st_mode & 0o777
            assert mode == 0o644

    def test_creates_parent_dir(self, tmp_dir):
        """Creates parent directory if it doesn't exist."""
        log_path = tmp_dir / "deep" / "nested" / "test.log"
        tunnels = [TunnelConfig(name="t", log=str(log_path))]
        prepare_log_files(tunnels)
        assert log_path.exists()

    def test_preserves_existing_file(self, tmp_dir):
        """Does not truncate existing log file (may still be in use)."""
        log_path = tmp_dir / "test.log"
        log_path.write_text("old content here")
        tunnels = [TunnelConfig(name="t", log=str(log_path))]
        prepare_log_files(tunnels)
        assert log_path.read_text() == "old content here"

    def test_skips_empty_log(self, tmp_dir):
        """Tunnels without log field are skipped."""
        tunnels = [TunnelConfig(name="t", log="")]
        prepare_log_files(tunnels)  # no crash
