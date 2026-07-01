"""Tests for IPsecPlugin: IPsec/IKEv2 connection via strongSwan (swanctl)."""

from __future__ import annotations

import contextlib
from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.ipsec import IPsecPlugin


@contextlib.contextmanager
def _ipsec_connect_ok(plugin, *, connection="vpn"):
    """Set up successful swanctl connect: load-all ok, initiate ok, SA established."""
    mock_load = MagicMock()
    mock_load.returncode = 0
    mock_init = MagicMock()
    mock_init.returncode = 0
    mock_sas = MagicMock()
    mock_sas.returncode = 0
    mock_sas.stdout = f"  {connection}: IKEv2, established"

    with patch("tv.vpn.ipsec.proc") as mock_proc:
        mock_proc.run.side_effect = [mock_load, mock_init, mock_sas]
        mock_proc.wait_for.return_value = True
        mock_proc.find_pids.return_value = [5555]
        yield mock_proc


@contextlib.contextmanager
def _ipsec_connect_fail_load(plugin, stderr=""):
    """Set up failing swanctl --load-all: returns non-zero exit code."""
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = stderr
    with patch("tv.vpn.ipsec.proc") as mock_proc:
        mock_proc.run.return_value = mock_result
        yield mock_proc


@contextlib.contextmanager
def _ipsec_connect_fail_initiate(plugin, stderr=""):
    """Set up: load-all ok but initiate fails."""
    mock_load = MagicMock()
    mock_load.returncode = 0
    mock_init = MagicMock()
    mock_init.returncode = 1
    mock_init.stderr = stderr
    with patch("tv.vpn.ipsec.proc") as mock_proc:
        mock_proc.run.side_effect = [mock_load, mock_init]
        yield mock_proc


@contextlib.contextmanager
def _ipsec_connect_fail_sa(plugin):
    """Set up: load-all ok, initiate ok, but SA never established."""
    mock_load = MagicMock()
    mock_load.returncode = 0
    mock_init = MagicMock()
    mock_init.returncode = 0
    with patch("tv.vpn.ipsec.proc") as mock_proc:
        mock_proc.run.side_effect = [mock_load, mock_init]
        mock_proc.wait_for.return_value = False
        yield mock_proc


@pytest.fixture
def ipsec_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="ipsec",
        type="ipsec",
        order=5,
        config_file="swanctl.conf",
        log=str(tmp_dir / "ipsec.log"),
        interface="",
        routes={
            "hosts": ["10.0.0.1"],
            "networks": ["10.0.0.0/24"],
        },
        extra={"connection": "vpn"},
    )


@pytest.fixture
def plugin(ipsec_cfg, mock_net, logger, tmp_dir):
    return IPsecPlugin(ipsec_cfg, mock_net, logger, tmp_dir)


# =========================================================================
# Meta
# =========================================================================


class TestMeta:
    def test_process_name(self, plugin):
        assert plugin.process_name == "charon"

    def test_display_name(self, plugin):
        assert plugin.display_name == "IPsec"

    def test_registered(self):
        from tv.vpn.registry import get_plugin

        assert get_plugin("ipsec") is IPsecPlugin

    def test_binary(self):
        assert IPsecPlugin.binary == "swanctl"

    def test_type_display_name(self):
        assert IPsecPlugin.type_display_name == "IPsec"

    def test_emergency_patterns(self, tmp_dir):
        assert "charon" in IPsecPlugin.emergency_patterns(tmp_dir)


# =========================================================================
# Positive: successful connection
# =========================================================================


class TestConnectSuccess:
    def test_normal_connection(self, plugin):
        """swanctl --load-all ok, --initiate ok, SA established."""
        with _ipsec_connect_ok(plugin):
            r = plugin.connect()

        assert r.ok is True
        assert r.pid == 5555

    def test_adds_routes_with_interface(self, plugin):
        """Routes added via interface when interface is set."""
        plugin.cfg.interface = "ipsec0"
        with _ipsec_connect_ok(plugin):
            plugin.connect()

        route_calls = plugin.net.add_iface_route.call_args_list
        targets = [c[0][0] for c in route_calls]
        assert "10.0.0.1" in targets
        assert "10.0.0.0/24" in targets

    def test_sets_up_dns_from_config(self, plugin):
        """DNS resolver set up from TunnelConfig.dns."""
        plugin.cfg.interface = "ipsec0"
        plugin.cfg.dns = {"nameservers": ["10.0.1.1"], "domains": ["corp.local"]}
        with _ipsec_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_called_once_with(
            ["corp.local"],
            ["10.0.1.1"],
            "ipsec0",
            gateway_host="",
        )

    def test_no_dns_when_not_configured(self, plugin):
        """No DNS setup when dns is empty."""
        plugin.cfg.dns = {}
        with _ipsec_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_not_called()

    def test_load_all_uses_sudo(self, plugin):
        """swanctl --load-all runs with sudo."""
        with _ipsec_connect_ok(plugin) as mock_proc:
            plugin.connect()

        load_call = mock_proc.run.call_args_list[0]
        assert load_call[1].get("sudo") is True

    def test_initiate_uses_sudo(self, plugin):
        """swanctl --initiate runs with sudo."""
        with _ipsec_connect_ok(plugin) as mock_proc:
            plugin.connect()

        init_call = mock_proc.run.call_args_list[1]
        assert init_call[1].get("sudo") is True


# =========================================================================
# Negative: connection failures
# =========================================================================


class TestConnectFailure:
    def test_load_all_fails(self, plugin, capsys):
        """swanctl --load-all returns non-zero exit code."""
        with _ipsec_connect_fail_load(plugin):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "exit code 1" in out or "kod 1" in out.lower() or "code 1" in out.lower()

    def test_initiate_fails(self, plugin, capsys):
        """swanctl --initiate returns non-zero exit code."""
        with _ipsec_connect_fail_initiate(plugin):
            r = plugin.connect()

        assert r.ok is False

    def test_sa_not_established(self, plugin, capsys):
        """SA never established within timeout."""
        with _ipsec_connect_fail_sa(plugin):
            r = plugin.connect()

        assert r.ok is False

    def test_shows_config_hint_on_load_fail(self, plugin, capsys):
        """On load-all failure, shows config path hint."""
        with _ipsec_connect_fail_load(plugin):
            plugin.connect()

        out = capsys.readouterr().out
        assert "swanctl.conf" in out

    def test_shows_stderr_on_load_fail(self, plugin, capsys):
        """On load-all failure, shows last line of stderr."""
        with _ipsec_connect_fail_load(plugin, stderr="Line 1\ncould not load config"):
            plugin.connect()

        out = capsys.readouterr().out
        assert "could not load config" in out

    def test_shows_stderr_on_initiate_fail(self, plugin, capsys):
        """On initiate failure, shows last line of stderr."""
        with _ipsec_connect_fail_initiate(
            plugin, stderr="Line 1\nestablishing connection failed"
        ):
            plugin.connect()

        out = capsys.readouterr().out
        assert "establishing connection failed" in out


# =========================================================================
# Disconnect
# =========================================================================


class TestDisconnect:
    def test_disconnect_uses_swanctl_terminate(self, plugin):
        """disconnect() calls swanctl --terminate --ike <connection>."""
        with patch("tv.vpn.ipsec.proc") as mock_proc:
            plugin.disconnect()

        cmd = mock_proc.run.call_args[0][0]
        assert cmd[0] == "swanctl"
        assert cmd[1] == "--terminate"
        assert cmd[2] == "--ike"
        assert cmd[3] == "vpn"
        assert mock_proc.run.call_args[1].get("sudo") is True

    def test_disconnect_custom_connection(self, plugin):
        """Different connection name = different --ike argument."""
        plugin.cfg.extra["connection"] = "office"
        with patch("tv.vpn.ipsec.proc") as mock_proc:
            plugin.disconnect()

        cmd = mock_proc.run.call_args[0][0]
        assert cmd[3] == "office"

    def test_kill_by_pattern(self, plugin):
        """_kill_by_pattern kills charon."""
        with patch("tv.vpn.ipsec.proc") as mock_proc:
            plugin._kill_by_pattern()

        mock_proc.kill_pattern.assert_called_once_with("charon", sudo=True)


# =========================================================================
# Resolved defaults: connect uses cfg directly
# =========================================================================


class TestResolvedDefaults:
    def test_connect_uses_resolved_config(self, plugin):
        """connect() takes config_file from cfg directly."""
        plugin.cfg.config_file = "my-ipsec.conf"
        with _ipsec_connect_ok(plugin) as mock_proc:
            plugin.connect()

        load_call = mock_proc.run.call_args_list[0][0][0]
        assert any("my-ipsec.conf" in str(arg) for arg in load_call)

    def test_connect_uses_resolved_connection(self, plugin):
        """connect() takes connection from cfg.extra directly."""
        plugin.cfg.extra["connection"] = "office"
        with _ipsec_connect_ok(plugin, connection="office") as mock_proc:
            plugin.connect()

        init_call = mock_proc.run.call_args_list[1][0][0]
        assert "office" in init_call

    def test_config_schema_params(self):
        """Config schema returns config_file and connection params."""
        schema = IPsecPlugin.config_schema()
        assert len(schema) == 2
        keys = [p.key for p in schema]
        assert "config_file" in keys
        assert "connection" in keys

    def test_config_schema_config_file(self):
        """config_file param has correct env_var and target."""
        schema = IPsecPlugin.config_schema()
        cf = next(p for p in schema if p.key == "config_file")
        assert cf.env_var == "VPN_IPSEC_CONFIG"
        assert cf.target == "config_file"

    def test_config_schema_connection(self):
        """connection param has correct env_var and target."""
        schema = IPsecPlugin.config_schema()
        conn = next(p for p in schema if p.key == "connection")
        assert conn.env_var == "VPN_IPSEC_CONNECTION"
        assert conn.target == "extra"

    def test_discover_pid_finds_charon(self, ipsec_cfg, tmp_dir):
        """discover_pid finds charon process."""
        with patch("tv.vpn.ipsec.proc") as mock_proc:
            mock_proc.find_pids.return_value = [1234]
            pid = IPsecPlugin.discover_pid(ipsec_cfg, tmp_dir)

        assert pid == 1234

    def test_discover_pid_returns_none(self, ipsec_cfg, tmp_dir):
        """discover_pid returns None when no charon process."""
        with patch("tv.vpn.ipsec.proc") as mock_proc:
            mock_proc.find_pids.return_value = []
            pid = IPsecPlugin.discover_pid(ipsec_cfg, tmp_dir)

        assert pid is None
