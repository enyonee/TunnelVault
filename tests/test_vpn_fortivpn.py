"""Tests for FortiVPNPlugin: connection with PPP gateway detection."""

from __future__ import annotations

import contextlib
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.fortivpn import (
    FortiVPNPlugin,
    FortiDNSInfo,
    _detect_ppp_gateway,
    parse_forti_dns,
)


@contextlib.contextmanager
def _patch_config_file():
    """Patch os calls for connect() predictable config file."""
    with (
        patch("tv.vpn.fortivpn.os.open", return_value=99),
        patch("tv.vpn.fortivpn.os.write"),
        patch("tv.vpn.fortivpn.os.close"),
        patch("tv.vpn.fortivpn.os.unlink") as mock_unlink,
    ):
        yield mock_unlink


def _setup_mock_net_snapshot(mock_net):
    """Configure mock_net.interfaces() to simulate ppp0 appearing after connect.

    First call returns {en0, lo0} (before snapshot).
    Subsequent calls return {en0, lo0, ppp0} (after connect).
    """
    call_count = 0
    ifaces_before = {"en0": "192.168.1.7", "lo0": "127.0.0.1"}
    ifaces_after = {"en0": "192.168.1.7", "lo0": "127.0.0.1", "ppp0": "10.0.0.2"}

    def _interfaces():
        nonlocal call_count
        call_count += 1
        return ifaces_before if call_count == 1 else ifaces_after

    mock_net.interfaces.side_effect = _interfaces


@pytest.fixture
def forti_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="forti1",
        type="fortivpn",
        order=2,
        log=str(tmp_dir / "openfortivpn.log"),
        auth={
            "host": "vpn.test.local",
            "port": "44333",
            "login": "testuser",
            "pass": "testpass",
            "cert_mode": "manual",
            "trusted_cert": "abcdef1234567890" * 4,
        },
        routes={"networks": ["192.168.100.0/24", "10.0.0.0/8"]},
        dns={
            "nameservers": ["10.0.1.1", "10.0.1.2"],
            "domains": ["alpha.local", "bravo.local"],
        },
        extra={"fallback_gateway": "169.254.2.1"},
    )


@pytest.fixture
def plugin(forti_cfg, mock_net, logger, tmp_dir):
    _setup_mock_net_snapshot(mock_net)
    return FortiVPNPlugin(forti_cfg, mock_net, logger, tmp_dir)


@contextlib.contextmanager
def _forti_connect_ok(plugin, ppp_gw="10.0.0.1"):
    """Set up successful FortiVPN connect: popen(pid=9999), ppp0 detected, ppp_peer returns gw."""
    forti_log = Path(plugin.cfg.log)
    forti_log.parent.mkdir(parents=True, exist_ok=True)
    forti_log.write_text("")
    mock_popen = MagicMock()
    mock_popen.pid = 9999
    with (
        _patch_config_file() as mock_unlink,
        patch("tv.vpn.fortivpn.proc") as mock_proc,
    ):
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()
        plugin.net.iface_info.return_value = "ppp0: flags=8051<UP>"
        plugin.net.ppp_peer.return_value = ppp_gw
        yield mock_proc, mock_unlink


@contextlib.contextmanager
def _forti_connect_fail(plugin, poll=1, is_alive=False):
    """Set up failing FortiVPN connect: popen(pid=9999), wait_for=False."""
    mock_popen = MagicMock()
    mock_popen.pid = 9999
    mock_popen.poll.return_value = poll
    with _patch_config_file(), patch("tv.vpn.fortivpn.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.return_value = False
        mock_proc.is_alive.return_value = is_alive
        yield mock_proc


# =========================================================================
# Meta
# =========================================================================


class TestMeta:
    def test_process_name(self, plugin):
        assert plugin.process_name == "openfortivpn"

    def test_display_name(self, plugin):
        assert plugin.display_name == "FortiVPN"

    def test_registered(self):
        from tv.vpn.registry import get_plugin

        assert get_plugin("fortivpn") is FortiVPNPlugin


# =========================================================================
# Positive: PPP gateway detection
# =========================================================================


class TestDetectPppGateway:
    def test_found_on_first_attempt(self, mock_net):
        """ppp_peer возвращает gateway с первой попытки."""
        mock_net.ppp_peer.return_value = "192.168.100.1"
        gw = _detect_ppp_gateway(mock_net, interface="ppp0")
        assert gw == "192.168.100.1"
        mock_net.ppp_peer.assert_called_once_with("ppp0")

    def test_found_on_second_attempt(self, mock_net):
        """ppp_peer возвращает пустую строку, потом gateway."""
        mock_net.ppp_peer.side_effect = ["", "10.0.0.1"]
        with patch("tv.vpn.fortivpn.time.sleep"):
            gw = _detect_ppp_gateway(mock_net, interface="ppp0")
        assert gw == "10.0.0.1"
        assert mock_net.ppp_peer.call_count == 2

    def test_custom_interface(self, mock_net):
        """Передаётся указанный interface."""
        mock_net.ppp_peer.return_value = "172.16.0.1"
        gw = _detect_ppp_gateway(mock_net, interface="ppp1")
        assert gw == "172.16.0.1"
        mock_net.ppp_peer.assert_called_once_with("ppp1")

    def test_default_interface_is_ppp0(self, mock_net):
        """По умолчанию проверяет ppp0."""
        mock_net.ppp_peer.return_value = "10.0.0.1"
        _detect_ppp_gateway(mock_net)
        mock_net.ppp_peer.assert_called_once_with("ppp0")


# =========================================================================
# Negative / inverse: PPP gateway failures
# =========================================================================


class TestDetectPppGatewayInverse:
    @patch("tv.vpn.fortivpn.time.sleep")
    def test_all_attempts_empty(self, mock_sleep, mock_net):
        """ppp_peer всегда возвращает пустую строку - пустой gateway."""
        mock_net.ppp_peer.return_value = ""
        gw = _detect_ppp_gateway(mock_net, interface="ppp0")
        assert gw == ""

    @patch("tv.vpn.fortivpn.time.sleep")
    def test_sleeps_between_attempts(self, mock_sleep, mock_net):
        """Между попытками вызывается sleep."""
        mock_net.ppp_peer.return_value = ""
        _detect_ppp_gateway(mock_net, interface="ppp0")
        assert mock_sleep.call_count > 0


# =========================================================================
# Positive: full connect flow
# =========================================================================


class TestConnectSuccess:
    def test_successful_connection(self, plugin):
        """Нормальный коннект: ppp interface detected via snapshot, gateway найден."""
        with _forti_connect_ok(plugin):
            r = plugin.connect()

        assert r.ok is True
        assert r.pid == 9999
        assert plugin._pid == 9999
        assert plugin.cfg.interface == "ppp0"

    def test_uses_config_file_not_cli_password(self, plugin):
        """Пароль передаётся через predictable config, а не CLI -p."""
        with _forti_connect_ok(plugin) as (mock_proc, _):
            plugin.connect()
            cmd = mock_proc.run_background.call_args[0][0]
            assert "-c" in cmd
            assert "-p" not in cmd
            assert plugin.cfg.auth["pass"] not in cmd

    def test_predictable_config_path(self, plugin):
        """Config path uses tunnel name, not random tempfile."""
        with _forti_connect_ok(plugin) as (mock_proc, _):
            plugin.connect()
            forti_cmd = mock_proc.run_background.call_args_list[0][0][0]
            assert f"/tmp/forti_{plugin.cfg.name}.conf" in forti_cmd

    def test_sets_network_routes(self, plugin):
        """После коннекта добавляет маршруты через detected interface."""
        with _forti_connect_ok(plugin):
            plugin.connect()

        iface_calls = plugin.net.add_iface_route.call_args_list
        added_targets = [c[0][0] for c in iface_calls]
        for net_route in plugin.cfg.routes["networks"]:
            assert net_route in added_targets

    def test_adds_host_routes_from_targets(self, plugin):
        """После коннекта добавляет host-маршруты через detected interface."""
        plugin.cfg.routes["hosts"] = ["git.test.local", "5.6.7.8"]
        with _forti_connect_ok(plugin):
            plugin.connect()

        iface_calls = plugin.net.add_iface_route.call_args_list
        added_targets = [c[0][0] for c in iface_calls]
        assert "git.test.local" in added_targets
        assert "5.6.7.8" in added_targets

    def test_sets_dns_resolvers(self, plugin):
        """После коннекта настраивает DNS resolver."""
        with _forti_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_called_once()
        domains_arg = plugin.net.setup_dns_resolver.call_args[0][0]
        assert domains_arg == plugin.cfg.dns["domains"]


# =========================================================================
# Negative / inverse: connection failures
# =========================================================================


class TestConnectFailure:
    def test_ppp_timeout(self, plugin, capsys):
        """ppp interface не появляется за 20с -> fail."""
        with _forti_connect_fail(plugin):
            r = plugin.connect()

        assert r.ok is False
        assert r.pid == 9999

    def test_process_alive_but_no_ppp(self, plugin, capsys):
        """Процесс жив, но ppp нет - показывает warning."""
        with _forti_connect_fail(plugin, is_alive=True):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "PID=9999" in out

    def test_process_crashed_shows_exit_code(self, plugin, capsys):
        """Процесс упал - показывает exit code."""
        with _forti_connect_fail(plugin, poll=2):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "2" in out

    def test_shows_log_hint(self, plugin, capsys):
        """При ошибке показывает путь к логу."""
        with _forti_connect_fail(plugin):
            plugin.connect()

        out = capsys.readouterr().out
        assert "openfortivpn.log" in out

    def test_poll_none_shows_question_mark(self, plugin, capsys):
        """poll() возвращает None - показываем '?' вместо None."""
        with _forti_connect_fail(plugin, poll=None):
            plugin.connect()

        out = capsys.readouterr().out
        assert "?" in out
        assert "None" not in out

    def test_no_ppp_gateway_uses_fallback(self, plugin, capsys):
        """Не нашли PPP gateway - используем fallback."""
        with (
            _forti_connect_ok(plugin, ppp_gw=""),
            patch("tv.vpn.fortivpn._detect_ppp_gateway", return_value=""),
        ):
            r = plugin.connect()

        assert r.ok is True
        out = capsys.readouterr().out
        assert "fallback" in out

    def test_no_fallback_gateway(self, plugin, capsys):
        """Нет fallback gateway - warn, но ok."""
        plugin.cfg.extra = {}
        with (
            _forti_connect_ok(plugin, ppp_gw=""),
            patch("tv.vpn.fortivpn._detect_ppp_gateway", return_value=""),
        ):
            r = plugin.connect()

        assert r.ok is True
        out = capsys.readouterr().out
        assert "routes may not work" in out

    def test_empty_dns_skips_resolver(self, tmp_dir, mock_net, logger):
        """Пустые dns domains/nameservers - не вызывает setup_dns_resolver."""
        cfg = TunnelConfig(
            name="nodns",
            type="fortivpn",
            order=2,
            log=str(tmp_dir / "openfortivpn.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "trusted_cert": "abc",
            },
            dns={},  # empty!
        )
        _setup_mock_net_snapshot(mock_net)
        p = FortiVPNPlugin(cfg, mock_net, logger, tmp_dir)

        with _forti_connect_ok(p):
            p.connect()

        mock_net.setup_dns_resolver.assert_not_called()

    def test_config_not_deleted_after_connect(self, plugin):
        """Config file is NOT deleted after connect (kept for disconnect)."""
        with _forti_connect_ok(plugin) as (_, mock_unlink):
            plugin.connect()

        mock_unlink.assert_not_called()


# =========================================================================
# Managed vs native routing mode
# =========================================================================


class TestRoutingMode:
    def test_managed_mode_passes_no_routes(self, plugin):
        """With custom routes/DNS, runs with --no-routes --no-dns."""
        with _forti_connect_ok(plugin) as (mock_proc, _):
            plugin.connect()
            cmd = mock_proc.run_background.call_args_list[0][0][0]
            assert "--no-routes" in cmd
            assert "--no-dns" in cmd

    def test_native_mode_skips_no_routes(self, tmp_dir, mock_net, logger):
        """Without custom routes/DNS, runs without --no-routes --no-dns."""
        cfg = TunnelConfig(
            name="bare",
            type="fortivpn",
            order=2,
            log=str(tmp_dir / "forti.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "trusted_cert": "abc",
            },
            routes={},
            dns={},
        )
        _setup_mock_net_snapshot(mock_net)
        p = FortiVPNPlugin(cfg, mock_net, logger, tmp_dir)

        with _forti_connect_ok(p) as (mock_proc, _):
            r = p.connect()

        cmd = mock_proc.run_background.call_args_list[0][0][0]
        assert "--no-routes" not in cmd
        assert "--no-dns" not in cmd
        assert r.ok is True

    def test_native_mode_skips_add_routes(self, tmp_dir, mock_net, logger):
        """Native mode does not call add_iface_route."""
        cfg = TunnelConfig(
            name="bare",
            type="fortivpn",
            order=2,
            log=str(tmp_dir / "forti.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "trusted_cert": "abc",
            },
            routes={},
            dns={},
        )
        _setup_mock_net_snapshot(mock_net)
        p = FortiVPNPlugin(cfg, mock_net, logger, tmp_dir)

        with _forti_connect_ok(p):
            p.connect()

        mock_net.add_iface_route.assert_not_called()
        mock_net.setup_dns_resolver.assert_not_called()

    def test_routes_only_is_managed(self, tmp_dir, mock_net, logger):
        """Networks without DNS is still managed mode."""
        cfg = TunnelConfig(
            name="routes_only",
            type="fortivpn",
            order=2,
            log=str(tmp_dir / "forti.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "trusted_cert": "abc",
            },
            routes={"networks": ["10.0.0.0/8"]},
            dns={},
        )
        _setup_mock_net_snapshot(mock_net)
        p = FortiVPNPlugin(cfg, mock_net, logger, tmp_dir)

        with _forti_connect_ok(p) as (mock_proc, _):
            p.connect()

        cmd = mock_proc.run_background.call_args_list[0][0][0]
        assert "--no-routes" in cmd
        assert "--no-dns" in cmd


# =========================================================================
# Disconnect
# =========================================================================


class TestPlatformPing:
    """Background ping uses correct flags per platform."""

    @pytest.mark.parametrize(
        "platform_name,flag,absent_flags",
        [
            ("Darwin", "-t", ["-W", "-n"]),
            ("Linux", "-W", ["-t", "-n"]),
            ("Windows", "-n", ["-c"]),
        ],
    )
    def test_ping_uses_platform_flag(self, plugin, platform_name, flag, absent_flags):
        with (
            _forti_connect_ok(plugin) as (mock_proc, _),
            patch("tv.vpn.fortivpn.platform.system", return_value=platform_name),
        ):
            plugin.connect()

        ping_calls = [
            c for c in mock_proc.run_background.call_args_list if c[0][0][0] == "ping"
        ]
        assert len(ping_calls) == 1
        ping_cmd = ping_calls[0][0][0]
        assert flag in ping_cmd
        for absent in absent_flags:
            assert absent not in ping_cmd

    def test_windows_ping_timeout_in_milliseconds(self, plugin):
        """On Windows, -w value is in milliseconds (warmup * 1000)."""
        with (
            _forti_connect_ok(plugin) as (mock_proc, _),
            patch("tv.vpn.fortivpn.platform.system", return_value="Windows"),
        ):
            plugin.connect()

        ping_calls = [
            c for c in mock_proc.run_background.call_args_list if c[0][0][0] == "ping"
        ]
        ping_cmd = ping_calls[0][0][0]
        w_idx = ping_cmd.index("-w")
        w_val = int(ping_cmd[w_idx + 1])
        assert w_val >= 1000


class TestDnsInterface:
    """DNS resolver uses detected ppp interface."""

    def test_dns_passes_detected_interface(self, plugin):
        """setup_dns_resolver called with dynamically detected interface."""
        with _forti_connect_ok(plugin):
            plugin.connect()

        dns_call = plugin.net.setup_dns_resolver.call_args
        assert dns_call is not None
        assert dns_call[0][2] == "ppp0"


# =========================================================================
# Disconnect
# =========================================================================


class TestDisconnect:
    def test_disconnect_by_pid(self, plugin):
        """With PID set, disconnect kills by PID."""
        plugin._pid = 12345
        with patch("tv.vpn.base.proc") as mock_proc, patch("tv.vpn.fortivpn.os.unlink"):
            mock_proc.is_alive.side_effect = [True, False]
            mock_proc.kill_by_pid.return_value = True

            plugin.disconnect()

        mock_proc.kill_by_pid.assert_called_once_with(12345, sudo=True)

    def test_disconnect_fallback_pattern(self, plugin):
        """Without PID, disconnect uses pattern match."""
        plugin._pid = None
        with (
            patch("tv.vpn.fortivpn.proc") as mock_proc,
            patch("tv.vpn.fortivpn.os.unlink"),
        ):
            plugin.disconnect()

        mock_proc.kill_pattern.assert_called_once_with(
            f"openfortivpn -c /tmp/forti_{plugin.cfg.name}.conf", sudo=True
        )

    def test_disconnect_pid_timeout_warns_and_pattern_fallback(self, plugin):
        """PID kill timeout -> warning logged + pattern fallback + config cleaned."""
        plugin._pid = 12345
        plugin._conf_path = "/tmp/forti_forti1.conf"
        with (
            patch("tv.vpn.base.proc") as base_proc,
            patch("tv.vpn.base.time.sleep"),
            patch("tv.vpn.fortivpn.proc") as forti_proc,
            patch("tv.vpn.fortivpn.os.unlink") as mock_unlink,
        ):
            base_proc.is_alive.return_value = True  # never dies
            base_proc.kill_by_pid.return_value = True

            plugin.disconnect()

        # Warning logged
        log_content = plugin.log.log_path.read_text()
        assert "WARN" in log_content
        assert "12345" in log_content
        assert "pattern fallback" in log_content
        # Pattern fallback called
        forti_proc.kill_pattern.assert_called_once()
        # Config cleaned up
        mock_unlink.assert_called_once_with("/tmp/forti_forti1.conf")

    def test_disconnect_cleans_config(self, plugin):
        """Disconnect removes temp config file."""
        plugin._pid = None
        plugin._conf_path = "/tmp/forti_test.conf"
        with (
            patch("tv.vpn.fortivpn.proc"),
            patch("tv.vpn.fortivpn.os.unlink") as mock_unlink,
        ):
            plugin.disconnect()

        mock_unlink.assert_called_once_with("/tmp/forti_test.conf")

    def test_disconnect_ignores_missing_config(self, plugin):
        """Disconnect doesn't crash if config already deleted."""
        plugin._pid = None
        with (
            patch("tv.vpn.fortivpn.proc"),
            patch("tv.vpn.fortivpn.os.unlink", side_effect=OSError),
        ):
            plugin.disconnect()  # no exception

    def test_disconnect_cleans_dns_routes(self, plugin):
        """Disconnect removes DNS server routes."""
        plugin._pid = None
        plugin._dns_routes = ["10.11.1.101", "10.0.0.12"]
        with patch("tv.vpn.fortivpn.proc"), patch("tv.vpn.fortivpn.os.unlink"):
            plugin.disconnect()

        assert plugin.net.delete_host_route.call_count == 2
        deleted = [c[0][0] for c in plugin.net.delete_host_route.call_args_list]
        assert "10.11.1.101" in deleted
        assert "10.0.0.12" in deleted
        assert plugin._dns_routes == []


# =========================================================================
# DNS auto-discovery: log parsing
# =========================================================================


class TestParseFortiDns:
    def test_standard_log_line(self):
        """Standard 'Got addresses' line with two NS and two suffixes."""
        log = "INFO:   Got addresses: [10.212.134.121], ns [10.11.1.101, 10.0.0.12], ns_suffix [new-mmc.com;nmmc.local]"
        result = parse_forti_dns(log)
        assert result == FortiDNSInfo(
            nameservers=["10.11.1.101", "10.0.0.12"],
            suffixes=["new-mmc.com", "nmmc.local"],
        )

    def test_single_nameserver(self):
        """Single nameserver, single suffix."""
        log = "INFO:   Got addresses: [10.0.0.1], ns [8.8.8.8], ns_suffix [corp.local]"
        result = parse_forti_dns(log)
        assert result == FortiDNSInfo(nameservers=["8.8.8.8"], suffixes=["corp.local"])

    def test_empty_ns_and_suffix(self):
        """Empty ns and ns_suffix brackets."""
        log = "INFO:   Got addresses: [10.0.0.1], ns [], ns_suffix []"
        result = parse_forti_dns(log)
        assert result == FortiDNSInfo(nameservers=[], suffixes=[])

    def test_no_match_returns_none(self):
        """Log without 'Got addresses' returns None."""
        log = "INFO:   Connected to gateway.\nINFO:   Tunnel is up and running."
        assert parse_forti_dns(log) is None

    def test_multiline_real_log(self):
        """Realistic multiline openfortivpn log."""
        log = (
            "INFO:   Connected to gateway.\n"
            "INFO:   Got addresses: [10.212.134.121], ns [10.11.1.101, 10.0.0.12], ns_suffix [new-mmc.com;nmmc.local]\n"
            "INFO:   Tunnel is up and running.\n"
            "INFO:   Setting up ppp0 interface.\n"
        )
        result = parse_forti_dns(log)
        assert result is not None
        assert result.nameservers == ["10.11.1.101", "10.0.0.12"]
        assert result.suffixes == ["new-mmc.com", "nmmc.local"]


# =========================================================================
# DNS auto-discovery: config merge
# =========================================================================


class TestDnsAutoDiscovery:
    """_apply_discovered_dns merges log-parsed DNS into config."""

    def _make_plugin_with_log(self, tmp_dir, mock_net, logger, dns, log_content):
        """Create a plugin with a log file containing the given content."""
        tcfg = TunnelConfig(
            name="disc",
            type="fortivpn",
            order=2,
            log=str(tmp_dir / "forti_disc.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "trusted_cert": "abc",
            },
            routes={"networks": ["10.0.0.0/8"]},
            dns=dns,
        )
        _setup_mock_net_snapshot(mock_net)
        p = FortiVPNPlugin(tcfg, mock_net, logger, tmp_dir)
        log_path = Path(tcfg.log)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(log_content)
        return p, log_path

    def test_empty_dns_filled_from_log(self, tmp_dir, mock_net, logger):
        """Empty dns config -> nameservers and domains from log."""
        log = "INFO:   Got addresses: [10.0.0.1], ns [10.11.1.101, 10.0.0.12], ns_suffix [corp.local;dev.local]"
        p, log_path = self._make_plugin_with_log(tmp_dir, mock_net, logger, {}, log)

        p._apply_discovered_dns(log_path)

        assert p.cfg.dns["nameservers"] == ["10.11.1.101", "10.0.0.12"]
        assert p.cfg.dns["domains"] == ["corp.local", "dev.local"]

    def test_manual_nameservers_not_overwritten(self, tmp_dir, mock_net, logger):
        """Manual nameservers preserved, discovery logged but not applied."""
        log = "INFO:   Got addresses: [10.0.0.1], ns [10.11.1.101], ns_suffix [corp.local]"
        dns = {"nameservers": ["1.1.1.1"], "domains": []}
        p, log_path = self._make_plugin_with_log(tmp_dir, mock_net, logger, dns, log)

        p._apply_discovered_dns(log_path)

        assert p.cfg.dns["nameservers"] == ["1.1.1.1"]

    def test_domains_merged(self, tmp_dir, mock_net, logger):
        """Config domains + discovered suffixes merged without duplicates."""
        log = "INFO:   Got addresses: [10.0.0.1], ns [10.11.1.101], ns_suffix [corp.local;dev.local]"
        dns = {"nameservers": [], "domains": ["corp.local", "staging.local"]}
        p, log_path = self._make_plugin_with_log(tmp_dir, mock_net, logger, dns, log)

        p._apply_discovered_dns(log_path)

        domains = p.cfg.dns["domains"]
        assert domains == ["corp.local", "staging.local", "dev.local"]

    def test_no_duplicates_in_domains(self, tmp_dir, mock_net, logger):
        """Identical domains from config and log -> no duplicates."""
        log = "INFO:   Got addresses: [10.0.0.1], ns [10.11.1.101], ns_suffix [alpha.local;bravo.local]"
        dns = {"nameservers": [], "domains": ["alpha.local", "bravo.local"]}
        p, log_path = self._make_plugin_with_log(tmp_dir, mock_net, logger, dns, log)

        p._apply_discovered_dns(log_path)

        assert p.cfg.dns["domains"] == ["alpha.local", "bravo.local"]


# =========================================================================
# DNS routes
# =========================================================================


class TestDnsRoutes:
    def test_dns_routes_added(self, plugin):
        """_add_dns_routes adds host routes for each nameserver."""
        plugin.cfg.dns = {"nameservers": ["10.11.1.101", "10.0.0.12"], "domains": []}

        plugin._add_dns_routes("ppp0")

        calls = plugin.net.add_iface_route.call_args_list
        dns_route_calls = [c for c in calls if c[0][0] in ("10.11.1.101", "10.0.0.12")]
        assert len(dns_route_calls) == 2
        for c in dns_route_calls:
            assert c[0][1] == "ppp0"
            assert c[1]["host"] is True or c[0][2] is True
        assert plugin._dns_routes == ["10.11.1.101", "10.0.0.12"]

    def test_dns_routes_cleaned_on_disconnect(self, plugin):
        """DNS routes added during connect are removed on disconnect."""
        plugin._pid = None
        plugin._dns_routes = ["10.11.1.101", "10.0.0.12"]
        with patch("tv.vpn.fortivpn.proc"), patch("tv.vpn.fortivpn.os.unlink"):
            plugin.disconnect()

        deleted = [c[0][0] for c in plugin.net.delete_host_route.call_args_list]
        assert "10.11.1.101" in deleted
        assert "10.0.0.12" in deleted
