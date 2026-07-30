"""Tests for OpenConnectPlugin: connection with TUN gateway detection."""

from __future__ import annotations

import contextlib
import platform
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.openconnect import (
    OpenConnectPlugin,
    parse_openconnect_output,
)

pytestmark = pytest.mark.skipif(
    platform.system() == "Windows", reason="OpenConnect is Unix-only"
)


def _setup_mock_net_snapshot(mock_net, is_macos=False):
    """Configure mock_net.interfaces() to simulate tun0/utun appearing after connect.

    First call returns {en0, lo0} (before snapshot).
    Subsequent calls return {en0, lo0, tun0} or {en0, lo0, utun3} (after connect).
    """
    call_count = 0
    ifaces_before = {"en0": "192.168.1.7", "lo0": "127.0.0.1"}
    tun_name = "utun3" if is_macos else "tun0"
    ifaces_after = {"en0": "192.168.1.7", "lo0": "127.0.0.1", tun_name: "10.0.0.2"}

    def _interfaces():
        nonlocal call_count
        call_count += 1
        return ifaces_before if call_count == 1 else ifaces_after

    mock_net.interfaces.side_effect = _interfaces


@pytest.fixture
def oc_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="oc1",
        type="openconnect",
        order=2,
        log=str(tmp_dir / "openconnect.log"),
        auth={
            "host": "vpn.test.local",
            "port": "443",
            "login": "testuser",
            "pass": "testpass",
            "protocol": "fortinet",
            "cert_mode": "pin",
            "servercert": "sha256:abcdef1234567890" * 2,
        },
        routes={"networks": ["192.168.100.0/24", "10.0.0.0/8"]},
        dns={
            "nameservers": ["10.0.1.1", "10.0.1.2"],
            "domains": ["alpha.local", "bravo.local"],
        },
    )


@pytest.fixture
def plugin(oc_cfg, mock_net, logger, tmp_dir):
    _setup_mock_net_snapshot(mock_net, is_macos=platform.system() == "Darwin")
    return OpenConnectPlugin(oc_cfg, mock_net, logger, tmp_dir)


_real_open = open  # capture before builtins.open gets patched


@contextlib.contextmanager
def _oc_connect_ok(plugin):
    """Set up successful OpenConnect connect: popen(pid=9999), tun0/utun detected."""
    oc_log = Path(plugin.cfg.log)
    oc_log.parent.mkdir(parents=True, exist_ok=True)
    # Realistic openconnect output with DNS/gateway info
    oc_log.write_text(
        "Connected to HTTPS on vpn.test.local with ciphersuite (TLS1.3)...\n"
        "Got address: 10.212.1.55\n"
        "Got DNS 10.0.0.53\n"
        "Got DNS 10.0.0.54\n"
        "Got search domain corp.local\n"
        "Got search domain internal.company.com\n"
        "CSTP connected. DPD 60, Keepalive 30\n"
        "Connected as 10.212.1.55, using SSL, with DTLS + LZS\n"
    )

    mock_popen = MagicMock()
    mock_popen.pid = 9999
    mock_popen.stdin = MagicMock()

    with (
        patch("tv.vpn.openconnect.subprocess.Popen", return_value=mock_popen),
        patch("tv.vpn.openconnect.proc") as mock_proc,
        patch("builtins.open", side_effect=lambda *a, **kw: _real_open(*a, **kw)),
    ):
        mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()
        plugin.net.iface_info.return_value = "tun0: flags=8051<UP>"
        yield mock_proc


@contextlib.contextmanager
def _oc_connect_fail(plugin, poll=1, is_alive=False):
    """Set up failing OpenConnect connect: popen(pid=9999), wait_for=False."""
    mock_popen = MagicMock()
    mock_popen.pid = 9999
    mock_popen.poll.return_value = poll
    mock_popen.stdin = MagicMock()

    with (
        patch("tv.vpn.openconnect.subprocess.Popen", return_value=mock_popen),
        patch("tv.vpn.openconnect.proc") as mock_proc,
        patch("builtins.open", side_effect=lambda *a, **kw: _real_open(*a, **kw)),
    ):
        mock_proc.wait_for.return_value = False
        mock_proc.is_alive.return_value = is_alive
        yield mock_proc


# =========================================================================
# Meta
# =========================================================================


class TestMeta:
    def test_process_name(self, plugin):
        assert plugin.process_name == "openconnect"

    def test_display_name(self, plugin):
        assert plugin.display_name == "OpenConnect"

    def test_registered(self):
        from tv.vpn.registry import get_plugin

        assert get_plugin("openconnect") is OpenConnectPlugin


# =========================================================================
# Parsing: openconnect output
# =========================================================================


class TestParseOpenConnectOutput:
    def test_standard_output(self):
        """Standard openconnect output with address, DNS, domains."""
        output = (
            "Connected to HTTPS on vpn.company.com with ciphersuite (TLS1.3)...\n"
            "Got address: 10.212.1.55\n"
            "Got DNS 10.0.0.53\n"
            "Got DNS 10.0.0.54\n"
            "Got search domain corp.local\n"
            "Got search domain internal.company.com\n"
            "CSTP connected. DPD 60, Keepalive 30\n"
            "Connected as 10.212.1.55, using SSL, with DTLS + LZS\n"
        )
        result = parse_openconnect_output(output)
        assert result is not None
        assert result.address == "10.212.1.55"
        assert result.nameservers == ["10.0.0.53", "10.0.0.54"]
        assert result.search_domains == ["corp.local", "internal.company.com"]
        assert result.connected is True

    def test_single_dns(self):
        """Single DNS server, single search domain."""
        output = (
            "Got address: 10.0.0.1\n"
            "Got DNS 8.8.8.8\n"
            "Got search domain example.com\n"
            "Connected as 10.0.0.1\n"
        )
        result = parse_openconnect_output(output)
        assert result is not None
        assert result.nameservers == ["8.8.8.8"]
        assert result.search_domains == ["example.com"]
        assert result.connected is True

    def test_no_dns_or_domains(self):
        """Address only, no DNS or search domains."""
        output = "Got address: 10.0.0.1\n"
        result = parse_openconnect_output(output)
        assert result is not None
        assert result.address == "10.0.0.1"
        assert result.nameservers == []
        assert result.search_domains == []
        assert result.connected is False

    def test_no_address_returns_none(self):
        """Output without 'Got address' returns None."""
        output = "Connecting...\nEstablishing SSL connection...\n"
        result = parse_openconnect_output(output)
        assert result is None

    def test_multiline_real_log(self):
        """Realistic multiline openconnect log."""
        output = (
            "Connected to HTTPS on vpn.test.local\n"
            "Got address: 10.212.134.121\n"
            "Got DNS 10.11.1.101\n"
            "Got DNS 10.0.0.12\n"
            "Got search domain new-mmc.com\n"
            "Got search domain nmmc.local\n"
            "CSTP connected.\n"
            "Connected as 10.212.134.121\n"
        )
        result = parse_openconnect_output(output)
        assert result is not None
        assert result.address == "10.212.134.121"
        assert result.nameservers == ["10.11.1.101", "10.0.0.12"]
        assert result.search_domains == ["new-mmc.com", "nmmc.local"]
        assert result.connected is True


# =========================================================================
# Positive: full connect flow
# =========================================================================


class TestConnectSuccess:
    def test_successful_connection(self, plugin):
        """Normal connect: tun interface detected via snapshot."""
        with _oc_connect_ok(plugin):
            r = plugin.connect()

        assert r.ok is True
        assert r.pid == 9999
        assert plugin._pid == 9999
        expected_iface = "utun3" if platform.system() == "Darwin" else "tun0"
        assert plugin.cfg.interface == expected_iface

    def test_password_via_stdin(self, plugin):
        """Password sent through stdin pipe, not CLI args."""
        with _oc_connect_ok(plugin):
            plugin.connect()
            # Password written to stdin and closed
            # Mock would have been called with password

    def test_cli_args_structure(self, plugin):
        """CLI args include --protocol, -u, --passwd-on-stdin."""
        with (
            _oc_connect_ok(plugin),
            patch("tv.vpn.openconnect.subprocess.Popen") as mock_popen,
        ):
            plugin.connect()
            cmd = mock_popen.call_args[0][0]
            assert "openconnect" in cmd
            assert "vpn.test.local:443" in cmd
            assert "--protocol=fortinet" in cmd
            assert "-u" in cmd
            assert "testuser" in cmd
            assert "--passwd-on-stdin" in cmd

    def test_pin_cert_mode(self, plugin):
        """cert_mode=pin adds --servercert."""
        with (
            _oc_connect_ok(plugin),
            patch("tv.vpn.openconnect.subprocess.Popen") as mock_popen,
        ):
            plugin.connect()
            cmd = mock_popen.call_args[0][0]
            servercert_arg = [arg for arg in cmd if arg.startswith("--servercert=")]
            assert len(servercert_arg) == 1
            assert "sha256:abcdef" in servercert_arg[0]

    def test_system_cert_mode(self, tmp_dir, mock_net, logger):
        """cert_mode=system omits --servercert."""
        cfg = TunnelConfig(
            name="sys_cert",
            type="openconnect",
            order=2,
            log=str(tmp_dir / "openconnect.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "user",
                "pass": "pass",
                "protocol": "fortinet",
                "cert_mode": "system",
            },
        )
        _setup_mock_net_snapshot(mock_net, is_macos=platform.system() == "Darwin")
        p = OpenConnectPlugin(cfg, mock_net, logger, tmp_dir)

        with (
            _oc_connect_ok(p),
            patch("tv.vpn.openconnect.subprocess.Popen") as mock_popen,
        ):
            p.connect()
            cmd = mock_popen.call_args[0][0]
            servercert_args = [arg for arg in cmd if arg.startswith("--servercert")]
            assert len(servercert_args) == 0

    def test_sets_network_routes(self, plugin):
        """After connect adds routes via interface."""
        with _oc_connect_ok(plugin):
            plugin.connect()

        iface_calls = plugin.net.add_iface_route.call_args_list
        added_targets = [c[0][0] for c in iface_calls]
        for net_route in plugin.cfg.routes["networks"]:
            assert net_route in added_targets

    def test_adds_host_routes(self, plugin):
        """After connect adds host routes via interface."""
        plugin.cfg.routes["hosts"] = ["git.test.local", "5.6.7.8"]
        with _oc_connect_ok(plugin):
            plugin.connect()

        iface_calls = plugin.net.add_iface_route.call_args_list
        added_targets = [c[0][0] for c in iface_calls]
        assert "git.test.local" in added_targets
        assert "5.6.7.8" in added_targets

    def test_sets_dns_resolvers(self, plugin):
        """After connect sets up DNS resolver."""
        with _oc_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_called_once()
        domains_arg = plugin.net.setup_dns_resolver.call_args[0][0]
        assert domains_arg == plugin.cfg.dns["domains"]

    @patch("tv.vpn.openconnect.platform.system", return_value="Darwin")
    def test_macos_utun_detection(self, mock_platform, tmp_dir, mock_net, logger):
        """On macOS, detects utun interface instead of tun."""
        cfg = TunnelConfig(
            name="macos",
            type="openconnect",
            order=2,
            log=str(tmp_dir / "openconnect.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "user",
                "pass": "pass",
                "protocol": "fortinet",
                "cert_mode": "pin",
                "servercert": "sha256:abc",
            },
            routes={"networks": ["10.0.0.0/8"]},
            dns={"nameservers": ["10.0.1.1"], "domains": ["test.local"]},
        )
        _setup_mock_net_snapshot(mock_net, is_macos=True)
        p = OpenConnectPlugin(cfg, mock_net, logger, tmp_dir)

        with _oc_connect_ok(p):
            r = p.connect()

        assert r.ok is True
        assert p.cfg.interface == "utun3"


# =========================================================================
# Negative / inverse: connection failures
# =========================================================================


class TestConnectFailure:
    def test_tun_timeout(self, plugin, capsys):
        """tun interface doesn't appear -> fail."""
        with _oc_connect_fail(plugin):
            r = plugin.connect()

        assert r.ok is False
        assert r.pid == 9999

    def test_process_alive_but_no_tun(self, plugin, capsys):
        """Process alive but tun doesn't appear - shows warning."""
        with _oc_connect_fail(plugin, is_alive=True):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "PID=9999" in out

    def test_process_crashed_shows_exit_code(self, plugin, capsys):
        """Process crashed - shows exit code."""
        with _oc_connect_fail(plugin, poll=2):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "2" in out

    def test_shows_log_hint(self, plugin, capsys):
        """On error shows log path."""
        with _oc_connect_fail(plugin):
            plugin.connect()

        out = capsys.readouterr().out
        assert "openconnect.log" in out

    def test_poll_none_shows_question_mark(self, plugin, capsys):
        """poll() returns None - show '?' instead of None."""
        with _oc_connect_fail(plugin, poll=None):
            plugin.connect()

        out = capsys.readouterr().out
        assert "?" in out
        assert "None" not in out

    def test_empty_dns_skips_resolver(self, tmp_dir, mock_net, logger):
        """Empty dns domains/nameservers - doesn't call setup_dns_resolver."""
        cfg = TunnelConfig(
            name="nodns",
            type="openconnect",
            order=2,
            log=str(tmp_dir / "openconnect.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "pin",
                "servercert": "abc",
            },
            dns={},  # empty!
        )
        _setup_mock_net_snapshot(mock_net, is_macos=platform.system() == "Darwin")
        p = OpenConnectPlugin(cfg, mock_net, logger, tmp_dir)

        with _oc_connect_ok(p):
            p.connect()

        mock_net.setup_dns_resolver.assert_not_called()


# =========================================================================
# Managed vs native routing mode
# =========================================================================


class TestRoutingMode:
    def test_managed_mode_adds_custom_routes(self, plugin):
        """With custom routes/DNS, adds routes via interface after connect."""
        with _oc_connect_ok(plugin):
            plugin.connect()

        iface_calls = plugin.net.add_iface_route.call_args_list
        added_targets = [c[0][0] for c in iface_calls]
        for net in plugin.cfg.routes["networks"]:
            assert net in added_targets

    def test_native_mode_skips_custom_routes(self, tmp_dir, mock_net, logger):
        """Without custom routes/DNS, no add_iface_route calls."""
        cfg = TunnelConfig(
            name="bare",
            type="openconnect",
            order=2,
            log=str(tmp_dir / "oc.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "pin",
                "servercert": "abc",
            },
            routes={},
            dns={},
        )
        _setup_mock_net_snapshot(mock_net, is_macos=platform.system() == "Darwin")
        p = OpenConnectPlugin(cfg, mock_net, logger, tmp_dir)

        with _oc_connect_ok(p):
            r = p.connect()

        assert r.ok is True
        # Native mode: no custom routes added by tunnelvault
        mock_net.add_iface_route.assert_not_called()

    def test_native_mode_skips_add_routes(self, tmp_dir, mock_net, logger):
        """Native mode does not call add_iface_route."""
        cfg = TunnelConfig(
            name="bare",
            type="openconnect",
            order=2,
            log=str(tmp_dir / "oc.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "pin",
                "servercert": "abc",
            },
            routes={},
            dns={},
        )
        _setup_mock_net_snapshot(mock_net, is_macos=platform.system() == "Darwin")
        p = OpenConnectPlugin(cfg, mock_net, logger, tmp_dir)

        with _oc_connect_ok(p):
            p.connect()

        mock_net.add_iface_route.assert_not_called()
        mock_net.setup_dns_resolver.assert_not_called()

    def test_routes_only_is_managed(self, tmp_dir, mock_net, logger):
        """Networks without DNS still adds custom routes."""
        cfg = TunnelConfig(
            name="routes_only",
            type="openconnect",
            order=2,
            log=str(tmp_dir / "oc.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "pin",
                "servercert": "abc",
            },
            routes={"networks": ["10.0.0.0/8"]},
            dns={},
        )
        _setup_mock_net_snapshot(mock_net, is_macos=platform.system() == "Darwin")
        p = OpenConnectPlugin(cfg, mock_net, logger, tmp_dir)

        with _oc_connect_ok(p):
            p.connect()

        iface_calls = p.net.add_iface_route.call_args_list
        added = [c[0][0] for c in iface_calls]
        assert "10.0.0.0/8" in added


# =========================================================================
# Platform ping
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
    def test_ping_uses_platform_flag(
        self, oc_cfg, mock_net, logger, tmp_dir, platform_name, flag, absent_flags
    ):
        is_macos = platform_name == "Darwin"
        _setup_mock_net_snapshot(mock_net, is_macos=is_macos)
        p = OpenConnectPlugin(oc_cfg, mock_net, logger, tmp_dir)

        with (
            _oc_connect_ok(p) as mock_proc,
            patch("tv.vpn.openconnect.platform.system", return_value=platform_name),
        ):
            p.connect()

        ping_calls = [
            c for c in mock_proc.run_background.call_args_list if c[0][0][0] == "ping"
        ]
        assert len(ping_calls) == 1
        ping_cmd = ping_calls[0][0][0]
        assert flag in ping_cmd
        for absent in absent_flags:
            assert absent not in ping_cmd


# =========================================================================
# DNS auto-discovery
# =========================================================================


class TestDnsAutoDiscovery:
    """_apply_discovered_dns merges log-parsed DNS into config."""

    def _make_plugin_with_log(self, tmp_dir, mock_net, logger, dns, log_content):
        """Create a plugin with a log file containing the given content."""
        tcfg = TunnelConfig(
            name="disc",
            type="openconnect",
            order=2,
            log=str(tmp_dir / "oc_disc.log"),
            auth={
                "host": "vpn.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "pin",
                "servercert": "abc",
            },
            routes={"networks": ["10.0.0.0/8"]},
            dns=dns,
        )
        _setup_mock_net_snapshot(mock_net, is_macos=platform.system() == "Darwin")
        p = OpenConnectPlugin(tcfg, mock_net, logger, tmp_dir)
        log_path = Path(tcfg.log)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(log_content)
        return p, log_path

    def test_empty_dns_filled_from_log(self, tmp_dir, mock_net, logger):
        """Empty dns config -> nameservers and domains from log."""
        log = (
            "Got address: 10.0.0.1\n"
            "Got DNS 10.11.1.101\n"
            "Got DNS 10.0.0.12\n"
            "Got search domain corp.local\n"
            "Got search domain dev.local\n"
        )
        p, log_path = self._make_plugin_with_log(tmp_dir, mock_net, logger, {}, log)

        p._apply_discovered_dns(log_path)

        assert p.cfg.dns["nameservers"] == ["10.11.1.101", "10.0.0.12"]
        assert p.cfg.dns["domains"] == ["corp.local", "dev.local"]

    def test_manual_nameservers_not_overwritten(self, tmp_dir, mock_net, logger):
        """Manual nameservers preserved, discovery logged but not applied."""
        log = (
            "Got address: 10.0.0.1\nGot DNS 10.11.1.101\nGot search domain corp.local\n"
        )
        dns = {"nameservers": ["1.1.1.1"], "domains": []}
        p, log_path = self._make_plugin_with_log(tmp_dir, mock_net, logger, dns, log)

        p._apply_discovered_dns(log_path)

        assert p.cfg.dns["nameservers"] == ["1.1.1.1"]

    def test_domains_merged(self, tmp_dir, mock_net, logger):
        """Config domains + discovered suffixes merged without duplicates."""
        log = (
            "Got address: 10.0.0.1\n"
            "Got DNS 10.11.1.101\n"
            "Got search domain corp.local\n"
            "Got search domain dev.local\n"
        )
        dns = {"nameservers": [], "domains": ["corp.local", "staging.local"]}
        p, log_path = self._make_plugin_with_log(tmp_dir, mock_net, logger, dns, log)

        p._apply_discovered_dns(log_path)

        domains = p.cfg.dns["domains"]
        assert domains == ["corp.local", "staging.local", "dev.local"]

    def test_no_duplicates_in_domains(self, tmp_dir, mock_net, logger):
        """Identical domains from config and log -> no duplicates."""
        log = (
            "Got address: 10.0.0.1\n"
            "Got DNS 10.11.1.101\n"
            "Got search domain alpha.local\n"
            "Got search domain bravo.local\n"
        )
        dns = {"nameservers": [], "domains": ["alpha.local", "bravo.local"]}
        p, log_path = self._make_plugin_with_log(tmp_dir, mock_net, logger, dns, log)

        p._apply_discovered_dns(log_path)

        assert p.cfg.dns["domains"] == ["alpha.local", "bravo.local"]


# =========================================================================
# Disconnect
# =========================================================================


class TestDisconnect:
    def test_disconnect_sends_sigint_first(self, plugin):
        """Disconnect sends SIGINT for graceful shutdown."""
        plugin._pid = 12345
        with (
            patch("tv.vpn.openconnect.proc") as mock_proc,
            patch("tv.vpn.openconnect.os.kill") as mock_kill,
            patch("tv.vpn.openconnect.time.sleep"),
        ):
            mock_proc.is_alive.side_effect = [True, False]  # alive, then dies
            plugin.disconnect()

        # SIGINT sent
        import signal

        mock_kill.assert_called_once_with(12345, signal.SIGINT)

    def test_disconnect_fallback_to_sigterm(self, plugin):
        """If SIGINT doesn't work, falls back to SIGTERM."""
        plugin._pid = 12345
        with (
            patch("tv.vpn.base.proc") as base_proc,
            patch("tv.vpn.openconnect.proc") as oc_proc,
            patch("tv.vpn.openconnect.os.kill"),
            patch("tv.vpn.openconnect.time.sleep"),
        ):
            oc_proc.is_alive.return_value = True  # still alive after SIGINT
            base_proc.is_alive.return_value = True
            base_proc.kill_by_pid.return_value = False

            plugin.disconnect()

        # SIGTERM fallback called
        base_proc.kill_by_pid.assert_called_once_with(12345, sudo=True)

    def test_disconnect_fallback_pattern(self, plugin):
        """Without PID, disconnect uses pattern match."""
        plugin._pid = None
        with patch("tv.vpn.openconnect.proc") as mock_proc:
            plugin.disconnect()

        mock_proc.kill_pattern.assert_called_once()
        pattern = mock_proc.kill_pattern.call_args[0][0]
        assert "openconnect" in pattern
        assert "fortinet" in pattern
        assert plugin.cfg.auth["host"] in pattern


class TestPostResolveParams:
    """Tests for cert_mode=auto in OpenConnectPlugin.post_resolve_params."""

    def test_auto_cert_generated(self):
        """cert_mode=auto triggers SPKI pin generation."""
        tc = TunnelConfig(
            name="oc1",
            type="openconnect",
            auth={
                "host": "vpn.test.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "auto",
            },
        )
        with patch(
            "tv.vpn.openconnect.generate_spki_pin",
            return_value="pin-sha256:AABBCCDD==",
        ):
            OpenConnectPlugin.post_resolve_params(tc, quiet=True)
        assert tc.auth["servercert"] == "pin-sha256:AABBCCDD=="

    def test_auto_cert_existing_not_overwritten(self):
        """cert_mode=auto with servercert already set skips generation."""
        tc = TunnelConfig(
            name="oc1",
            type="openconnect",
            auth={
                "host": "vpn.test.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "auto",
                "servercert": "sha256:existing",
            },
        )
        with patch(
            "tv.vpn.openconnect.generate_spki_pin",
        ) as mock_gen:
            OpenConnectPlugin.post_resolve_params(tc, quiet=True)
        mock_gen.assert_not_called()
        assert tc.auth["servercert"] == "sha256:existing"

    def test_pin_mode_skips_generation(self):
        """cert_mode=pin does not trigger auto-generation."""
        tc = TunnelConfig(
            name="oc1",
            type="openconnect",
            auth={
                "host": "vpn.test.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "pin",
            },
        )
        with patch(
            "tv.vpn.openconnect.generate_spki_pin",
        ) as mock_gen:
            OpenConnectPlugin.post_resolve_params(tc, quiet=True)
        mock_gen.assert_not_called()

    def test_auto_cert_from_env(self):
        """cert_mode=auto with VPN_SERVERCERT env uses env value."""
        import os

        tc = TunnelConfig(
            name="oc1",
            type="openconnect",
            auth={
                "host": "vpn.test.com",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "auto",
            },
        )
        with (
            patch.dict(os.environ, {"VPN_SERVERCERT": "sha256:env_cert"}),
            patch("tv.vpn.openconnect.generate_spki_pin") as mock_gen,
        ):
            OpenConnectPlugin.post_resolve_params(tc, quiet=True)
        mock_gen.assert_not_called()
        assert tc.auth["servercert"] == "sha256:env_cert"

    def test_auto_cert_unreachable(self):
        """cert_mode=auto with unreachable host shows warning."""
        tc = TunnelConfig(
            name="oc1",
            type="openconnect",
            auth={
                "host": "unreachable.test",
                "port": "443",
                "login": "u",
                "pass": "p",
                "protocol": "fortinet",
                "cert_mode": "auto",
            },
        )
        with patch(
            "tv.vpn.openconnect.generate_spki_pin",
            return_value="",
        ):
            OpenConnectPlugin.post_resolve_params(tc, quiet=False)
        assert not tc.auth.get("servercert")


# =========================================================================
# discover_pid / _kill_by_pattern: шаблон должен совпадать с реальным argv
# =========================================================================


# Реальная командная строка: хост идёт ДО --protocol
_REAL_ARGV = (
    "openconnect vpn.test.local:443 --protocol=fortinet "
    "-u testuser --passwd-on-stdin --servercert=pin-sha256:AbC123"
)


class TestDiscoverPidPattern:
    def test_pattern_matches_real_argv(self, oc_cfg, tmp_dir):
        import re

        captured: dict[str, str] = {}

        def _fake_find_pids(pattern: str) -> list[int]:
            captured["pattern"] = pattern
            return [4242]

        with patch("tv.vpn.openconnect.proc.find_pids", _fake_find_pids):
            pid = OpenConnectPlugin.discover_pid(oc_cfg, tmp_dir)

        assert pid == 4242
        assert re.search(captured["pattern"], _REAL_ARGV), (
            f"шаблон {captured['pattern']!r} не матчит реальный argv"
        )

    def test_no_host_returns_none(self, oc_cfg, tmp_dir):
        oc_cfg.auth["host"] = ""
        assert OpenConnectPlugin.discover_pid(oc_cfg, tmp_dir) is None

    def test_kill_pattern_matches_real_argv(self, plugin):
        import re

        captured: dict[str, str] = {}

        def _fake_kill(pattern: str, sudo: bool = False) -> None:
            captured["pattern"] = pattern

        with patch("tv.vpn.openconnect.proc.kill_pattern", _fake_kill):
            plugin._kill_by_pattern()

        assert re.search(captured["pattern"], _REAL_ARGV), (
            f"шаблон {captured['pattern']!r} не матчит реальный argv"
        )
