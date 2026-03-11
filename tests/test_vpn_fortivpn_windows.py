"""Tests for FortiVPNPlugin Windows branch: unsupported warning, ping flags."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.fortivpn import FortiVPNPlugin


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
    )


@pytest.fixture
def plugin(forti_cfg, mock_net, logger, tmp_dir):
    return FortiVPNPlugin(forti_cfg, mock_net, logger, tmp_dir)


# =========================================================================
# Windows: unsupported - early return
# =========================================================================


class TestWindowsUnsupported:
    @patch("tv.vpn.fortivpn.IS_WINDOWS", True)
    def test_returns_fail_on_windows(self, plugin):
        """connect() returns VPNResult(ok=False) on Windows."""
        r = plugin.connect()
        assert r.ok is False
        assert "unsupported" in r.detail.lower() or "windows" in r.detail.lower()

    @patch("tv.vpn.fortivpn.IS_WINDOWS", True)
    def test_shows_warning_on_windows(self, plugin, capsys):
        """connect() shows warning about unsupported platform."""
        plugin.connect()
        out = capsys.readouterr().out
        assert "not available" in out.lower() or "windows" in out.lower()

    @patch("tv.vpn.fortivpn.IS_WINDOWS", True)
    def test_does_not_launch_process_on_windows(self, plugin):
        """connect() does not attempt to launch openfortivpn on Windows."""
        with patch("tv.vpn.fortivpn.proc") as mock_proc:
            plugin.connect()

        mock_proc.run_background.assert_not_called()
        mock_proc.run.assert_not_called()

    @patch("tv.vpn.fortivpn.IS_WINDOWS", True)
    def test_logs_warning_on_windows(self, plugin):
        """connect() logs warning about unsupported platform."""
        plugin.connect()
        log_content = plugin.log.log_path.read_text()
        assert "WARN" in log_content
        assert "not available" in log_content.lower() or "Windows" in log_content


# =========================================================================
# Ping warmup: Windows uses -n and -w (milliseconds)
# =========================================================================


class TestWindowsPing:
    def _connect_with_ping(self, plugin, platform_name):
        """Helper: run connect with managed mode (DNS configured) on a given platform."""
        plugin.cfg.dns = {
            "nameservers": ["10.0.1.1"],
            "domains": ["alpha.local"],
        }
        plugin.cfg.routes = {"networks": ["10.0.0.0/8"]}
        plugin.cfg.extra = {"fallback_gateway": "169.254.2.1"}

        call_count = 0
        ifaces_before = {"en0": "192.168.1.7", "lo0": "127.0.0.1"}
        ifaces_after = {"en0": "192.168.1.7", "lo0": "127.0.0.1", "ppp0": "10.0.0.2"}

        def _interfaces():
            nonlocal call_count
            call_count += 1
            return ifaces_before if call_count == 1 else ifaces_after

        plugin.net.interfaces.side_effect = _interfaces
        plugin.net.iface_info.return_value = "ppp0: flags=8051<UP>"
        plugin.net.ppp_peer.return_value = "10.0.0.1"

        mock_popen = MagicMock()
        mock_popen.pid = 9999
        with (
            patch("tv.vpn.fortivpn.os.open", return_value=99),
            patch("tv.vpn.fortivpn.os.write"),
            patch("tv.vpn.fortivpn.os.close"),
            patch("tv.vpn.fortivpn.os.unlink"),
            patch("tv.vpn.fortivpn.proc") as mock_proc,
            patch("tv.vpn.fortivpn.platform.system", return_value=platform_name),
        ):
            mock_proc.run_background.return_value = mock_popen
            mock_proc.wait_for.side_effect = lambda desc, fn, *a, **kw: fn() or fn()
            plugin.connect()
            return mock_proc

    def test_windows_ping_uses_n_and_w_milliseconds(self, plugin):
        """On Windows, ping uses -n (count) and -w (timeout in ms)."""
        mock_proc = self._connect_with_ping(plugin, "Windows")
        ping_calls = [
            c for c in mock_proc.run_background.call_args_list if c[0][0][0] == "ping"
        ]
        assert len(ping_calls) == 1
        ping_cmd = ping_calls[0][0][0]
        assert "-n" in ping_cmd
        assert "-w" in ping_cmd
        assert "-c" not in ping_cmd
        # -w value should be in milliseconds (warmup * 1000)
        w_idx = ping_cmd.index("-w")
        w_val = int(ping_cmd[w_idx + 1])
        assert w_val >= 1000  # at least 1 second in ms

    def test_darwin_ping_uses_c_and_t(self, plugin):
        """On Darwin, ping uses -c (count) and -t (timeout in seconds)."""
        mock_proc = self._connect_with_ping(plugin, "Darwin")
        ping_calls = [
            c for c in mock_proc.run_background.call_args_list if c[0][0][0] == "ping"
        ]
        assert len(ping_calls) == 1
        ping_cmd = ping_calls[0][0][0]
        assert "-c" in ping_cmd
        assert "-t" in ping_cmd
        assert "-n" not in ping_cmd

    def test_linux_ping_uses_c_and_W(self, plugin):
        """On Linux, ping uses -c (count) and -W (timeout in seconds)."""
        mock_proc = self._connect_with_ping(plugin, "Linux")
        ping_calls = [
            c for c in mock_proc.run_background.call_args_list if c[0][0][0] == "ping"
        ]
        assert len(ping_calls) == 1
        ping_cmd = ping_calls[0][0][0]
        assert "-c" in ping_cmd
        assert "-W" in ping_cmd
        assert "-n" not in ping_cmd


# =========================================================================
# kill_patterns uses dynamic temp_dir
# =========================================================================


class TestKillPatterns:
    def test_kill_patterns_use_cfg_temp_dir(self):
        """kill_patterns should reference cfg.paths.temp_dir, not hardcoded /tmp."""
        from tv.app_config import cfg

        pattern = FortiVPNPlugin.kill_patterns[0]
        assert cfg.paths.temp_dir in pattern
        assert "openfortivpn" in pattern
