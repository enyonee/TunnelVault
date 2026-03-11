"""Tests for SingBoxPlugin: sing-box connection."""

from __future__ import annotations

import contextlib
import platform
from unittest.mock import patch, MagicMock

import pytest

from tv.vpn.base import TunnelConfig
from tv.vpn.singbox import SingBoxPlugin

pytestmark = pytest.mark.skipif(
    platform.system() == "Windows", reason="sing-box plugin is Unix-only"
)


@contextlib.contextmanager
def _singbox_connect_ok(plugin):
    """Set up successful sing-box connect: popen(pid=5555), interface up."""
    mock_popen = MagicMock()
    mock_popen.pid = 5555
    with patch("tv.vpn.singbox.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.return_value = True
        plugin.net.check_interface.return_value = True
        plugin.net.iface_info.return_value = "utun99: flags=8051<UP>"
        yield mock_proc


@contextlib.contextmanager
def _singbox_connect_fail(plugin, poll=1, is_alive=False):
    """Set up failing sing-box connect: popen(pid=5555), wait_for=False."""
    mock_popen = MagicMock()
    mock_popen.pid = 5555
    mock_popen.poll.return_value = poll
    with patch("tv.vpn.singbox.proc") as mock_proc:
        mock_proc.run_background.return_value = mock_popen
        mock_proc.wait_for.return_value = False
        mock_proc.is_alive.return_value = is_alive
        yield mock_proc


@pytest.fixture
def singbox_cfg(tmp_dir) -> TunnelConfig:
    return TunnelConfig(
        name="singbox",
        type="singbox",
        order=3,
        config_file="singbox.json",
        log=str(tmp_dir / "sing-box.log"),
        interface="utun99",
        routes={
            "hosts": ["203.0.113.30"],
            "networks": ["172.18.0.0/16"],
        },
    )


@pytest.fixture
def plugin(singbox_cfg, mock_net, logger, tmp_dir):
    return SingBoxPlugin(singbox_cfg, mock_net, logger, tmp_dir)


# =========================================================================
# Meta
# =========================================================================


class TestMeta:
    def test_process_name(self, plugin):
        assert plugin.process_name == "sing-box"

    def test_display_name(self, plugin):
        assert plugin.display_name == "sing-box"

    def test_registered(self):
        from tv.vpn.registry import get_plugin

        assert get_plugin("singbox") is SingBoxPlugin


# =========================================================================
# Positive: successful connection
# =========================================================================


class TestConnectSuccess:
    def test_normal_connection(self, plugin):
        """sing-box запускается, utun99 появляется, маршруты добавлены."""
        with _singbox_connect_ok(plugin):
            r = plugin.connect()

        assert r.ok is True
        assert r.pid == 5555

    def test_adds_routes_from_config(self, plugin):
        """Добавляет host и network маршруты из TunnelConfig."""
        with _singbox_connect_ok(plugin):
            plugin.connect()

        route_calls = plugin.net.add_iface_route.call_args_list
        targets = [c[0][0] for c in route_calls]
        assert "203.0.113.30" in targets
        assert "172.18.0.0/16" in targets

    def test_sets_up_dns_from_config(self, plugin):
        """DNS resolver set up from TunnelConfig.dns."""
        plugin.cfg.dns = {"nameservers": ["10.0.1.1"], "domains": ["alpha.local"]}
        with _singbox_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_called_once_with(
            ["alpha.local"],
            ["10.0.1.1"],
            "utun99",
        )

    def test_no_dns_when_not_configured(self, plugin):
        """No DNS setup when dns is empty."""
        plugin.cfg.dns = {}
        with _singbox_connect_ok(plugin):
            plugin.connect()

        plugin.net.setup_dns_resolver.assert_not_called()

    def test_launches_with_sudo(self, plugin):
        """sing-box запускается с sudo."""
        with _singbox_connect_ok(plugin) as mock_proc:
            plugin.connect()

        bg_call = mock_proc.run_background.call_args
        assert bg_call[1].get("sudo") is True


# =========================================================================
# Negative / inverse: connection failures
# =========================================================================


class TestConnectFailure:
    def test_interface_timeout(self, plugin, capsys):
        """Интерфейс не появляется за 15с -> fail."""
        with _singbox_connect_fail(plugin):
            r = plugin.connect()

        assert r.ok is False
        assert r.pid == 5555

    def test_process_alive_but_no_interface(self, plugin, capsys):
        """Процесс жив, но интерфейс не появился."""
        with _singbox_connect_fail(plugin, is_alive=True):
            r = plugin.connect()

        assert r.ok is False
        out = capsys.readouterr().out
        assert "PID=5555" in out

    def test_poll_none_shows_question_mark(self, plugin, capsys):
        """poll() возвращает None - показываем '?'."""
        with _singbox_connect_fail(plugin, poll=None):
            plugin.connect()

        out = capsys.readouterr().out
        assert "?" in out
        assert "None" not in out

    def test_shows_log_hint(self, plugin, capsys):
        """При ошибке показывает путь к логу."""
        with _singbox_connect_fail(plugin):
            plugin.connect()

        out = capsys.readouterr().out
        assert "sing-box.log" in out


# =========================================================================
# Disconnect
# =========================================================================


class TestDisconnect:
    def test_disconnect_by_pid(self, plugin):
        """With PID set, disconnect kills by PID first."""
        plugin._pid = 5555
        with patch("tv.vpn.base.proc") as mock_proc:
            mock_proc.is_alive.side_effect = [True, False]
            mock_proc.kill_by_pid.return_value = True

            plugin.disconnect()

        mock_proc.kill_by_pid.assert_called_once_with(5555, sudo=True)

    def test_disconnect_fallback_pattern(self, plugin):
        """Without PID, disconnect uses per-instance pattern."""
        plugin._pid = None
        with patch("tv.vpn.singbox.proc") as mock_proc:
            plugin.disconnect()

        mock_proc.kill_pattern.assert_called_once()
        pattern = mock_proc.kill_pattern.call_args[0][0]
        assert "sing-box run -c" in pattern
        assert "singbox.json" in pattern

    def test_disconnect_pid_timeout_warns_and_falls_through(self, plugin):
        """PID kill timeout -> warning logged + pattern fallback."""
        plugin._pid = 5555
        with (
            patch("tv.vpn.base.proc") as base_proc,
            patch("tv.vpn.base.time.sleep"),
            patch("tv.vpn.singbox.proc") as sb_proc,
        ):
            base_proc.is_alive.return_value = True  # never dies
            base_proc.kill_by_pid.return_value = True

            plugin.disconnect()

        # Warning logged to file
        log_content = plugin.log.log_path.read_text()
        assert "WARN" in log_content
        assert "5555" in log_content
        assert "pattern fallback" in log_content
        # Pattern fallback called
        sb_proc.kill_pattern.assert_called_once()

    def test_disconnect_pattern_per_config(self, plugin):
        """Different config = different kill pattern."""
        plugin.cfg.config_file = "custom-sb.json"
        plugin._pid = None
        with patch("tv.vpn.singbox.proc") as mock_proc:
            plugin.disconnect()

        pattern = mock_proc.kill_pattern.call_args[0][0]
        assert "custom-sb.json" in pattern
        assert "singbox.json" not in pattern


# =========================================================================
# Resolved defaults: connect uses cfg directly
# =========================================================================


class TestResolvedDefaults:
    def test_connect_uses_resolved_interface(self, plugin):
        """connect() takes interface from cfg directly (no fallback)."""
        plugin.cfg.interface = "utun100"
        with _singbox_connect_ok(plugin) as mock_proc:
            plugin.net.iface_info.return_value = "utun100: flags=8051<UP>"
            r = plugin.connect()

        assert r.ok is True
        wait_call = mock_proc.wait_for.call_args
        assert "utun100" in wait_call[0][0]

    def test_connect_uses_resolved_config(self, plugin):
        """connect() takes config_file from cfg directly (no fallback)."""
        plugin.cfg.config_file = "my-singbox.json"
        (plugin.script_dir / "my-singbox.json").write_text("{}")
        with _singbox_connect_ok(plugin) as mock_proc:
            plugin.connect()

        bg_call = mock_proc.run_background.call_args[0][0]
        assert any("my-singbox.json" in str(arg) for arg in bg_call)

    def test_connect_config_not_found(self, plugin):
        """connect() fails immediately if config file does not exist."""
        plugin.cfg.config_file = "nonexistent.json"
        r = plugin.connect()
        assert r.ok is False
        assert r.detail == "config not found"
