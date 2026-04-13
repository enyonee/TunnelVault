"""Tests for proxy mode: config patching, port check, system proxy."""

from __future__ import annotations

import json
import os
import platform
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tv.app_config import reset


@pytest.fixture(autouse=True)
def _reset_config():
    reset()
    yield
    reset()


class TestPatchForProxy:
    """Test sing-box config patching for proxy mode."""

    def test_replaces_tun_with_mixed(self, tmp_path):
        from tv.vpn.singbox import _patch_for_proxy

        config = {
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "utun98",
                    "inet4_address": "172.19.0.1/28",
                    "auto_route": True,
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
        }
        config_path = tmp_path / "test.json"
        config_path.write_text(json.dumps(config))

        log = MagicMock()
        result = _patch_for_proxy(config_path, 1080, log)

        assert result is not None
        patched = json.loads(Path(result).read_text())

        # TUN inbound removed, mixed added
        inbound_types = [ib["type"] for ib in patched["inbounds"]]
        assert "tun" not in inbound_types
        assert "mixed" in inbound_types

        mixed = next(ib for ib in patched["inbounds"] if ib["type"] == "mixed")
        assert mixed["listen"] == "127.0.0.1"
        assert mixed["listen_port"] == 1080

        os.unlink(result)

    def test_preserves_non_tun_inbounds(self, tmp_path):
        from tv.vpn.singbox import _patch_for_proxy

        config = {
            "inbounds": [
                {"type": "tun", "tag": "tun-in"},
                {"type": "dns", "tag": "dns-in", "listen": "127.0.0.1"},
            ],
            "outbounds": [{"type": "direct"}],
        }
        config_path = tmp_path / "test.json"
        config_path.write_text(json.dumps(config))

        result = _patch_for_proxy(config_path, 1080, MagicMock())
        patched = json.loads(Path(result).read_text())

        types = [ib["type"] for ib in patched["inbounds"]]
        assert "dns" in types
        assert "mixed" in types
        assert "tun" not in types

        os.unlink(result)

    def test_custom_port(self, tmp_path):
        from tv.vpn.singbox import _patch_for_proxy

        config = {"inbounds": [{"type": "tun"}], "outbounds": [{"type": "direct"}]}
        config_path = tmp_path / "test.json"
        config_path.write_text(json.dumps(config))

        result = _patch_for_proxy(config_path, 8080, MagicMock())
        patched = json.loads(Path(result).read_text())

        mixed = patched["inbounds"][0]
        assert mixed["listen_port"] == 8080

        os.unlink(result)

    def test_invalid_json_returns_none(self, tmp_path):
        from tv.vpn.singbox import _patch_for_proxy

        config_path = tmp_path / "bad.json"
        config_path.write_text("not json")

        result = _patch_for_proxy(config_path, 1080, MagicMock())
        assert result is None

    def test_missing_file_returns_none(self, tmp_path):
        from tv.vpn.singbox import _patch_for_proxy

        result = _patch_for_proxy(tmp_path / "nope.json", 1080, MagicMock())
        assert result is None


class TestPatchAddProxyInbound:
    """Test adding mixed inbound alongside TUN for --proxy mode."""

    def test_adds_mixed_keeps_tun(self, tmp_path):
        from tv.vpn.singbox import _patch_add_proxy_inbound

        config = {
            "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "utun98"}],
            "outbounds": [{"type": "direct"}],
        }
        config_path = tmp_path / "test.json"
        config_path.write_text(json.dumps(config))

        result = _patch_add_proxy_inbound(config_path, 1080, MagicMock())
        assert result is not None
        patched = json.loads(Path(result).read_text())

        types = [ib["type"] for ib in patched["inbounds"]]
        assert "tun" in types
        assert "mixed" in types

        mixed = next(ib for ib in patched["inbounds"] if ib["type"] == "mixed")
        assert mixed["listen_port"] == 1080
        assert mixed["listen"] == "127.0.0.1"

        os.unlink(result)

    def test_replaces_existing_mixed(self, tmp_path):
        from tv.vpn.singbox import _patch_add_proxy_inbound

        config = {
            "inbounds": [
                {"type": "tun", "tag": "tun-in"},
                {"type": "mixed", "tag": "old-proxy", "listen_port": 9999},
            ],
            "outbounds": [{"type": "direct"}],
        }
        config_path = tmp_path / "test.json"
        config_path.write_text(json.dumps(config))

        result = _patch_add_proxy_inbound(config_path, 1080, MagicMock())
        patched = json.loads(Path(result).read_text())

        mixed_inbounds = [ib for ib in patched["inbounds"] if ib["type"] == "mixed"]
        assert len(mixed_inbounds) == 1
        assert mixed_inbounds[0]["listen_port"] == 1080

        os.unlink(result)

    def test_invalid_json_returns_none(self, tmp_path):
        from tv.vpn.singbox import _patch_add_proxy_inbound

        config_path = tmp_path / "bad.json"
        config_path.write_text("not json")

        result = _patch_add_proxy_inbound(config_path, 1080, MagicMock())
        assert result is None


class TestCheckPortListening:
    def test_listening_port(self):
        from tv.vpn.singbox import _check_port_listening

        # Bind a temporary server
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)
        try:
            assert _check_port_listening(port)
        finally:
            srv.close()

    def test_closed_port(self):
        from tv.vpn.singbox import _check_port_listening

        # Use a port that's very unlikely to be listening
        assert not _check_port_listening(19999)


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="networksetup is macOS only",
)
class TestSystemProxy:
    def test_setup_calls_networksetup(self):
        from tv.net import DarwinNet

        net = DarwinNet()
        with patch("tv.net._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Wi-Fi\n")
            net.setup_system_proxy(1080)

        # Should call networksetup for web, secure web, and socks
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("setwebproxy" in c and "1080" in c for c in calls)
        assert any("setsecurewebproxy" in c and "1080" in c for c in calls)
        assert any("setsocksfirewallproxy" in c and "1080" in c for c in calls)

    def test_cleanup_calls_networksetup_off(self):
        from tv.net import DarwinNet

        net = DarwinNet()
        with patch("tv.net._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Wi-Fi\n")
            net.cleanup_system_proxy()

        calls = [str(c) for c in mock_run.call_args_list]
        assert any("setwebproxystate" in c and "off" in c for c in calls)
        assert any("setsecurewebproxystate" in c and "off" in c for c in calls)
        assert any("setsocksfirewallproxystate" in c and "off" in c for c in calls)


class TestLinuxSystemProxy:
    """Test LinuxNet.setup_system_proxy / cleanup_system_proxy."""

    def test_setup_with_gsettings(self):
        from tv.net import LinuxNet

        net = LinuxNet()
        with (
            patch("tv.net.shutil.which", return_value="/usr/bin/gsettings"),
            patch("tv.net._run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            result = net.setup_system_proxy(1080)

        assert result is True
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("org.gnome.system.proxy" in c and "manual" in c for c in calls)
        assert any("org.gnome.system.proxy.http" in c and "1080" in c for c in calls)
        assert any("org.gnome.system.proxy.https" in c and "1080" in c for c in calls)
        assert any("org.gnome.system.proxy.socks" in c and "1080" in c for c in calls)

    def test_setup_fallback_env(self):
        from tv.net import LinuxNet

        net = LinuxNet()
        with (
            patch("tv.net.shutil.which", return_value=None),
            patch("tv.net._run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            result = net.setup_system_proxy(8080)

        assert result is True
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("tee" in c and "/etc/environment" in c for c in calls)

    def test_cleanup_with_gsettings(self):
        from tv.net import LinuxNet

        net = LinuxNet()
        with (
            patch("tv.net.shutil.which", return_value="/usr/bin/gsettings"),
            patch("tv.net._run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            result = net.cleanup_system_proxy()

        assert result is True
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("org.gnome.system.proxy" in c and "none" in c for c in calls)


class TestLinuxEnvProxy:
    """Test _write_env_proxy / _remove_env_proxy helpers."""

    def test_remove_cleans_markers(self, tmp_path):
        from tv.net import _remove_env_proxy

        env_file = tmp_path / "environment"
        env_file.write_text(
            "PATH=/usr/bin\n"
            "# tunnelvault-proxy\n"
            'http_proxy="http://127.0.0.1:1080/"\n'
            "# tunnelvault-proxy-end\n"
            "OTHER=val\n"
        )
        with patch("tv.net._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            # Patch the file path
            with patch(
                "builtins.open",
                side_effect=lambda f, *a, **kw: (
                    env_file.open(*a, **kw)
                    if f == "/etc/environment"
                    else open(f, *a, **kw)
                ),
            ):
                result = _remove_env_proxy()

        assert result is True
        # Verify tee was called with cleaned content (no proxy lines)
        tee_call = mock_run.call_args
        input_data = tee_call.kwargs.get("input", "")
        assert "tunnelvault-proxy" not in input_data
        assert "http_proxy" not in input_data
        assert "PATH=/usr/bin" in input_data
        assert "OTHER=val" in input_data

    def test_remove_noop_when_no_markers(self):
        from tv.net import _remove_env_proxy

        with patch(
            "builtins.open",
            side_effect=lambda f, *a, **kw: (
                __import__("io").StringIO("PATH=/usr/bin\n")
                if f == "/etc/environment"
                else open(f, *a, **kw)
            ),
        ):
            result = _remove_env_proxy()

        assert result is True

    def test_remove_noop_when_no_file(self):
        from tv.net import _remove_env_proxy

        with patch("builtins.open", side_effect=OSError("not found")):
            result = _remove_env_proxy()

        assert result is True


class TestWindowsSystemProxy:
    """Test WindowsNet.setup_system_proxy / cleanup_system_proxy."""

    def test_setup_calls_netsh_and_registry(self):
        from tv.net import WindowsNet

        net = WindowsNet()
        with patch("tv.net._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = net.setup_system_proxy(1080)

        assert result is True
        calls = [str(c) for c in mock_run.call_args_list]
        assert any(
            "netsh" in c and "winhttp" in c and "set" in c and "proxy" in c
            for c in calls
        )
        assert any("ProxyServer" in c and "127.0.0.1:1080" in c for c in calls)
        assert any("ProxyEnable" in c and "1" in c for c in calls)

    def test_cleanup_resets_proxy(self):
        from tv.net import WindowsNet

        net = WindowsNet()
        with patch("tv.net._run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = net.cleanup_system_proxy()

        assert result is True
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("netsh" in c and "winhttp" in c and "reset" in c for c in calls)
        assert any("ProxyEnable" in c and "0" in c for c in calls)

    def test_setup_ok_if_either_succeeds(self):
        """Even if netsh fails, registry success is enough."""
        from tv.net import WindowsNet

        net = WindowsNet()
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            rc = 1 if call_count[0] == 1 else 0  # netsh fails, powershell ok
            return MagicMock(returncode=rc)

        with patch("tv.net._run", side_effect=side_effect):
            result = net.setup_system_proxy(1080)

        assert result is True
