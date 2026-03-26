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
