"""Integration tests for proxy mode (--proxy and --proxy-only).

Tests verify that sing-box mixed inbound actually accepts connections
and proxies traffic. Uses direct outbound (no SS server needed).
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
from pathlib import Path

import pytest

from tv.vpn.singbox import _patch_add_proxy_inbound

pytestmark = pytest.mark.network

PROXY_PORT = 11080  # avoid conflict with anything on 1080


@pytest.fixture
def singbox_proxy_config(tmp_path: Path) -> Path:
    """Sing-box config with mixed inbound + direct outbound."""
    config_path = tmp_path / "sb-proxy-test.json"
    config_path.write_text(
        json.dumps(
            {
                "log": {"level": "info"},
                "inbounds": [
                    {
                        "type": "mixed",
                        "tag": "proxy-in",
                        "listen": "127.0.0.1",
                        "listen_port": PROXY_PORT,
                    }
                ],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"final": "direct"},
            },
            indent=2,
        )
    )
    return config_path


@pytest.fixture
def singbox_tun_config(tmp_path: Path) -> Path:
    """Sing-box config with TUN inbound + direct outbound (for --proxy patching)."""
    config_path = tmp_path / "sb-tun-test.json"
    config_path.write_text(
        json.dumps(
            {
                "log": {"level": "info"},
                "inbounds": [
                    {
                        "type": "tun",
                        "tag": "tun-in",
                        "interface_name": "tun-test",
                        "address": ["172.19.0.1/30"],
                        "auto_route": False,
                        "stack": "system",
                    }
                ],
                "outbounds": [{"type": "direct", "tag": "direct"}],
                "route": {"final": "direct"},
            },
            indent=2,
        )
    )
    return config_path


def _wait_port(port: int, timeout: int = 15) -> bool:
    """Wait for port to start listening."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except (ConnectionRefusedError, TimeoutError, OSError):
            time.sleep(0.5)
    return False


# =========================================================================
# Proxy-only mode: sing-box with mixed inbound
# =========================================================================


class TestProxyOnly:
    """Test --proxy-only mode: sing-box listens on proxy port."""

    def test_proxy_port_listens(self, singbox_proxy_config):
        """sing-box with mixed inbound actually listens on the port."""
        proc = subprocess.Popen(
            ["sing-box", "run", "-c", str(singbox_proxy_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            assert _wait_port(PROXY_PORT), f"Port {PROXY_PORT} not listening after 15s"
        finally:
            proc.kill()
            proc.wait()

    def test_socks5_proxy_works(self, singbox_proxy_config):
        """SOCKS5 request through sing-box proxy reaches the internet."""
        proc = subprocess.Popen(
            ["sing-box", "run", "-c", str(singbox_proxy_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            assert _wait_port(PROXY_PORT)
            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "--max-time",
                    "10",
                    "--proxy",
                    f"socks5://127.0.0.1:{PROXY_PORT}",
                    "https://ifconfig.me",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert result.returncode == 0, (
                f"curl failed (rc={result.returncode}): {result.stderr}"
            )
            assert result.stdout.strip(), "No IP returned"
        finally:
            proc.kill()
            proc.wait()

    def test_socks5_proxy_multiple_requests(self, singbox_proxy_config):
        """Multiple sequential requests through same proxy work."""
        proc = subprocess.Popen(
            ["sing-box", "run", "-c", str(singbox_proxy_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            assert _wait_port(PROXY_PORT)
            for url in ["https://ifconfig.me", "https://google.com"]:
                result = subprocess.run(
                    [
                        "curl",
                        "-s",
                        "--max-time",
                        "10",
                        "--proxy",
                        f"socks5://127.0.0.1:{PROXY_PORT}",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                assert result.returncode == 0, (
                    f"curl to {url} failed (rc={result.returncode})"
                )
        finally:
            proc.kill()
            proc.wait()


# =========================================================================
# TUN + Proxy mode: patched config has both inbounds
# =========================================================================


class TestProxyPlusTun:
    """Test --proxy mode: TUN + mixed inbound in same config."""

    def test_patched_config_has_both_inbounds(self, singbox_tun_config, test_logger):
        """_patch_add_proxy_inbound adds mixed alongside TUN."""
        patched = _patch_add_proxy_inbound(singbox_tun_config, PROXY_PORT, test_logger)
        assert patched is not None

        data = json.loads(Path(patched).read_text())
        types = [ib["type"] for ib in data["inbounds"]]
        assert "tun" in types
        assert "mixed" in types

        mixed = next(ib for ib in data["inbounds"] if ib["type"] == "mixed")
        assert mixed["listen_port"] == PROXY_PORT

        Path(patched).unlink()

    def test_proxy_works_with_patched_tun_config(
        self, singbox_tun_config, test_logger, requires_tun
    ):
        """Patched config: proxy port listens even with TUN inbound present."""
        patched = _patch_add_proxy_inbound(singbox_tun_config, PROXY_PORT, test_logger)
        assert patched is not None

        proc = subprocess.Popen(
            ["sudo", "sing-box", "run", "-c", patched],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            assert _wait_port(PROXY_PORT), f"Port {PROXY_PORT} not listening"

            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "--max-time",
                    "10",
                    "--proxy",
                    f"socks5://127.0.0.1:{PROXY_PORT}",
                    "https://ifconfig.me",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert result.returncode == 0, f"curl through proxy failed: {result.stderr}"
        finally:
            subprocess.run(
                ["sudo", "kill", str(proc.pid)], check=False, capture_output=True
            )
            proc.wait()
            Path(patched).unlink(missing_ok=True)
