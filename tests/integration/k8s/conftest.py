"""Fixtures for K8s integration tests with real VPN servers.

These tests run inside a privileged K8s pod with NET_ADMIN capability.
VPN servers (OpenVPN, ocserv, sing-box) must be running in the test-vpn namespace.
Environment variables provide server addresses and credentials.
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from tv.logger import Logger
from tv.net import NetManager


def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        pytest.skip(f"Missing env var {name} - not in K8s test environment")
    return val


@pytest.fixture(scope="session")
def openvpn_server() -> str:
    return _require_env("OPENVPN_SERVER")


@pytest.fixture(scope="session")
def ocserv_host() -> str:
    return _require_env("OCSERV_HOST")


@pytest.fixture(scope="session")
def ocserv_port() -> str:
    return _require_env("OCSERV_PORT")


@pytest.fixture(scope="session")
def ocserv_user() -> str:
    return _require_env("OCSERV_USER")


@pytest.fixture(scope="session")
def ocserv_pass() -> str:
    return _require_env("OCSERV_PASS")


@pytest.fixture(scope="session")
def singbox_server() -> str:
    return _require_env("SINGBOX_SERVER")


@pytest.fixture(scope="session")
def singbox_ss_port() -> str:
    return _require_env("SINGBOX_SS_PORT")


@pytest.fixture(scope="session")
def singbox_ss_password() -> str:
    return _require_env("SINGBOX_SS_PASSWORD")


@pytest.fixture
def real_net() -> NetManager:
    """Real NetManager for the current platform (Linux in K8s)."""
    return NetManager.create()


@pytest.fixture
def test_logger(tmp_path: Path) -> Logger:
    return Logger(tmp_path / "integration-test.log")


@pytest.fixture
def openvpn_client_config(tmp_path: Path, openvpn_server: str) -> Path:
    """Generate OpenVPN client config pointing to the test server.

    In K8s, the openvpn-server pod generates a client.ovpn at /shared/client.ovpn.
    For the test runner, we generate a minimal config or use the shared one.
    """
    shared_config = Path("/shared/client.ovpn")
    if shared_config.exists():
        return shared_config

    # Fallback: minimal config (won't have certs, tests should handle this)
    config_path = tmp_path / "client.ovpn"
    config_path.write_text(textwrap.dedent(f"""\
        client
        dev tun
        proto udp
        remote {openvpn_server} 1194
        resolv-retry infinite
        nobind
        persist-key
        persist-tun
        cipher AES-256-GCM
        verb 3
    """))
    return config_path


@pytest.fixture
def fortivpn_config(tmp_path: Path, ocserv_host: str, ocserv_port: str,
                     ocserv_user: str, ocserv_pass: str) -> dict:
    """FortiVPN tunnel config dict for the ocserv test server."""
    # Get server certificate fingerprint
    fingerprint = ""
    fp_file = Path("/shared/server-fingerprint.txt")
    if fp_file.exists():
        fingerprint = fp_file.read_text().strip()

    return {
        "host": ocserv_host,
        "port": ocserv_port,
        "login": ocserv_user,
        "pass": ocserv_pass,
        "trusted_cert": fingerprint,
    }


@pytest.fixture
def singbox_client_config(tmp_path: Path, singbox_server: str,
                           singbox_ss_port: str,
                           singbox_ss_password: str) -> Path:
    """Generate sing-box client config for Shadowsocks proxy."""
    config_path = tmp_path / "singbox-client.json"
    config_path.write_text(textwrap.dedent(f"""\
        {{
          "log": {{"level": "info"}},
          "inbounds": [
            {{
              "type": "tun",
              "tag": "tun-in",
              "interface_name": "tun-test",
              "inet4_address": "172.19.0.1/30",
              "auto_route": false,
              "stack": "system"
            }}
          ],
          "outbounds": [
            {{
              "type": "shadowsocks",
              "tag": "ss-out",
              "server": "{singbox_server}",
              "server_port": {singbox_ss_port},
              "method": "aes-256-gcm",
              "password": "{singbox_ss_password}"
            }},
            {{
              "type": "direct",
              "tag": "direct"
            }}
          ],
          "route": {{
            "rules": [
              {{
                "inbound": ["tun-in"],
                "outbound": "ss-out"
              }}
            ],
            "final": "direct"
          }}
        }}
    """))
    return config_path


@pytest.fixture(autouse=True)
def _ensure_tun_device():
    """Ensure /dev/net/tun exists (needed in containers)."""
    tun_path = Path("/dev/net/tun")
    if not tun_path.exists():
        Path("/dev/net").mkdir(parents=True, exist_ok=True)
        subprocess.run(["mknod", "/dev/net/tun", "c", "10", "200"],
                       check=False, capture_output=True)
        subprocess.run(["chmod", "600", "/dev/net/tun"],
                       check=False, capture_output=True)


@pytest.fixture(autouse=True)
def _cleanup_after_test():
    """Kill any leftover VPN processes after each test."""
    yield
    for proc_name in ("openvpn", "openfortivpn", "sing-box"):
        subprocess.run(["pkill", "-f", proc_name],
                       check=False, capture_output=True)
    # Small delay for interfaces to disappear
    import time
    time.sleep(0.5)
