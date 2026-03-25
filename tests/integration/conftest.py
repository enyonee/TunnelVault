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
from tv.net import NetManager, create as create_net


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
    return create_net()


@pytest.fixture
def test_logger(tmp_path: Path) -> Logger:
    return Logger(tmp_path / "integration-test.log")


@pytest.fixture
def openvpn_client_config(tmp_path: Path, openvpn_server: str) -> Path:
    """Generate OpenVPN client config pointing to the test server.

    In K8s, the openvpn-server pod generates a client.ovpn at /shared/client.ovpn.
    For the test runner, we generate a minimal config or use the shared one.
    """
    # ConfigMap mounted at /shared with client.ovpn (includes certs)
    shared_config = Path("/shared/client.ovpn")
    if shared_config.exists():
        return shared_config

    # Fallback: minimal config without certs (connect will fail)
    config_path = tmp_path / "client.ovpn"
    config_path.write_text(
        textwrap.dedent(f"""\
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
    """)
    )
    return config_path


@pytest.fixture
def fortivpn_config(
    tmp_path: Path,
    ocserv_host: str,
    ocserv_port: str,
    ocserv_user: str,
    ocserv_pass: str,
) -> dict:
    """FortiVPN tunnel config dict for the ocserv test server."""
    # Get server certificate fingerprint
    fingerprint = ""
    fp_file = Path("/shared/ocserv-fingerprint")
    if fp_file.exists():
        fingerprint = fp_file.read_text().strip()

    return {
        "host": ocserv_host,
        "port": ocserv_port,
        "login": ocserv_user,
        "pass": ocserv_pass,
        "trusted_cert": fingerprint,
    }


@pytest.fixture(scope="session")
def ocserv_cert_pin(ocserv_host: str, ocserv_port: str) -> str:
    """Get ocserv server certificate pin-sha256 for openconnect --servercert."""
    result = subprocess.run(
        ["openconnect", f"--server={ocserv_host}:{ocserv_port}",
         "--authenticate", "--servercert=invalid", "--user=x", "--passwd-on-stdin"],
        input="x\n", capture_output=True, text=True, timeout=10,
    )
    # Parse pin from error: "server's certificate: pin-sha256:xxx"
    for line in result.stderr.splitlines():
        if "pin-sha256:" in line:
            pin = line.split("pin-sha256:")[-1].strip()
            return f"pin-sha256:{pin}"
    return ""


@pytest.fixture
def singbox_client_config(
    tmp_path: Path, singbox_server: str, singbox_ss_port: str, singbox_ss_password: str
) -> Path:
    """Generate sing-box client config for Shadowsocks proxy."""
    config_path = tmp_path / "singbox-client.json"
    config_path.write_text(
        textwrap.dedent(f"""\
        {{
          "log": {{"level": "info"}},
          "inbounds": [
            {{
              "type": "tun",
              "tag": "tun-in",
              "interface_name": "tun-test",
              "address": ["172.19.0.1/30"],
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
    """)
    )
    return config_path


@pytest.fixture(autouse=True)
def _ensure_devices():
    """Ensure /dev/net/tun and /dev/ppp exist (needed in containers)."""
    tun_path = Path("/dev/net/tun")
    if not tun_path.exists():
        Path("/dev/net").mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["mknod", "/dev/net/tun", "c", "10", "200"],
            check=False,
            capture_output=True,
        )
        subprocess.run(
            ["chmod", "600", "/dev/net/tun"], check=False, capture_output=True
        )
    ppp_path = Path("/dev/ppp")
    if not ppp_path.exists():
        subprocess.run(
            ["mknod", "/dev/ppp", "c", "108", "0"],
            check=False,
            capture_output=True,
        )
        subprocess.run(
            ["chmod", "600", "/dev/ppp"], check=False, capture_output=True
        )


def _can_create_tun() -> bool:
    """Check if real VPN tun/ppp creation works.

    Docker Desktop macOS passes /dev/net/tun ioctl but VPN clients still
    can't create interfaces (kernel namespace limitation).
    Use explicit env var TUN_AVAILABLE=1 set only on real Linux hosts.
    """
    return os.environ.get("TUN_AVAILABLE", "") == "1"


_tun_works: bool | None = None


@pytest.fixture
def requires_tun():
    """Skip test if tun creation is not available (Docker Desktop macOS)."""
    global _tun_works
    if _tun_works is None:
        _tun_works = _can_create_tun()
    if not _tun_works:
        pytest.skip("TUN creation not available (Docker Desktop macOS?)")


@pytest.fixture(autouse=True)
def _cleanup_after_test():
    """Kill leftover VPN processes, clean interfaces, restore routing."""
    import time

    # Capture default gateway before test
    gw_result = subprocess.run(
        ["ip", "route", "show", "default"], capture_output=True, text=True,
    )
    default_gw = gw_result.stdout.strip()

    yield

    # Kill all VPN processes
    for proc_name in ("openvpn", "openfortivpn", "openconnect", "sing-box"):
        subprocess.run(["pkill", "-9", "-f", proc_name], check=False, capture_output=True)
    time.sleep(1)

    # Remove leftover tun/ppp interfaces
    result = subprocess.run(["ip", "-br", "link"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        iface = line.split()[0]
        if iface.startswith(("tun", "ppp")) or iface in ("tun-test", "vpns0"):
            subprocess.run(
                ["ip", "link", "delete", iface], check=False, capture_output=True,
            )

    # Restore default route if it was changed by VPN client
    gw_now = subprocess.run(
        ["ip", "route", "show", "default"], capture_output=True, text=True,
    )
    if gw_now.stdout.strip() != default_gw and default_gw:
        # Flush non-default routes added by VPN and restore original
        subprocess.run(["ip", "route", "flush", "table", "main"], check=False, capture_output=True)
        subprocess.run(
            ["ip", "route", "add"] + default_gw.split(),
            check=False, capture_output=True,
        )
        # Re-add container network route
        subprocess.run(
            ["ip", "route", "add", "172.28.0.0/24", "dev", "eth0"],
            check=False, capture_output=True,
        )

    time.sleep(0.5)
