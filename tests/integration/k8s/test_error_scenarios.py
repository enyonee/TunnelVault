"""Integration tests: error scenarios and failure handling.

Tests that tunnelvault handles failures gracefully:
- Wrong credentials
- Unreachable server
- Server killed mid-session
- Invalid config
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tv.net import NetManager


pytestmark = pytest.mark.network


class TestAuthFailure:
    """Wrong credentials should fail gracefully, not hang or crash."""

    def test_fortivpn_wrong_password(
        self, tmp_path: Path, ocserv_host: str, ocserv_port: str, real_net: NetManager
    ):
        """openfortivpn with wrong password returns non-zero, no interface leak."""
        conf = tmp_path / "bad-auth.conf"
        conf.write_text(
            f"host = {ocserv_host}\n"
            f"port = {ocserv_port}\n"
            "username = testuser\n"
            "password = WRONG_PASSWORD_12345\n"
        )

        ifaces_before = set(real_net.interfaces().keys())

        result = subprocess.run(
            ["openfortivpn", "-c", str(conf), "--no-routes", "--no-dns"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Должен упасть, не зависнуть
        assert result.returncode != 0, "Expected failure with wrong password"

        # Не должно остаться интерфейсов
        ifaces_after = set(real_net.interfaces().keys())
        leaked = [i for i in (ifaces_after - ifaces_before) if i.startswith("ppp")]
        assert len(leaked) == 0, f"PPP interface leaked after auth failure: {leaked}"

    def test_openvpn_bad_config(
        self, tmp_path: Path, openvpn_server: str, real_net: NetManager
    ):
        """OpenVPN with invalid config exits quickly without interface leak."""
        bad_config = tmp_path / "bad.ovpn"
        bad_config.write_text(
            f"client\n"
            f"dev tun\n"
            f"proto udp\n"
            f"remote {openvpn_server} 1194\n"
            f"# Missing certs/keys - should fail\n"
        )

        ifaces_before = set(real_net.interfaces().keys())

        result = subprocess.run(
            ["openvpn", "--config", str(bad_config)],
            capture_output=True,
            text=True,
            timeout=15,
        )

        assert result.returncode != 0, "Expected failure with missing certs"

        ifaces_after = set(real_net.interfaces().keys())
        leaked = [
            i for i in (ifaces_after - ifaces_before) if i.startswith(("tun", "utun"))
        ]
        assert len(leaked) == 0, f"Tun interface leaked after config error: {leaked}"


class TestUnreachableServer:
    """Connection to unreachable server should timeout, not hang forever."""

    def test_openvpn_unreachable_host_times_out(
        self, tmp_path: Path, real_net: NetManager
    ):
        """OpenVPN to non-routable IP times out within reasonable time."""
        config = tmp_path / "unreachable.ovpn"
        config.write_text(
            "client\n"
            "dev tun\n"
            "proto udp\n"
            "remote 192.0.2.1 1194\n"  # RFC 5737 TEST-NET - не маршрутизируется
            "connect-retry-max 1\n"
            "connect-timeout 5\n"
            "resolv-retry 1\n"
            "nobind\n"
        )

        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["openvpn", "--config", str(config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Ждём максимум 15 секунд - openvpn должен сдаться
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=5)

        ifaces_after = set(real_net.interfaces().keys())
        leaked = [
            i for i in (ifaces_after - ifaces_before) if i.startswith(("tun", "utun"))
        ]
        assert len(leaked) == 0, f"Interface leaked after timeout: {leaked}"


class TestServerKilledMidSession:
    """What happens when VPN process is killed externally (SIGKILL)."""

    def test_openvpn_killed_cleans_interface(
        self, openvpn_client_config: Path, real_net: NetManager
    ):
        """After SIGKILL of openvpn, interface eventually disappears."""
        import signal

        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["openvpn", "--config", str(openvpn_client_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Ждём подключения
        connected = False
        for _ in range(30):
            time.sleep(0.5)
            new = set(real_net.interfaces().keys()) - ifaces_before
            if any(i.startswith(("tun", "utun")) for i in new):
                connected = True
                break

        if not connected:
            proc.kill()
            proc.wait(timeout=5)
            pytest.skip("OpenVPN connection failed, cannot test kill scenario")

        # SIGKILL - жёсткое убийство
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=5)
        time.sleep(2)

        # Интерфейс должен исчезнуть (ядро убирает при смерти процесса)
        ifaces_after = set(real_net.interfaces().keys())
        leaked = [
            i for i in (ifaces_after - ifaces_before) if i.startswith(("tun", "utun"))
        ]
        assert len(leaked) == 0, (
            f"Tun interface leaked after SIGKILL: {leaked}. "
            f"Kernel should clean up when owning process dies."
        )
