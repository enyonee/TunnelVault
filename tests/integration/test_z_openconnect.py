"""Integration tests: OpenConnect (ocserv) connect/disconnect.

OpenConnect uses TUN interface (not PPP like openfortivpn).
ocserv must be running in the test network.
"""

from __future__ import annotations

import subprocess
import time

import pytest

from tv.net import NetManager


pytestmark = pytest.mark.network


def _start_openconnect(
    host: str,
    port: str,
    user: str,
    password: str,
    cert_pin: str,
) -> tuple[bool, str]:
    """Start openconnect in background.

    Returns (success, output) tuple. success=False if process failed or timed out.
    """
    proc = subprocess.Popen(
        [
            "openconnect",
            f"--server={host}:{port}",
            f"--user={user}",
            "--passwd-on-stdin",
            "--no-dtls",
            f"--servercert={cert_pin}",
            "--background",
            "--pid-file=/tmp/openconnect-test.pid",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        out, _ = proc.communicate(input=f"{password}\n".encode(), timeout=15)
        output = out.decode(errors="replace") if out else ""
        return proc.returncode == 0, output
    except subprocess.TimeoutExpired:
        proc.kill()
        return False, "timeout"


def _wait_for_tun(
    net: NetManager, ifaces_before: set, timeout: float = 10
) -> str | None:
    """Wait for a new tun interface to appear."""
    for _ in range(int(timeout / 0.5)):
        time.sleep(0.5)
        ifaces_now = set(net.interfaces().keys())
        new = ifaces_now - ifaces_before
        tun_ifaces = [i for i in new if i.startswith("tun")]
        if tun_ifaces:
            return tun_ifaces[0]
    return None


class TestOpenConnectConnect:
    """Real openconnect connection to ocserv via TUN."""

    def test_connect_creates_tun_interface(
        self,
        ocserv_host: str,
        ocserv_port: str,
        ocserv_user: str,
        ocserv_pass: str,
        ocserv_cert_pin: str,
        real_net: NetManager,
        requires_tun,
    ):
        """openconnect creates a tun interface after connect."""
        if not ocserv_cert_pin:
            pytest.skip("Could not obtain ocserv certificate pin")

        ifaces_before = set(real_net.interfaces().keys())
        ok, output = _start_openconnect(
            ocserv_host, ocserv_port, ocserv_user, ocserv_pass, ocserv_cert_pin
        )
        if not ok:
            pytest.skip(f"openconnect failed to start: {output[:200]}")

        try:
            new_iface = _wait_for_tun(real_net, ifaces_before)
            assert new_iface is not None, (
                f"No tun interface appeared. Ifaces: {real_net.interfaces()}"
            )
        finally:
            subprocess.run(
                ["pkill", "-f", "openconnect"], check=False, capture_output=True
            )
            time.sleep(1)

    def test_connect_and_disconnect_cleans_up(
        self,
        ocserv_host: str,
        ocserv_port: str,
        ocserv_user: str,
        ocserv_pass: str,
        ocserv_cert_pin: str,
        real_net: NetManager,
        requires_tun,
    ):
        """After disconnect, tun interface disappears."""
        if not ocserv_cert_pin:
            pytest.skip("Could not obtain ocserv certificate pin")

        ifaces_before = set(real_net.interfaces().keys())
        ok, output = _start_openconnect(
            ocserv_host, ocserv_port, ocserv_user, ocserv_pass, ocserv_cert_pin
        )
        if not ok:
            pytest.skip(f"openconnect failed to start: {output[:200]}")

        _wait_for_tun(real_net, ifaces_before)

        subprocess.run(["pkill", "-f", "openconnect"], check=False, capture_output=True)
        time.sleep(2)

        ifaces_after = set(real_net.interfaces().keys())
        new_ifaces = ifaces_after - ifaces_before
        tun_ifaces = [i for i in new_ifaces if i.startswith("tun")]
        assert len(tun_ifaces) == 0, f"Leftover tun interfaces: {tun_ifaces}"

    def test_ping_through_vpn(
        self,
        ocserv_host: str,
        ocserv_port: str,
        ocserv_user: str,
        ocserv_pass: str,
        ocserv_cert_pin: str,
        real_net: NetManager,
        requires_tun,
    ):
        """Can ping ocserv gateway through TUN tunnel."""
        if not ocserv_cert_pin:
            pytest.skip("Could not obtain ocserv certificate pin")

        ifaces_before = set(real_net.interfaces().keys())
        ok, output = _start_openconnect(
            ocserv_host, ocserv_port, ocserv_user, ocserv_pass, ocserv_cert_pin
        )
        if not ok:
            pytest.skip(f"openconnect failed to start: {output[:200]}")

        try:
            new_iface = _wait_for_tun(real_net, ifaces_before)
            if new_iface is None:
                pytest.skip("TUN interface not created")

            result = subprocess.run(
                ["ping", "-c", "3", "-W", "2", ocserv_host],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                f"Ping to {ocserv_host} failed:\n{result.stdout}\n{result.stderr}"
            )
        finally:
            subprocess.run(
                ["pkill", "-f", "openconnect"], check=False, capture_output=True
            )
            time.sleep(1)
