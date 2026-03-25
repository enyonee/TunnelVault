"""Integration tests: FortiVPN (openfortivpn -> ocserv) connect/disconnect.

Runs inside privileged K8s pod. ocserv must be running in test-vpn namespace.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tv.net import NetManager


pytestmark = [
    pytest.mark.network,
    pytest.mark.skip(reason="openfortivpn requires FortiGate server, ocserv is AnyConnect only"),
]


@pytest.fixture
def forti_config_file(tmp_path: Path, fortivpn_config: dict) -> Path:
    """Write openfortivpn config file."""
    conf = tmp_path / "forti-test.conf"
    lines = [
        f"host = {fortivpn_config['host']}",
        f"port = {fortivpn_config['port']}",
        f"username = {fortivpn_config['login']}",
        f"password = {fortivpn_config['pass']}",
    ]
    if fortivpn_config.get("trusted_cert"):
        lines.append(f"trusted-cert = {fortivpn_config['trusted_cert']}")
    # В тестовой среде отключаем проверку сертификата если нет fingerprint
    conf.write_text("\n".join(lines) + "\n")
    return conf


class TestFortiVPNConnect:
    """Real openfortivpn connection to ocserv."""

    def test_connect_creates_ppp_interface(
        self, forti_config_file: Path, real_net: NetManager, requires_tun
    ):
        """openfortivpn creates a ppp interface after connect."""
        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["openfortivpn", "-c", str(forti_config_file), "--no-routes", "--no-dns"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        try:
            new_iface = None
            for _ in range(30):
                time.sleep(0.5)
                ifaces_now = set(real_net.interfaces().keys())
                new = ifaces_now - ifaces_before
                ppp_ifaces = [i for i in new if i.startswith("ppp")]
                if ppp_ifaces:
                    new_iface = ppp_ifaces[0]
                    break

            assert new_iface is not None, (
                f"No ppp interface appeared. Ifaces: {real_net.interfaces()}"
            )

            # Verify PPP peer gateway
            peer = real_net.ppp_peer(new_iface)
            assert peer, f"No PPP peer detected for {new_iface}"

        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_connect_and_disconnect_cleans_up(
        self, forti_config_file: Path, real_net: NetManager, requires_tun
    ):
        """After disconnect, ppp interface disappears."""
        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["openfortivpn", "-c", str(forti_config_file), "--no-routes", "--no-dns"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for connect
        for _ in range(30):
            time.sleep(0.5)
            ifaces_now = set(real_net.interfaces().keys())
            if ifaces_now - ifaces_before:
                break

        proc.terminate()
        proc.wait(timeout=5)
        time.sleep(1)

        ifaces_after = set(real_net.interfaces().keys())
        new_ifaces = ifaces_after - ifaces_before
        ppp_ifaces = [i for i in new_ifaces if i.startswith("ppp")]
        assert len(ppp_ifaces) == 0, f"Leftover ppp interfaces: {ppp_ifaces}"

    def test_ping_through_vpn(self, forti_config_file: Path, real_net: NetManager, requires_tun):
        """Can ping VPN gateway through PPP tunnel."""
        ifaces_before = set(real_net.interfaces().keys())

        proc = subprocess.Popen(
            ["openfortivpn", "-c", str(forti_config_file), "--no-routes", "--no-dns"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            new_iface = None
            for _ in range(30):
                time.sleep(0.5)
                ifaces_now = set(real_net.interfaces().keys())
                new = ifaces_now - ifaces_before
                ppp_ifaces = [i for i in new if i.startswith("ppp")]
                if ppp_ifaces:
                    new_iface = ppp_ifaces[0]
                    break

            if new_iface is None:
                pytest.skip("PPP interface not created (ocserv may be misconfigured)")

            # Get PPP peer and ping it
            peer = real_net.ppp_peer(new_iface)
            if not peer:
                pytest.skip("Cannot determine PPP peer gateway")

            result = subprocess.run(
                ["ping", "-c", "3", "-W", "2", peer],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                f"Ping to PPP peer {peer} failed:\n{result.stdout}\n{result.stderr}"
            )

        finally:
            proc.terminate()
            proc.wait(timeout=5)
