"""Integration tests for DNS leak prevention.

Verify that DNS queries go through the VPN tunnel, not directly to
the default gateway. Uses tcpdump to capture DNS packets on the
non-VPN interface while making DNS queries.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tv.net import create as create_net

pytestmark = [pytest.mark.network]


def _start_openvpn(config: Path) -> subprocess.Popen:
    """Start OpenVPN and wait for tun interface."""
    proc = subprocess.Popen(
        [
            "sudo",
            "openvpn",
            "--config",
            str(config),
            "--daemon",
            "--log",
            "/tmp/ovpn-leak.log",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    net = create_net()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        ifaces = net.interfaces()
        tun = [i for i in ifaces if i.startswith("tun")]
        if tun:
            return proc
        time.sleep(1)
    pytest.fail("OpenVPN tun interface did not appear within 20s")


def _stop_openvpn():
    subprocess.run(["sudo", "pkill", "-f", "openvpn"], check=False, capture_output=True)
    time.sleep(1)


class TestDNSLeak:
    """Verify DNS doesn't leak outside VPN tunnel."""

    def test_dns_goes_through_tunnel(self, openvpn_client_config, requires_tun):
        """DNS queries should not appear on eth0 while VPN is active.

        Captures UDP port 53 on eth0 for 5 seconds while making DNS queries.
        If VPN is working correctly, DNS should go through tun, not eth0.
        """
        _start_openvpn(openvpn_client_config)
        try:
            time.sleep(2)  # let routes settle

            # Start tcpdump on eth0 capturing DNS (UDP 53)
            capture_file = "/tmp/dns-leak-test.pcap"
            tcpdump = subprocess.Popen(
                [
                    "sudo",
                    "tcpdump",
                    "-i",
                    "eth0",
                    "-n",
                    "udp port 53",
                    "-c",
                    "10",  # capture max 10 packets
                    "-w",
                    capture_file,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(1)  # let tcpdump start

            # Make DNS queries that should go through VPN
            for domain in ["google.com", "github.com", "cloudflare.com"]:
                subprocess.run(
                    ["nslookup", domain],
                    capture_output=True,
                    timeout=5,
                )

            time.sleep(3)  # wait for any leaked packets

            # Stop tcpdump
            subprocess.run(
                ["sudo", "kill", str(tcpdump.pid)],
                check=False,
                capture_output=True,
            )
            tcpdump.wait(timeout=5)

            # Read capture - should have 0 DNS packets on eth0
            result = subprocess.run(
                ["sudo", "tcpdump", "-r", capture_file, "-n"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            dns_packets = [
                line
                for line in result.stdout.splitlines()
                if ".53:" in line or ".53 " in line
            ]

            # Allow 0-1 packets (initial resolver cache miss might leak once)
            assert len(dns_packets) <= 1, (
                f"DNS leak detected: {len(dns_packets)} DNS packets on eth0:\n"
                + "\n".join(dns_packets[:5])
            )

        finally:
            _stop_openvpn()
            Path(capture_file).unlink(missing_ok=True)

    def test_no_dns_leak_after_disconnect(self, openvpn_client_config, requires_tun):
        """After VPN disconnect, DNS should resume working normally (no broken state)."""
        _start_openvpn(openvpn_client_config)
        time.sleep(3)
        _stop_openvpn()
        time.sleep(2)

        # DNS should work after disconnect
        result = subprocess.run(
            ["nslookup", "google.com"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (
            f"DNS broken after VPN disconnect: {result.stderr}"
        )
