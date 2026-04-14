"""Integration tests: SSH tunnel SOCKS proxy with real SSH server.

Runs inside test-runner container. SSH server must be running in vpn-e2e network.
Environment variables provide server address and credentials.
"""

from __future__ import annotations

import subprocess
import time

import pytest


pytestmark = pytest.mark.network


def _wait_for_port(host: str, port: int, timeout: int = 10) -> bool:
    """Wait for a TCP port to start listening."""
    for _ in range(timeout * 2):
        result = subprocess.run(
            ["nc", "-z", host, str(port)],
            capture_output=True,
            timeout=3,
        )
        if result.returncode == 0:
            return True
        time.sleep(0.5)
    return False


class TestSSHConnection:
    """Basic SSH connectivity to the test server."""

    def test_ssh_connection_works(self, ssh_socks_config: dict):
        """sshpass + ssh can reach the server and run a command."""
        cfg = ssh_socks_config
        result = subprocess.run(
            [
                "sshpass",
                "-p",
                cfg["pass"],
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-p",
                cfg["port"],
                f"{cfg['user']}@{cfg['host']}",
                "echo",
                "hello",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"SSH connection failed: {result.stderr}"
        assert "hello" in result.stdout


class TestSSHSocksProxy:
    """SOCKS proxy mode: ssh -D creates a local SOCKS5 listener."""

    def test_socks_proxy_creates_tunnel(self, ssh_socks_config: dict):
        """ssh -D opens SOCKS port and keeps it listening."""
        cfg = ssh_socks_config
        socks_port = cfg["socks_port"]

        ssh_proc = subprocess.Popen(
            [
                "sshpass",
                "-p",
                cfg["pass"],
                "ssh",
                "-D",
                str(socks_port),
                "-N",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ExitOnForwardFailure=yes",
                "-p",
                cfg["port"],
                f"{cfg['user']}@{cfg['host']}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            assert _wait_for_port("127.0.0.1", socks_port), (
                f"SOCKS port {socks_port} did not open within timeout"
            )

            # Verify the port is still listening (not a transient open)
            check = subprocess.run(
                ["nc", "-z", "127.0.0.1", str(socks_port)],
                capture_output=True,
                timeout=3,
            )
            assert check.returncode == 0, "SOCKS port closed unexpectedly"

        finally:
            ssh_proc.terminate()
            ssh_proc.wait(timeout=5)

    def test_socks_proxy_disconnect(self, ssh_socks_config: dict):
        """After killing ssh, SOCKS port stops listening."""
        cfg = ssh_socks_config
        socks_port = cfg["socks_port"]

        ssh_proc = subprocess.Popen(
            [
                "sshpass",
                "-p",
                cfg["pass"],
                "ssh",
                "-D",
                str(socks_port),
                "-N",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ExitOnForwardFailure=yes",
                "-p",
                cfg["port"],
                f"{cfg['user']}@{cfg['host']}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            assert _wait_for_port("127.0.0.1", socks_port), (
                f"SOCKS port {socks_port} did not open within timeout"
            )
        finally:
            ssh_proc.terminate()
            ssh_proc.wait(timeout=5)

        # After kill, port should be closed
        time.sleep(1)
        check = subprocess.run(
            ["nc", "-z", "127.0.0.1", str(socks_port)],
            capture_output=True,
            timeout=3,
        )
        assert check.returncode != 0, (
            f"SOCKS port {socks_port} still listening after ssh killed"
        )
