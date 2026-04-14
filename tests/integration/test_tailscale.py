"""Integration tests: Tailscale connect/disconnect with Headscale server.

Runs inside privileged container. Headscale coordination server must be running
in vpn-e2e network. Auth key is shared via volume at /shared/ts/ts-auth-key.
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest


pytestmark = pytest.mark.network

TS_SOCKET = "/var/run/tailscale/tailscaled.sock"
TS_STATE = "/var/lib/tailscale/tailscaled.state"


def _ts(*args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    """Run tailscale CLI with explicit socket path."""
    return subprocess.run(
        ["tailscale", f"--socket={TS_SOCKET}", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _ensure_tailscaled():
    """Ensure tailscaled daemon is running (started by entrypoint or manually)."""
    # Check if already running (started by container entrypoint)
    for _ in range(10):
        if os.path.exists(TS_SOCKET):
            return
        # Try starting manually if not running
        check = subprocess.run(["pgrep", "-x", "tailscaled"], capture_output=True)
        if check.returncode != 0:
            os.makedirs("/var/lib/tailscale", exist_ok=True)
            os.makedirs("/var/run/tailscale", exist_ok=True)
            subprocess.Popen(
                [
                    "tailscaled",
                    f"--state={TS_STATE}",
                    "--tun=userspace-networking",
                    f"--socket={TS_SOCKET}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        time.sleep(1)
    if not os.path.exists(TS_SOCKET):
        pytest.skip("tailscaled socket not available")


def _tailscale_cleanup():
    """Disconnect and logout from tailscale."""
    try:
        _ts("down", timeout=3)
    except subprocess.TimeoutExpired:
        pass
    try:
        _ts("logout", timeout=3)
    except subprocess.TimeoutExpired:
        pass


class TestTailscaleConnect:
    """Real Tailscale connection lifecycle via Headscale."""

    def test_full_tailscale_lifecycle(
        self, ts_auth_key: str, headscale_url: str, requires_tun
    ):
        """Connect, get IP, disconnect - full lifecycle in one test."""
        _ensure_tailscaled()

        try:
            # 1. Connect with auth key
            result = _ts(
                "up",
                f"--auth-key={ts_auth_key}",
                f"--login-server={headscale_url}",
                "--accept-routes",
                "--timeout=20s",
                timeout=30,
            )
            assert result.returncode == 0, f"tailscale up failed: {result.stderr}"

            time.sleep(5)

            # 2. Verify status
            status = _ts("status", timeout=10)
            assert status.returncode == 0, (
                f"tailscale status failed (rc={status.returncode}): {status.stderr}"
            )

            # 3. Verify IP
            ip_result = _ts("ip", "-4", timeout=10)
            assert ip_result.returncode == 0, f"tailscale ip failed: {ip_result.stderr}"
            ip_addr = ip_result.stdout.strip()
            assert ip_addr.startswith("100.64."), (
                f"Expected 100.64.x.x address, got: {ip_addr}"
            )

            # 4. Disconnect
            down_result = _ts("down")
            assert down_result.returncode == 0, (
                f"tailscale down failed: {down_result.stderr}"
            )
            time.sleep(1)

            # 5. Verify stopped
            status2 = _ts("status")
            stopped = (
                status2.returncode != 0
                or "stopped" in status2.stdout.lower()
                or "stopped" in status2.stderr.lower()
            )
            assert stopped, (
                f"Expected stopped state: rc={status2.returncode} "
                f"{status2.stdout} {status2.stderr}"
            )

        finally:
            _tailscale_cleanup()
