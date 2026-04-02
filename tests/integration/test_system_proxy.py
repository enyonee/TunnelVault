"""Integration tests: system proxy setup and cleanup on real OS.

Tests that setup_system_proxy / cleanup_system_proxy actually change
system-level proxy settings. Platform-specific: each test class checks
the tools available on the current OS.

Marked with @pytest.mark.network (may need sudo on Linux).
"""

from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from tv.net import create as create_net, NetManager

pytestmark = pytest.mark.network


def _create_net() -> NetManager:
    """Create platform-specific NetManager (same as create() but importable)."""
    return create_net()


def _get_gnome_proxy_mode() -> str | None:
    """Read GNOME proxy mode via gsettings. Returns None if not available."""
    if not shutil.which("gsettings"):
        return None
    r = subprocess.run(
        ["gsettings", "get", "org.gnome.system.proxy", "mode"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if r.returncode == 0:
        return r.stdout.strip().strip("'")
    return None


def _get_gnome_http_proxy() -> tuple[str, int] | None:
    """Read GNOME HTTP proxy host and port."""
    if not shutil.which("gsettings"):
        return None
    host_r = subprocess.run(
        ["gsettings", "get", "org.gnome.system.proxy.http", "host"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    port_r = subprocess.run(
        ["gsettings", "get", "org.gnome.system.proxy.http", "port"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if host_r.returncode == 0 and port_r.returncode == 0:
        host = host_r.stdout.strip().strip("'")
        port = int(port_r.stdout.strip())
        return host, port
    return None


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="macOS networksetup only",
)
class TestDarwinSystemProxy:
    """Test real macOS proxy setup/cleanup via networksetup."""

    def test_setup_and_cleanup_cycle(self):
        net = create_net()
        # Setup
        ok = net.setup_system_proxy(19876)
        assert ok, "setup_system_proxy returned False"

        # Verify proxy is set via networksetup
        r = subprocess.run(
            ["networksetup", "-getwebproxy", "Wi-Fi"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0:
            assert "19876" in r.stdout or "Enabled: Yes" in r.stdout

        # Cleanup
        ok = net.cleanup_system_proxy()
        assert ok, "cleanup_system_proxy returned False"

        # Verify proxy is off
        r = subprocess.run(
            ["networksetup", "-getwebproxy", "Wi-Fi"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0:
            assert "Enabled: No" in r.stdout


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux gsettings only",
)
class TestLinuxGsettingsProxy:
    """Test real GNOME proxy setup/cleanup via gsettings."""

    @pytest.fixture(autouse=True)
    def _skip_no_gsettings(self):
        if not shutil.which("gsettings"):
            pytest.skip("gsettings not available")

    def test_setup_sets_manual_mode(self):
        net = create_net()

        # Save original mode for restore
        original_mode = _get_gnome_proxy_mode()

        try:
            ok = net.setup_system_proxy(19876)
            assert ok, "setup_system_proxy returned False"

            mode = _get_gnome_proxy_mode()
            assert mode == "manual", f"Expected manual, got {mode}"

            hp = _get_gnome_http_proxy()
            assert hp is not None, "Could not read http proxy"
            assert hp == ("127.0.0.1", 19876), f"Expected 127.0.0.1:19876, got {hp}"
        finally:
            # Restore original mode
            net.cleanup_system_proxy()
            if original_mode and original_mode != "none":
                subprocess.run(
                    [
                        "gsettings",
                        "set",
                        "org.gnome.system.proxy",
                        "mode",
                        original_mode,
                    ],
                    capture_output=True,
                    timeout=5,
                )

    def test_cleanup_sets_none_mode(self):
        net = create_net()

        net.setup_system_proxy(19876)
        ok = net.cleanup_system_proxy()
        assert ok, "cleanup_system_proxy returned False"

        mode = _get_gnome_proxy_mode()
        assert mode == "none", f"Expected none, got {mode}"


@pytest.mark.skipif(
    platform.system() != "Linux" or shutil.which("gsettings") is not None,
    reason="Only for Linux without gsettings (env fallback)",
)
class TestLinuxEnvFallbackProxy:
    """Test /etc/environment proxy fallback (requires sudo)."""

    def test_setup_writes_env_and_cleanup_removes(self):
        net = create_net()

        try:
            ok = net.setup_system_proxy(19876)
            assert ok, "setup_system_proxy returned False"

            # Check /etc/environment has proxy lines
            content = open("/etc/environment").read()
            assert "tunnelvault-proxy" in content
            assert "19876" in content
        finally:
            ok = net.cleanup_system_proxy()
            assert ok, "cleanup_system_proxy returned False"

            content = open("/etc/environment").read()
            assert "tunnelvault-proxy" not in content


@pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Windows netsh/registry only",
)
class TestWindowsSystemProxy:
    """Test real Windows proxy setup/cleanup."""

    def test_setup_and_cleanup_cycle(self):
        net = create_net()

        try:
            ok = net.setup_system_proxy(19876)
            assert ok, "setup_system_proxy returned False"

            # Verify via netsh
            r = subprocess.run(
                ["netsh", "winhttp", "show", "proxy"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0:
                assert "127.0.0.1:19876" in r.stdout
        finally:
            ok = net.cleanup_system_proxy()
            assert ok, "cleanup_system_proxy returned False"

            # Verify proxy removed
            r = subprocess.run(
                ["netsh", "winhttp", "show", "proxy"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0:
                assert "Direct access" in r.stdout or "127.0.0.1:19876" not in r.stdout
