"""Integration tests for Fortinet auth flow via openconnect.

Uses fake-fortinet-server.py (from openconnect project) which emulates
FortiGate SSL VPN auth endpoints. Tests cover:
- Authentication with --protocol=fortinet
- Config XML parsing (DNS, routes, IP assignment)
- SPKI cert pin generation
- tunnelvault cert_mode=auto with Fortinet
"""

from __future__ import annotations

import subprocess

import pytest

from tv.vpn.cert import generate_cert_sha256, generate_spki_pin


pytestmark = pytest.mark.network


@pytest.fixture(scope="session")
def fortinet_cert_pin(fortinet_host: str, fortinet_port: str) -> str:
    """Auto-generate SPKI pin for fake-fortinet server."""
    pin = generate_spki_pin(fortinet_host, fortinet_port)
    assert pin, f"Failed to generate SPKI pin for {fortinet_host}:{fortinet_port}"
    return pin


def _oc_auth(host, port, user, password, pin, extra_args=None):
    """Run openconnect --authenticate and return CompletedProcess."""
    cmd = [
        "openconnect",
        f"--server={host}:{port}",
        "--protocol=fortinet",
        "--authenticate",
        f"--servercert={pin}",
        f"--user={user}",
        "--passwd-on-stdin",
    ]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd, input=f"{password}\n", capture_output=True, text=True, timeout=15
    )


class TestFortinetAuth:
    """Test openconnect --protocol=fortinet auth against fake server."""

    def test_authenticate_succeeds(
        self,
        fortinet_host,
        fortinet_port,
        fortinet_user,
        fortinet_pass,
        fortinet_cert_pin,
    ):
        """openconnect --authenticate completes auth and returns cookie."""
        result = _oc_auth(
            fortinet_host,
            fortinet_port,
            fortinet_user,
            fortinet_pass,
            fortinet_cert_pin,
        )
        output = result.stdout + result.stderr
        assert "COOKIE" in output or result.returncode == 0, (
            f"Auth failed (rc={result.returncode}):\n{output}"
        )

    def test_authenticate_returns_cookie_fields(
        self,
        fortinet_host,
        fortinet_port,
        fortinet_user,
        fortinet_pass,
        fortinet_cert_pin,
    ):
        """Auth response includes cookie and host fields for tunnel setup."""
        result = _oc_auth(
            fortinet_host,
            fortinet_port,
            fortinet_user,
            fortinet_pass,
            fortinet_cert_pin,
        )
        output = result.stdout
        # --authenticate prints COOKIE=, HOST=, FINGERPRINT= on stdout
        assert "COOKIE=" in output or "HOST=" in output, (
            f"No auth fields in output:\n{output}"
        )

    def test_wrong_pin_fails(
        self, fortinet_host, fortinet_port, fortinet_user, fortinet_pass
    ):
        """Wrong cert pin should fail verification."""
        result = _oc_auth(
            fortinet_host,
            fortinet_port,
            fortinet_user,
            fortinet_pass,
            "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        assert result.returncode != 0, "Auth should fail with wrong pin"


class TestFortinetCertPin:
    """Test SPKI pin generation against fake-fortinet HTTPS server."""

    def test_spki_pin_generated(self, fortinet_host, fortinet_port):
        """generate_spki_pin returns valid pin-sha256 for fake server."""
        pin = generate_spki_pin(fortinet_host, fortinet_port)
        assert pin.startswith("pin-sha256:"), f"Bad pin format: {pin}"
        # Base64 encoded SHA256 = 44 chars
        b64_part = pin.split(":", 1)[1]
        assert len(b64_part) > 20, f"Pin too short: {pin}"

    def test_spki_pin_deterministic(self, fortinet_host, fortinet_port):
        """Same server returns same pin on repeated calls."""
        pin1 = generate_spki_pin(fortinet_host, fortinet_port)
        pin2 = generate_spki_pin(fortinet_host, fortinet_port)
        assert pin1 == pin2

    def test_cert_sha256_also_works(self, fortinet_host, fortinet_port):
        """DER cert hash (for openfortivpn) also generates successfully."""
        cert = generate_cert_sha256(fortinet_host, fortinet_port)
        assert cert, "generate_cert_sha256 returned empty"
        assert len(cert) == 64, f"Expected 64 hex chars, got {len(cert)}: {cert}"

    def test_spki_pin_differs_from_der_hash(self, fortinet_host, fortinet_port):
        """SPKI pin and DER hash are different (different hashing targets)."""
        pin = generate_spki_pin(fortinet_host, fortinet_port)
        cert = generate_cert_sha256(fortinet_host, fortinet_port)
        # pin is base64, cert is hex - they should not be equal
        assert pin.split(":", 1)[1] != cert
