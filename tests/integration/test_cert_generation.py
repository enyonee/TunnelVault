"""Integration tests for TLS certificate fingerprint generation.

These tests call real openssl subprocess chains against real servers.
Requires network access. Marked with @pytest.mark.network.
"""

from __future__ import annotations

import re
import shutil

import pytest

from tv.config import _generate_cert, _SHA256_EMPTY

pytestmark = pytest.mark.network

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@pytest.fixture(autouse=True)
def _require_openssl():
    if not shutil.which("openssl"):
        pytest.skip("openssl not found on PATH")


class TestRealCertGeneration:
    def test_returns_valid_sha256_hex(self):
        """Real openssl chain against google.com:443 returns 64-char hex hash."""
        cert = _generate_cert("google.com", "443")
        assert cert, "Expected non-empty cert hash"
        assert _HEX64.match(cert), f"Not a valid SHA256 hex: {cert}"

    def test_not_sha256_of_empty(self):
        """Result must never be sha256 of empty input."""
        cert = _generate_cert("google.com", "443")
        assert cert != _SHA256_EMPTY

    def test_deterministic_result(self):
        """Same server returns same cert hash (cert doesn't change mid-test)."""
        cert1 = _generate_cert("google.com", "443")
        cert2 = _generate_cert("google.com", "443")
        assert cert1 == cert2

    def test_sni_produces_correct_cert(self):
        """Different SNI hostnames on the same IP can produce different certs."""
        # Both resolve to Google but SNI matters for cert selection.
        # At minimum, the function should return a valid cert for each.
        cert_google = _generate_cert("google.com", "443")
        cert_github = _generate_cert("github.com", "443")
        assert cert_google and cert_github
        # Google and GitHub have different certs
        assert cert_google != cert_github


class TestUnreachableHost:
    def test_unreachable_returns_empty(self):
        """RFC 5737 TEST-NET address - guaranteed unreachable, should timeout."""
        cert = _generate_cert("192.0.2.1", "443")
        assert cert == ""

    def test_bad_port_returns_empty(self):
        """Valid host, closed port - connection refused, returns empty."""
        cert = _generate_cert("google.com", "1")
        assert cert == ""

    def test_nonexistent_domain_returns_empty(self):
        """DNS resolution failure returns empty."""
        cert = _generate_cert("this-host-does-not-exist.invalid", "443")
        assert cert == ""
