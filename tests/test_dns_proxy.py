"""Tests for tv.dns_proxy: BypassDNSProxy lifecycle and route injection."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from tv.dns_proxy import BypassDNSProxy


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture
def proxy(mock_net, logger):
    """BypassDNSProxy with mocked deps, not started."""
    return BypassDNSProxy(
        suffixes=[".ru", ".рф"],
        upstream_dns="8.8.8.8",
        net=mock_net,
        logger=logger,
        gateway="192.168.1.1",
        bind="127.0.0.1",
        port=15353,  # non-privileged port for tests
    )


def _make_dns_reply(qname: str, ips: list[str]) -> bytes:
    """Build a minimal DNS reply with A records using dnslib."""
    from dnslib import DNSRecord, RR, A, QTYPE

    request = DNSRecord.question(qname)
    reply = request.reply()
    for ip in ips:
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))
    return reply.pack()


def _make_dns_query(qname: str) -> bytes:
    """Build a DNS query packet."""
    from dnslib import DNSRecord

    return DNSRecord.question(qname).pack()


# =========================================================================
# Lifecycle
# =========================================================================


class TestLifecycle:
    def test_start_and_stop_no_crash(self, proxy):
        """Proxy starts and stops without errors."""
        proxy.start()
        assert not proxy._stop_event.is_set()
        assert proxy._thread is not None
        assert proxy._thread.is_alive()

        proxy.stop()
        assert proxy._stop_event.is_set()
        assert proxy._thread is None

    def test_stop_without_start(self, proxy):
        """Stopping a proxy that was never started doesn't crash."""
        proxy.stop()

    def test_double_stop(self, proxy):
        """Double stop doesn't crash."""
        proxy.start()
        proxy.stop()
        proxy.stop()

    def test_injected_routes_empty_initially(self, proxy):
        """No routes injected before any queries."""
        assert proxy.injected_routes() == set()


# =========================================================================
# Suffix matching
# =========================================================================


class TestSuffixMatching:
    def test_matches_exact_tld(self, proxy):
        assert proxy._matches("ru.") is True
        assert proxy._matches("ru") is True

    def test_matches_subdomain(self, proxy):
        assert proxy._matches("mail.ru") is True
        assert proxy._matches("sub.mail.ru.") is True

    def test_no_match_partial(self, proxy):
        """'doru' should not match '.ru'."""
        assert proxy._matches("doru") is False
        assert proxy._matches("guru.com") is False

    def test_matches_idn(self, proxy):
        assert proxy._matches("test.рф") is True

    def test_no_match_unrelated(self, proxy):
        assert proxy._matches("google.com") is False

    def test_matches_with_dot_prefix(self, proxy):
        """Suffixes with leading dot work."""
        p = BypassDNSProxy(
            suffixes=[".example.com"],
            upstream_dns="8.8.8.8",
            net=MagicMock(),
            logger=MagicMock(),
            gateway="10.0.0.1",
        )
        assert p._matches("sub.example.com") is True
        assert p._matches("example.com") is True
        assert p._matches("notexample.com") is False


# =========================================================================
# Route injection
# =========================================================================


class TestRouteInjection:
    def test_inject_route_adds_to_set(self, proxy, mock_net):
        """Injecting a route tracks the IP."""
        proxy._inject_route("93.158.134.3", "mail.ru")

        mock_net.add_host_route.assert_called_once_with("93.158.134.3", "192.168.1.1")
        assert "93.158.134.3" in proxy.injected_routes()

    def test_inject_same_ip_twice_deduplicates(self, proxy, mock_net):
        """Same IP injected twice only calls add_host_route once."""
        proxy._inject_route("93.158.134.3", "mail.ru")
        proxy._inject_route("93.158.134.3", "other.ru")

        assert mock_net.add_host_route.call_count == 1

    def test_inject_route_failure_not_tracked(self, proxy, mock_net):
        """Failed route injection doesn't add IP to tracked set."""
        mock_net.add_host_route.return_value = False
        proxy._inject_route("10.0.0.1", "fail.ru")

        assert "10.0.0.1" not in proxy.injected_routes()

    def test_injected_routes_returns_copy(self, proxy, mock_net):
        """injected_routes() returns a copy, not a reference."""
        proxy._inject_route("1.2.3.4", "test.ru")
        routes = proxy.injected_routes()
        routes.add("9.9.9.9")
        assert "9.9.9.9" not in proxy.injected_routes()


# =========================================================================
# Handle + forward
# =========================================================================


class TestHandle:
    def test_handle_matching_query_injects_route(self, proxy, mock_net):
        """Matching DNS query extracts A-records and injects routes."""
        query_data = _make_dns_query("mail.ru")
        reply_data = _make_dns_reply("mail.ru", ["93.158.134.3", "77.88.21.3"])

        proxy._sock = MagicMock()
        proxy._stop_event.clear()

        with patch.object(proxy, "_forward", return_value=reply_data):
            proxy._handle(query_data, ("127.0.0.1", 12345))

        # Both IPs should get host routes
        assert "93.158.134.3" in proxy.injected_routes()
        assert "77.88.21.3" in proxy.injected_routes()
        assert mock_net.add_host_route.call_count == 2

        # Reply sent back to client
        proxy._sock.sendto.assert_called_once_with(reply_data, ("127.0.0.1", 12345))

    def test_handle_non_matching_query_no_injection(self, proxy, mock_net):
        """Non-matching query forwards reply but doesn't inject routes."""
        query_data = _make_dns_query("google.com")
        reply_data = _make_dns_reply("google.com", ["142.250.74.14"])

        proxy._sock = MagicMock()
        proxy._stop_event.clear()

        with patch.object(proxy, "_forward", return_value=reply_data):
            proxy._handle(query_data, ("127.0.0.1", 12345))

        mock_net.add_host_route.assert_not_called()
        proxy._sock.sendto.assert_called_once()

    def test_handle_upstream_timeout(self, proxy, mock_net):
        """Upstream timeout - no crash, no reply sent."""
        query_data = _make_dns_query("mail.ru")
        proxy._sock = MagicMock()
        proxy._stop_event.clear()

        with patch.object(proxy, "_forward", return_value=None):
            proxy._handle(query_data, ("127.0.0.1", 12345))

        mock_net.add_host_route.assert_not_called()
        proxy._sock.sendto.assert_not_called()


class TestForward:
    def test_forward_timeout_returns_none(self, proxy):
        """Upstream timeout returns None."""
        with patch("tv.dns_proxy.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.recvfrom.side_effect = socket.timeout("timed out")
            mock_sock_cls.return_value = mock_sock

            result = proxy._forward(b"\x00" * 12)

        assert result is None

    def test_forward_os_error_returns_none(self, proxy):
        """OS error returns None."""
        with patch("tv.dns_proxy.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.sendto.side_effect = OSError("network unreachable")
            mock_sock_cls.return_value = mock_sock

            result = proxy._forward(b"\x00" * 12)

        assert result is None
