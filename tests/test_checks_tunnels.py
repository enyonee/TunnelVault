"""Tests for run_all_from_tunnels() - per-tunnel check execution."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tv.checks import run_all_from_tunnels, _parse_fallback


class TestRunAllFromTunnels:
    def test_empty_tunnels(self):
        results, ext_ip = run_all_from_tunnels([])
        assert results == []
        assert ext_ip == ""

    def test_tunnel_with_no_checks(self, capsys):
        results, _ = run_all_from_tunnels(
            [
                ("openvpn", True, {}),
            ]
        )
        assert results == []

    @patch("tv.checks._check_port", return_value=True)
    def test_port_check_ok(self, mock_port, capsys):
        checks_cfg = {"ports": [{"host": "10.0.0.1", "port": 8080}]}
        results, _ = run_all_from_tunnels([("vpn1", True, checks_cfg)])

        assert len(results) == 1
        assert results[0].status == "ok"
        assert results[0].label == "10.0.0.1:8080"
        mock_port.assert_called_once_with("10.0.0.1", 8080)

    @patch("tv.checks._check_port", return_value=False)
    def test_port_check_fail(self, mock_port, capsys):
        checks_cfg = {"ports": [{"host": "10.0.0.1", "port": 8080}]}
        results, _ = run_all_from_tunnels([("vpn1", True, checks_cfg)])

        assert results[0].status == "fail"

    @patch("tv.checks._check_port", return_value=True)
    def test_tunnel_not_ok_skips_checks(self, mock_port, capsys):
        checks_cfg = {"ports": [{"host": "10.0.0.1", "port": 8080}]}
        results, _ = run_all_from_tunnels([("vpn1", False, checks_cfg)])

        assert results[0].status == "skip"
        mock_port.assert_not_called()

    @patch("tv.checks._check_ping", return_value=True)
    def test_ping_check(self, mock_ping, capsys):
        checks_cfg = {"ping": [{"host": "10.0.0.1", "label": "GW"}]}
        results, _ = run_all_from_tunnels([("vpn1", True, checks_cfg)])

        assert results[0].status == "ok"
        assert "GW" in results[0].label

    @patch("tv.checks._check_dns", return_value=True)
    def test_dns_check(self, mock_dns, capsys):
        checks_cfg = {"dns": [{"name": "app.alpha.local", "server": "10.0.1.1"}]}
        results, _ = run_all_from_tunnels([("vpn1", True, checks_cfg)])

        assert results[0].status == "ok"
        assert "app.alpha.local" in results[0].label

    @patch("tv.checks._check_http_any", return_value=True)
    def test_http_check(self, mock_http, capsys):
        checks_cfg = {"http": ["https://google.com"]}
        results, _ = run_all_from_tunnels([("openvpn", True, checks_cfg)])

        assert results[0].status == "ok"
        assert results[0].label == "google.com"

    @patch("tv.checks.get_external_ip", return_value="1.2.3.4")
    def test_external_ip_check_ok(self, mock_ip, capsys):
        checks_cfg = {"external_ip_url": "https://ifconfig.me"}
        results, ext_ip = run_all_from_tunnels([("openvpn", True, checks_cfg)])

        assert ext_ip == "1.2.3.4"
        assert results[0].status == "ok"
        assert results[0].detail == "1.2.3.4"

    @patch("tv.checks.get_external_ip", return_value=None)
    def test_external_ip_check_fail(self, mock_ip, capsys):
        checks_cfg = {"external_ip_url": "https://ifconfig.me"}
        results, ext_ip = run_all_from_tunnels([("openvpn", True, checks_cfg)])

        assert ext_ip == ""
        assert results[0].status == "fail"

    @patch("tv.checks.get_external_ip")
    def test_external_ip_skip_when_tunnel_down(self, mock_ip, capsys):
        checks_cfg = {"external_ip_url": "https://ifconfig.me"}
        results, _ = run_all_from_tunnels([("openvpn", False, checks_cfg)])

        assert results[0].status == "skip"
        mock_ip.assert_not_called()

    @patch("tv.checks._check_port", return_value=True)
    @patch("tv.checks._check_http_any", return_value=True)
    def test_multiple_tunnels(self, mock_http, mock_port, capsys):
        results, _ = run_all_from_tunnels(
            [
                ("vpn1", True, {"ports": [{"host": "10.0.0.1", "port": 8080}]}),
                ("openvpn", True, {"http": ["https://google.com"]}),
            ]
        )
        assert len(results) == 2
        assert all(r.status == "ok" for r in results)

    @patch("tv.checks._check_port", return_value=True)
    def test_with_logger(self, mock_port, logger, capsys):
        checks_cfg = {"ports": [{"host": "10.0.0.1", "port": 8080}]}
        results, _ = run_all_from_tunnels(
            [("vpn1", True, checks_cfg)],
            logger=logger,
        )
        assert results[0].status == "ok"

    # --- Ping with fallback ---

    @patch("tv.checks._check_ping", return_value=False)
    @patch("tv.checks._check_port", return_value=True)
    def test_ping_fallback_port_ok(self, mock_port, mock_ping, capsys):
        """Ping fails but fallback port check succeeds."""
        checks_cfg = {
            "ping": [{"host": "10.0.0.1", "label": "DNS", "fallback": "port:53"}]
        }
        results, _ = run_all_from_tunnels([("vpn1", True, checks_cfg)])

        assert results[0].status == "ok"
        assert "fallback" in results[0].detail
        assert "port:53" in results[0].detail
        mock_ping.assert_called_once_with("10.0.0.1")
        mock_port.assert_called_once_with("10.0.0.1", 53)

    @patch("tv.checks._check_ping", return_value=False)
    @patch("tv.checks._check_port", return_value=False)
    def test_ping_fallback_port_both_fail(self, mock_port, mock_ping, capsys):
        """Both ping and fallback port fail."""
        checks_cfg = {
            "ping": [{"host": "10.0.0.1", "label": "DNS", "fallback": "port:53"}]
        }
        results, _ = run_all_from_tunnels([("vpn1", True, checks_cfg)])

        assert results[0].status == "fail"
        assert "port:53" in results[0].detail

    @patch("tv.checks._check_ping", return_value=True)
    @patch("tv.checks._check_port")
    def test_ping_ok_skips_fallback(self, mock_port, mock_ping, capsys):
        """When ping succeeds, fallback is not called."""
        checks_cfg = {
            "ping": [{"host": "10.0.0.1", "label": "DNS", "fallback": "port:53"}]
        }
        results, _ = run_all_from_tunnels([("vpn1", True, checks_cfg)])

        assert results[0].status == "ok"
        assert results[0].detail == "ping ok"
        mock_port.assert_not_called()

    @patch("tv.checks._check_ping", return_value=False)
    @patch("tv.checks._check_dns", return_value=True)
    def test_ping_fallback_dns_ok(self, mock_dns, mock_ping, capsys):
        """Ping fails but fallback DNS check succeeds."""
        checks_cfg = {
            "ping": [{"host": "10.0.0.1", "label": "NS", "fallback": "dns:test.local"}]
        }
        results, _ = run_all_from_tunnels([("vpn1", True, checks_cfg)])

        assert results[0].status == "ok"
        assert "dns:test.local" in results[0].detail
        mock_dns.assert_called_once_with("test.local", "10.0.0.1")

    @patch("tv.checks._check_ping", return_value=False)
    def test_ping_no_fallback(self, mock_ping, capsys):
        """Ping fails without fallback - plain fail."""
        checks_cfg = {"ping": [{"host": "10.0.0.1", "label": "GW"}]}
        results, _ = run_all_from_tunnels([("vpn1", True, checks_cfg)])

        assert results[0].status == "fail"
        assert results[0].detail == "no ping"

    def test_ping_skip_when_tunnel_down(self, capsys):
        """Ping check skipped when tunnel is not ok."""
        checks_cfg = {
            "ping": [{"host": "10.0.0.1", "label": "GW", "fallback": "port:53"}]
        }
        results, _ = run_all_from_tunnels([("vpn1", False, checks_cfg)])

        assert results[0].status == "skip"

    @patch("tv.checks._check_ping", return_value=False)
    @patch("tv.checks._check_port", return_value=True)
    def test_ping_fallback_with_logger(self, mock_port, mock_ping, logger, capsys):
        """Fallback result is logged correctly."""
        checks_cfg = {
            "ping": [{"host": "10.0.0.1", "label": "DNS", "fallback": "port:53"}]
        }
        results, _ = run_all_from_tunnels(
            [("vpn1", True, checks_cfg)],
            logger=logger,
        )
        assert results[0].status == "ok"
        # Logger should contain fallback command info
        log_content = logger.log_path.read_text()
        assert "nc -z 10.0.0.1 53" in log_content


class TestParseFallback:
    @pytest.mark.parametrize(
        "spec,expected_label",
        [
            ("port:53", "port:53"),
            ("dns:test.local", "dns:test.local"),
        ],
    )
    def test_valid_fallback(self, spec, expected_label):
        fb = _parse_fallback(spec, "10.0.0.1")
        assert fb is not None
        _, label = fb
        assert label == expected_label

    @pytest.mark.parametrize("spec", ["", "unknown:blah", "justtext"])
    def test_invalid_fallback_returns_none(self, spec):
        assert _parse_fallback(spec, "10.0.0.1") is None
