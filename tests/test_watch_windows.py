"""Tests for tv.watch: Windows-specific data collection."""

from __future__ import annotations

from unittest.mock import patch

from tv.watch import (
    _windows_vpn_ifaces,
    _windows_iface_bytes,
    _windows_connections,
    _is_vpn_iface,
)


# =========================================================================
# _is_vpn_iface on Windows
# =========================================================================

class TestIsVpnIfaceWindows:
    @patch("tv.watch._IS_WINDOWS", True)
    def test_accepts_any_name(self):
        assert _is_vpn_iface("VPN Connection") is True
        assert _is_vpn_iface("Ethernet") is True
        assert _is_vpn_iface("WireGuard Tunnel") is True
        assert _is_vpn_iface("PPP adapter") is True


# =========================================================================
# _windows_vpn_ifaces: PowerShell Get-NetIPAddress parsing
# =========================================================================

class TestWindowsVpnIfaces:
    PS_OUTPUT = (
        "Ethernet                     192.168.1.5\n"
        "VPN Connection               10.0.0.2\n"
        "Loopback Pseudo-Interface 1  127.0.0.1\n"
        "Wi-Fi                        192.168.0.100\n"
    )

    def test_parses_interfaces(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.PS_OUTPUT
            result = _windows_vpn_ifaces()

        assert result["Ethernet"] == "192.168.1.5"
        assert result["VPN Connection"] == "10.0.0.2"
        assert result["Wi-Fi"] == "192.168.0.100"

    def test_excludes_loopback(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.PS_OUTPUT
            result = _windows_vpn_ifaces()

        assert "Loopback Pseudo-Interface 1" not in result

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _windows_vpn_ifaces() == {}

    def test_empty_lines_ignored(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = "\n\n  \n"
            assert _windows_vpn_ifaces() == {}

    def test_spaces_in_name(self):
        """Interface names with multiple spaces are handled correctly."""
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = "Local Area Connection 2   10.10.10.1\n"
            result = _windows_vpn_ifaces()

        assert result["Local Area Connection 2"] == "10.10.10.1"

    def test_single_interface(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = "Ethernet  192.168.1.5\n"
            result = _windows_vpn_ifaces()

        assert result == {"Ethernet": "192.168.1.5"}


# =========================================================================
# _windows_iface_bytes: PowerShell Get-NetAdapterStatistics parsing
# =========================================================================

class TestWindowsIfaceBytes:
    PS_OUTPUT = (
        "Ethernet                     1048576    524288\n"
        "Wi-Fi                        2097152    1048576\n"
    )

    def test_parses_bytes(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.PS_OUTPUT
            result = _windows_iface_bytes()

        assert result["Ethernet"] == (1048576, 524288)
        assert result["Wi-Fi"] == (2097152, 1048576)

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _windows_iface_bytes() == {}

    def test_empty_lines_ignored(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = "\n\n  \n"
            assert _windows_iface_bytes() == {}

    def test_non_numeric_bytes_skipped(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = "Ethernet   N/A   N/A\n"
            assert _windows_iface_bytes() == {}

    def test_spaces_in_adapter_name(self):
        """Adapter names with spaces parsed via rsplit."""
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = "Local Area Connection   999   888\n"
            result = _windows_iface_bytes()

        assert result["Local Area Connection"] == (999, 888)

    def test_large_byte_counts(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = "Ethernet   12345678901234   9876543210987\n"
            result = _windows_iface_bytes()

        assert result["Ethernet"] == (12345678901234, 9876543210987)


# =========================================================================
# _windows_connections: netstat -an -p TCP parsing
# =========================================================================

class TestWindowsConnections:
    NETSTAT_OUTPUT = (
        "\n"
        "Active Connections\n"
        "\n"
        "  Proto  Local Address          Foreign Address        State\n"
        "  TCP    10.0.0.2:54108         10.1.5.30:443          ESTABLISHED\n"
        "  TCP    10.0.0.2:54109         10.1.5.31:22           ESTABLISHED\n"
        "  TCP    192.168.1.5:55000      34.120.1.1:443         ESTABLISHED\n"
        "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING\n"
        "  TCP    10.0.0.2:54110         10.1.5.32:80           TIME_WAIT\n"
        "  TCP    10.0.0.2:54111         10.1.5.33:3389         CLOSE_WAIT\n"
    )

    def test_filters_by_local_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_OUTPUT
            result = _windows_connections({"10.0.0.2"})

        assert len(result) == 4  # 2 ESTABLISHED + TIME_WAIT + CLOSE_WAIT
        assert result[0].local == "10.0.0.2:54108"
        assert result[0].remote == "10.1.5.30:443"
        assert result[0].state == "ESTAB"

    def test_excludes_listening(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_OUTPUT
            result = _windows_connections({"10.0.0.2", "0.0.0.0"})

        states = [c.state for c in result]
        assert "LISTE" not in states

    def test_excludes_non_vpn_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_OUTPUT
            result = _windows_connections({"10.0.0.2"})

        local_ips = {c.local.rsplit(":", 1)[0] for c in result}
        assert "192.168.1.5" not in local_ips

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _windows_connections({"10.0.0.2"}) == []

    def test_empty_set_returns_nothing(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_OUTPUT
            assert _windows_connections(set()) == []

    def test_multiple_local_ips(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_OUTPUT
            result = _windows_connections({"10.0.0.2", "192.168.1.5"})

        assert len(result) == 5  # 4 from 10.0.0.2 + 1 from 192.168.1.5

    def test_state_truncated_to_5_chars(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_OUTPUT
            result = _windows_connections({"10.0.0.2"})

        # ESTABLISHED -> ESTAB, TIME_WAIT -> TIME_, CLOSE_WAIT -> CLOSE
        states = [c.state for c in result]
        assert "ESTAB" in states
        assert "TIME_" in states
        assert "CLOSE" in states
