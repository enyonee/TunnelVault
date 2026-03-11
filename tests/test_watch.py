"""Tests for tv.watch module."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch


from tv.watch import (
    Connection,
    TunnelSnapshot,
    _fmt_rate,
    _fmt_total,
    _port_label,
    _build_display,
    _resolve_names,
    _darwin_vpn_ifaces,
    _darwin_iface_bytes,
    _darwin_connections,
    _linux_vpn_ifaces,
    _linux_iface_bytes,
    _linux_connections,
)


# =========================================================================
# Formatting
# =========================================================================


class TestFormatting:
    def test_fmt_rate_bytes(self):
        assert _fmt_rate(500) == "500 B/s"

    def test_fmt_rate_kilobytes(self):
        assert _fmt_rate(12345) == "12.1 KB/s"

    def test_fmt_rate_megabytes(self):
        assert _fmt_rate(1234567) == "1.2 MB/s"

    def test_fmt_rate_zero(self):
        assert _fmt_rate(0) == "0 B/s"

    def test_fmt_total_bytes(self):
        assert _fmt_total(500) == "500 B"

    def test_fmt_total_kb(self):
        assert _fmt_total(12345) == "12.1 KB"

    def test_fmt_total_mb(self):
        assert _fmt_total(1234567) == "1.2 MB"

    def test_fmt_total_gb(self):
        assert _fmt_total(1234567890) == "1.1 GB"

    def test_port_label_https(self):
        assert _port_label("10.0.0.1:443") == "HTTPS"

    def test_port_label_ssh(self):
        assert _port_label("10.0.0.1:22") == "SSH"

    def test_port_label_unknown(self):
        assert _port_label("10.0.0.1:9999") == ""

    def test_port_label_no_port(self):
        assert _port_label("10.0.0.1") == ""


# =========================================================================
# macOS parsing
# =========================================================================


class TestDarwinVpnIfaces:
    IFCONFIG_OUTPUT = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.7 netmask 0xffffff00 broadcast 192.168.1.255
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet 10.8.0.22 --> 10.8.0.21 netmask 0xffffffff
ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
\tinet 10.0.0.2 --> 10.0.0.1 netmask 0xffffffff
"""

    def test_parses_vpn_interfaces(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.IFCONFIG_OUTPUT
            result = _darwin_vpn_ifaces()

        assert result == {"utun4": "10.8.0.22", "ppp0": "10.0.0.2"}
        assert "en0" not in result
        assert "lo0" not in result

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _darwin_vpn_ifaces() == {}


class TestDarwinIfaceBytes:
    NETSTAT_IB_OUTPUT = """\
Name    Mtu   Network       Address            Ipkts Ierrs  Ibytes    Opkts Oerrs  Obytes    Coll
lo0     16384 <Link#1>                          1234     0   56789     1234     0   56789       0
en0     1500  <Link#6>                         12345     0  987654     6543     0  654321       0
utun4   1500  <Link#17>                          100     0  100000       50     0   50000       0
utun4   1500  10.8.0/24     10.8.0.22            100     0  100000       50     0   50000       0
"""

    def test_parses_vpn_bytes(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_IB_OUTPUT
            result = _darwin_iface_bytes()

        assert result == {"utun4": (100000, 50000)}
        assert "en0" not in result

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _darwin_iface_bytes() == {}


class TestDarwinConnections:
    NETSTAT_AN_OUTPUT = """\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  10.8.0.22.54108        10.1.5.30.443          ESTABLISHED
tcp4       0      0  10.8.0.22.54109        10.1.5.31.22           ESTABLISHED
tcp4       0      0  192.168.1.7.55000      34.120.1.1.443         ESTABLISHED
tcp4       0      0  *.631                  *.*                    LISTEN
tcp4       0      0  10.8.0.22.54110        10.1.5.32.80           TIME_WAIT
"""

    def test_filters_by_local_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_AN_OUTPUT
            result = _darwin_connections({"10.8.0.22"})

        assert len(result) == 3  # 2 ESTABLISHED + 1 TIME_WAIT
        assert result[0].local == "10.8.0.22:54108"
        assert result[0].remote == "10.1.5.30:443"
        assert result[0].state == "ESTAB"

    def test_excludes_listen(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_AN_OUTPUT
            result = _darwin_connections({"10.8.0.22"})

        states = [c.state for c in result]
        assert "LISTE" not in states

    def test_excludes_non_vpn_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.NETSTAT_AN_OUTPUT
            result = _darwin_connections({"10.8.0.22"})

        local_ips = {c.local.rsplit(":", 1)[0] for c in result}
        assert "192.168.1.7" not in local_ips

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _darwin_connections({"10.8.0.22"}) == []


# =========================================================================
# Linux parsing
# =========================================================================


class TestLinuxVpnIfaces:
    IP_BR_OUTPUT = """\
lo               UNKNOWN        127.0.0.1/8
eth0             UP             192.168.1.5/24
tun0             UNKNOWN        10.8.0.22/24
ppp0             UP             10.0.0.2 peer 10.0.0.1
"""

    def test_parses_vpn_interfaces(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.IP_BR_OUTPUT
            result = _linux_vpn_ifaces()

        assert result == {"tun0": "10.8.0.22", "ppp0": "10.0.0.2"}
        assert "eth0" not in result

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _linux_vpn_ifaces() == {}


class TestLinuxIfaceBytes:
    PROC_NET_DEV = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456    1234    0    0    0     0          0         0   123456    1234    0    0    0     0       0          0
  eth0: 987654   12345    0    0    0     0          0         0   654321    6543    0    0    0     0       0          0
  tun0: 100000     100    0    0    0     0          0         0    50000      50    0    0    0     0       0          0
"""

    def test_parses_vpn_bytes(self):
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = lambda *a: None
            mock_open.return_value.readlines.return_value = (
                self.PROC_NET_DEV.splitlines(True)
            )
            result = _linux_iface_bytes()

        assert result == {"tun0": (100000, 50000)}
        assert "eth0" not in result

    def test_empty_on_error(self):
        with patch("builtins.open", side_effect=OSError):
            assert _linux_iface_bytes() == {}


class TestLinuxConnections:
    SS_TN_OUTPUT = """\
State      Recv-Q Send-Q Local Address:Port   Peer Address:Port Process
ESTAB      0      0      10.8.0.22:54108      10.1.5.30:443
ESTAB      0      0      10.8.0.22:54109      10.1.5.31:22
ESTAB      0      0      192.168.1.7:55000    34.120.1.1:443
TIME-WAIT  0      0      10.8.0.22:54110      10.1.5.32:80
"""

    def test_filters_by_local_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.SS_TN_OUTPUT
            result = _linux_connections({"10.8.0.22"})

        assert len(result) == 3
        assert result[0].local == "10.8.0.22:54108"
        assert result[0].remote == "10.1.5.30:443"

    def test_excludes_non_vpn_ip(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 0
            mock_cmd.return_value.stdout = self.SS_TN_OUTPUT
            result = _linux_connections({"10.8.0.22"})

        local_ips = {c.local.rsplit(":", 1)[0] for c in result}
        assert "192.168.1.7" not in local_ips

    def test_empty_on_failure(self):
        with patch("tv.watch._cmd") as mock_cmd:
            mock_cmd.return_value.returncode = 1
            mock_cmd.return_value.stdout = ""
            assert _linux_connections({"10.8.0.22"}) == []


# =========================================================================
# Display rendering
# =========================================================================


class TestBuildDisplay:
    def test_renders_with_snapshots(self):
        snapshots = [
            TunnelSnapshot(
                name="fortivpn",
                interface="ppp0",
                ip="10.0.0.2",
                bytes_in=100000,
                bytes_out=50000,
                rate_in=1234.0,
                rate_out=567.0,
                connections=[
                    Connection("10.0.0.2:54108", "10.1.5.30:443", "ESTAB"),
                ],
            ),
        ]
        panel = _build_display(snapshots, datetime(2025, 1, 15, 14, 32, 5), poll_ms=42)
        assert panel is not None
        # Title contains timing, tunnel count, and exit hint
        title = str(panel.title)
        assert "14:32:05" in title
        assert "1 tunnels" in title
        assert "42ms" in title
        assert "Ctrl+C" in title

    def test_renders_empty(self):
        panel = _build_display([], datetime(2025, 1, 15, 14, 32, 5))
        assert panel is not None

    def test_renders_no_connections(self):
        snapshots = [
            TunnelSnapshot(
                name="singbox",
                interface="utun99",
                ip="172.16.0.1",
            ),
        ]
        panel = _build_display(snapshots, datetime(2025, 1, 15, 14, 32, 5))
        assert panel is not None

    def test_renders_many_connections_truncated(self):
        conns = [
            Connection(f"10.0.0.2:{50000 + i}", f"10.1.5.{i}:443", "ESTAB")
            for i in range(50)
        ]
        snapshots = [
            TunnelSnapshot(
                name="test",
                interface="ppp0",
                ip="10.0.0.2",
                connections=conns,
            ),
        ]
        panel = _build_display(snapshots, datetime(2025, 1, 15, 14, 32, 5))
        assert panel is not None

    def test_renders_multiple_tunnels(self):
        snapshots = [
            TunnelSnapshot(name="vpn1", interface="ppp0", ip="10.0.0.2"),
            TunnelSnapshot(name="vpn2", interface="utun99", ip="172.16.0.1"),
        ]
        panel = _build_display(snapshots, datetime(2025, 1, 15, 14, 32, 5))
        assert panel is not None


# =========================================================================
# _resolve_names: interface -> tunnel name matching
# =========================================================================


class TestResolveNames:
    """Test interface-to-profile matching logic."""

    def test_exact_match(self):
        ifaces = {"utun99": "172.19.0.1"}
        result = _resolve_names(ifaces, {"utun99": "singbox"}, {}, show_all=False)
        assert result == {"utun99": "singbox"}

    def test_prefix_match(self):
        ifaces = {"ppp0": "10.0.0.1"}
        result = _resolve_names(ifaces, {}, {"ppp": "fortivpn"}, show_all=False)
        assert result == {"ppp0": "fortivpn"}

    def test_one_profile_one_interface(self):
        """Two utun interfaces but one openvpn profile - only first matches."""
        ifaces = {
            "utun4": "10.8.0.22",
            "utun40": "198.19.254.2",
            "utun99": "172.19.0.1",
        }
        exact = {"utun99": "singbox"}
        prefix = {"utun": "openvpn"}
        result = _resolve_names(ifaces, exact, prefix, show_all=False)
        assert result == {"utun99": "singbox", "utun4": "openvpn"}
        assert "utun40" not in result

    def test_full_setup_3_profiles(self):
        """Real scenario: fortivpn + openvpn + singbox, plus system utun40."""
        ifaces = {
            "ppp0": "10.212.134.103",
            "utun4": "10.8.0.22",
            "utun40": "198.19.254.2",
            "utun99": "172.19.0.1",
        }
        exact = {"utun99": "singbox"}
        prefix = {"ppp": "fortivpn", "utun": "openvpn"}
        result = _resolve_names(ifaces, exact, prefix, show_all=False)
        assert result == {
            "ppp0": "fortivpn",
            "utun4": "openvpn",
            "utun99": "singbox",
        }

    def test_show_all_includes_unknown(self):
        ifaces = {"utun4": "10.8.0.22", "utun40": "198.19.254.2"}
        result = _resolve_names(ifaces, {}, {"utun": "openvpn"}, show_all=True)
        assert result["utun4"] == "openvpn"
        assert result["utun40"] == "utun40"  # raw interface name

    def test_no_config_shows_all(self):
        ifaces = {"ppp0": "10.0.0.1", "utun4": "10.8.0.22"}
        result = _resolve_names(ifaces, {}, {}, show_all=True)
        assert result == {"ppp0": "ppp0", "utun4": "utun4"}

    def test_empty_ifaces(self):
        result = _resolve_names(
            {}, {"utun99": "singbox"}, {"ppp": "forti"}, show_all=False
        )
        assert result == {}

    def test_two_profiles_no_openvpn(self):
        """Remove openvpn, keep fortivpn + singbox. Old openvpn utun4 should be hidden."""
        ifaces = {
            "ppp0": "10.212.134.103",
            "utun4": "10.8.0.22",  # old openvpn, no profile
            "utun40": "198.19.254.2",  # system
            "utun99": "172.19.0.1",
        }
        exact = {"utun99": "singbox"}
        prefix = {"ppp": "fortivpn"}  # no openvpn prefix
        result = _resolve_names(ifaces, exact, prefix, show_all=False)
        assert result == {"ppp0": "fortivpn", "utun99": "singbox"}
        assert "utun4" not in result
        assert "utun40" not in result

    def test_two_profiles_no_fortivpn(self):
        """Remove fortivpn, keep openvpn + singbox."""
        ifaces = {
            "ppp0": "10.212.134.103",  # old fortivpn, no profile
            "utun4": "10.8.0.22",
            "utun40": "198.19.254.2",
            "utun99": "172.19.0.1",
        }
        exact = {"utun99": "singbox"}
        prefix = {"tun": "openvpn", "utun": "openvpn"}
        result = _resolve_names(ifaces, exact, prefix, show_all=False)
        assert result == {"utun4": "openvpn", "utun99": "singbox"}
        assert "ppp0" not in result

    def test_two_profiles_with_state(self):
        """State file provides exact mapping for both profiles."""
        ifaces = {
            "ppp0": "10.212.134.103",
            "utun4": "10.8.0.22",
            "utun40": "198.19.254.2",
            "utun99": "172.19.0.1",
        }
        # State file resolved ppp0 and utun99 to names, no openvpn
        exact = {"ppp0": "fortivpn", "utun99": "singbox"}
        result = _resolve_names(ifaces, exact, {}, show_all=False)
        assert result == {"ppp0": "fortivpn", "utun99": "singbox"}

    def test_two_openvpn_with_state(self):
        """Two openvpn profiles - state file distinguishes them."""
        ifaces = {"utun4": "10.8.0.22", "utun5": "10.9.0.22"}
        exact = {"utun4": "openvpn-work", "utun5": "openvpn-personal"}
        result = _resolve_names(ifaces, exact, {}, show_all=False)
        assert result == {"utun4": "openvpn-work", "utun5": "openvpn-personal"}

    def test_two_profiles_show_all(self):
        """With --all, unknown interfaces show with raw names."""
        ifaces = {
            "ppp0": "10.212.134.103",
            "utun4": "10.8.0.22",
            "utun40": "198.19.254.2",
            "utun99": "172.19.0.1",
        }
        exact = {"utun99": "singbox"}
        prefix = {"ppp": "fortivpn"}
        result = _resolve_names(ifaces, exact, prefix, show_all=True)
        assert result["ppp0"] == "fortivpn"
        assert result["utun99"] == "singbox"
        assert result["utun4"] == "utun4"
        assert result["utun40"] == "utun40"
