"""Kill switch: block non-VPN traffic via platform firewall rules.

When enabled, only traffic through VPN interfaces and to VPN server IPs
is allowed. If the VPN process dies, traffic does not leak to the open network.

Platform implementations:
- macOS: pf (Packet Filter) anchor
- Linux: iptables chain
- Windows: Windows Firewall via netsh
"""

from __future__ import annotations

import ipaddress
import platform
import re
from abc import ABC, abstractmethod
from typing import Optional

from tv.logger import Logger
from tv.net import _run


def _is_valid_ip(s: str) -> bool:
    """Validate IP address (IPv4 или IPv6, без CIDR)."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _is_valid_ipv4(s: str) -> bool:
    """Validate IPv4 address (строго IPv4, без CIDR)."""
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def _is_valid_ipv6(s: str) -> bool:
    """Validate IPv6 address (строго IPv6, без CIDR)."""
    try:
        ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


def _is_valid_network(s: str) -> bool:
    """Validate network in CIDR notation (IPv4 или IPv6)."""
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _is_valid_ipv4_network(s: str) -> bool:
    """Validate IPv4 network in CIDR notation (строго IPv4)."""
    try:
        ipaddress.IPv4Network(s, strict=False)
        return True
    except ValueError:
        return False


def _is_valid_ipv6_network(s: str) -> bool:
    """Validate IPv6 network in CIDR notation (строго IPv6)."""
    try:
        ipaddress.IPv6Network(s, strict=False)
        return True
    except ValueError:
        return False


def _is_valid_iface(s: str) -> bool:
    """Validate interface name (alphanumeric + limited symbols)."""
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", s))


def _sanitize_ips(ips: list[str], log_fn=None) -> list[str]:
    """Filter list to valid IPs only, log rejected."""
    result = []
    for ip in ips:
        if _is_valid_ip(ip):
            result.append(ip)
        elif log_fn:
            log_fn("WARN", f"rejected invalid IP: {ip!r}")
    return result


def _sanitize_networks(nets: list[str], log_fn=None) -> list[str]:
    """Filter list to valid CIDR networks only, log rejected."""
    result = []
    for n in nets:
        if _is_valid_network(n):
            result.append(n)
        elif log_fn:
            log_fn("WARN", f"rejected invalid network: {n!r}")
    return result


def _sanitize_ifaces(ifaces: list[str], log_fn=None) -> list[str]:
    """Filter list to valid interface names only, log rejected."""
    result = []
    for i in ifaces:
        if _is_valid_iface(i):
            result.append(i)
        elif log_fn:
            log_fn("WARN", f"rejected invalid interface: {i!r}")
    return result


def _split_by_family(ips: list[str]) -> tuple[list[str], list[str]]:
    """Разделить список IP на (ipv4, ipv6). Игнорирует уже невалидные."""
    v4: list[str] = []
    v6: list[str] = []
    for ip in ips:
        if _is_valid_ipv4(ip):
            v4.append(ip)
        elif _is_valid_ipv6(ip):
            v6.append(ip)
    return v4, v6


def _split_networks_by_family(nets: list[str]) -> tuple[list[str], list[str]]:
    """Разделить список CIDR на (ipv4, ipv6). Игнорирует невалидные."""
    v4: list[str] = []
    v6: list[str] = []
    for n in nets:
        if _is_valid_ipv4_network(n):
            v4.append(n)
        elif _is_valid_ipv6_network(n):
            v6.append(n)
    return v4, v6


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class KillSwitch(ABC):
    """Platform-agnostic kill switch interface."""

    def __init__(self, log: Optional[Logger] = None) -> None:
        self.log = log
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    @abstractmethod
    def enable(
        self,
        *,
        vpn_interfaces: list[str],
        vpn_server_ips: list[str],
        bypass_ips: list[str],
        bypass_networks: list[str],
    ) -> bool:
        """Apply firewall rules. Returns True on success."""

    @abstractmethod
    def disable(self) -> bool:
        """Remove firewall rules. Returns True on success."""

    def _log(self, level: str, msg: str) -> None:
        if self.log:
            self.log.log(level, f"killswitch: {msg}")

    def _sanitize(
        self,
        *,
        vpn_interfaces: list[str],
        vpn_server_ips: list[str],
        bypass_ips: list[str],
        bypass_networks: list[str],
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        """Validate and filter all inputs before passing to firewall commands."""
        return (
            _sanitize_ifaces(vpn_interfaces, self._log),
            _sanitize_ips(vpn_server_ips, self._log),
            _sanitize_ips(bypass_ips, self._log),
            _sanitize_networks(bypass_networks, self._log),
        )


# ---------------------------------------------------------------------------
# macOS - pf anchor
# ---------------------------------------------------------------------------

_PF_ANCHOR = "com.tunnelvault.killswitch"


class DarwinKillSwitch(KillSwitch):
    """macOS kill switch using pf (Packet Filter) anchor."""

    def enable(
        self,
        *,
        vpn_interfaces: list[str],
        vpn_server_ips: list[str],
        bypass_ips: list[str],
        bypass_networks: list[str],
    ) -> bool:
        vpn_interfaces, vpn_server_ips, bypass_ips, bypass_networks = self._sanitize(
            vpn_interfaces=vpn_interfaces,
            vpn_server_ips=vpn_server_ips,
            bypass_ips=bypass_ips,
            bypass_networks=bypass_networks,
        )
        rules = _build_pf_rules(
            vpn_interfaces=vpn_interfaces,
            vpn_server_ips=vpn_server_ips,
            bypass_ips=bypass_ips,
            bypass_networks=bypass_networks,
        )

        # Load rules into anchor
        r = _run(
            ["sudo", "pfctl", "-a", _PF_ANCHOR, "-f", "/dev/stdin"],
            input=rules,
        )
        if r.returncode != 0:
            self._log("ERROR", f"pfctl load failed: {r.stderr}")
            return False

        # Ensure anchor is referenced in main ruleset
        if not self._ensure_anchor_ref():
            self._log("WARN", "anchor reference not added, rules may not apply")

        # Enable pf if not already enabled
        _run(["sudo", "pfctl", "-e"])

        self._active = True
        self._log("INFO", f"enabled ({len(rules.splitlines())} rules)")
        return True

    def disable(self) -> bool:
        # Flush anchor rules
        r = _run(["sudo", "pfctl", "-a", _PF_ANCHOR, "-F", "all"])
        ok = r.returncode == 0

        # Remove anchor reference from main ruleset
        self._remove_anchor_ref()

        self._active = False
        self._log("INFO", "disabled")
        return ok

    def _ensure_anchor_ref(self) -> bool:
        """Add anchor reference to /etc/pf.conf if not present."""
        anchor_line = f'anchor "{_PF_ANCHOR}"'
        try:
            with open("/etc/pf.conf") as f:
                content = f.read()
            if anchor_line in content:
                return True
        except OSError:
            return False

        # Append anchor reference
        new_content = content.rstrip("\n") + f"\n{anchor_line}\n"
        r = _run(["sudo", "tee", "/etc/pf.conf"], input=new_content)
        if r.returncode != 0:
            return False

        # Reload main ruleset
        _run(["sudo", "pfctl", "-f", "/etc/pf.conf"])
        return True

    def _remove_anchor_ref(self) -> None:
        """Remove anchor reference from /etc/pf.conf."""
        anchor_line = f'anchor "{_PF_ANCHOR}"'
        try:
            with open("/etc/pf.conf") as f:
                lines = f.readlines()
        except OSError:
            return

        filtered = [line for line in lines if anchor_line not in line]
        if len(filtered) == len(lines):
            return  # nothing to remove

        r = _run(["sudo", "tee", "/etc/pf.conf"], input="".join(filtered))
        if r.returncode == 0:
            _run(["sudo", "pfctl", "-f", "/etc/pf.conf"])


def _build_pf_rules(
    *,
    vpn_interfaces: list[str],
    vpn_server_ips: list[str],
    bypass_ips: list[str],
    bypass_networks: list[str],
) -> str:
    """Build pf rules for kill switch anchor."""
    lines: list[str] = [
        "# tunnelvault kill switch - auto-generated, do not edit",
        "# Allow loopback (in + out)",
        "pass quick on lo0 all",
    ]

    # --- Outbound rules ---

    # Allow traffic to VPN server IPs (needed to establish tunnel)
    for ip in vpn_server_ips:
        lines.append(f"pass out quick inet proto {{ tcp, udp }} to {ip}")

    # Allow bypass IPs
    for ip in bypass_ips:
        lines.append(f"pass out quick inet to {ip}")

    # Allow bypass networks
    for net in bypass_networks:
        lines.append(f"pass out quick inet to {net}")

    # Allow DHCP (needed to get/renew IP)
    lines.append("pass out quick inet proto udp from any port 68 to any port 67")

    # Allow DNS to localhost (for local DNS proxy)
    lines.append("pass out quick inet proto { tcp, udp } to 127.0.0.1 port 53")

    # Allow all traffic through VPN interfaces (in + out)
    for iface in vpn_interfaces:
        lines.append(f"pass quick on {iface} all")

    # --- Inbound rules ---

    # Allow inbound from VPN server IPs (tunnel establishment responses)
    for ip in vpn_server_ips:
        lines.append(f"pass in quick inet proto {{ tcp, udp }} from {ip}")

    # Allow DHCP responses
    lines.append("pass in quick inet proto udp from any port 67 to any port 68")

    # Block everything else (out + in)
    lines.append("block out inet all")
    lines.append("block in inet all")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Linux - iptables chain
# ---------------------------------------------------------------------------

_IPTABLES_CHAIN = "TUNNELVAULT_KS"
_IPTABLES_CHAIN_IN = "TUNNELVAULT_KS_IN"


class LinuxKillSwitch(KillSwitch):
    """Linux kill switch using iptables chains on OUTPUT and INPUT."""

    def enable(
        self,
        *,
        vpn_interfaces: list[str],
        vpn_server_ips: list[str],
        bypass_ips: list[str],
        bypass_networks: list[str],
    ) -> bool:
        vpn_interfaces, vpn_server_ips, bypass_ips, bypass_networks = self._sanitize(
            vpn_interfaces=vpn_interfaces,
            vpn_server_ips=vpn_server_ips,
            bypass_ips=bypass_ips,
            bypass_networks=bypass_networks,
        )
        # Clean up any previous rules first
        self._flush_chain()

        # Create chain
        _run(["sudo", "iptables", "-N", _IPTABLES_CHAIN])

        # Allow loopback
        _run(["sudo", "iptables", "-A", _IPTABLES_CHAIN, "-o", "lo", "-j", "ACCEPT"])

        # Allow VPN server IPs
        for ip in vpn_server_ips:
            _run(
                [
                    "sudo",
                    "iptables",
                    "-A",
                    _IPTABLES_CHAIN,
                    "-d",
                    ip,
                    "-j",
                    "ACCEPT",
                ]
            )

        # Allow bypass IPs
        for ip in bypass_ips:
            _run(
                [
                    "sudo",
                    "iptables",
                    "-A",
                    _IPTABLES_CHAIN,
                    "-d",
                    ip,
                    "-j",
                    "ACCEPT",
                ]
            )

        # Allow bypass networks
        for net in bypass_networks:
            _run(
                [
                    "sudo",
                    "iptables",
                    "-A",
                    _IPTABLES_CHAIN,
                    "-d",
                    net,
                    "-j",
                    "ACCEPT",
                ]
            )

        # Allow DHCP
        _run(
            [
                "sudo",
                "iptables",
                "-A",
                _IPTABLES_CHAIN,
                "-p",
                "udp",
                "--sport",
                "68",
                "--dport",
                "67",
                "-j",
                "ACCEPT",
            ]
        )

        # Allow VPN interface families (tun+, ppp+ wildcards cover all instances)
        for prefix in ("tun+", "ppp+"):
            _run(
                [
                    "sudo",
                    "iptables",
                    "-A",
                    _IPTABLES_CHAIN,
                    "-o",
                    prefix,
                    "-j",
                    "ACCEPT",
                ]
            )

        # Drop everything else (OUTPUT)
        _run(["sudo", "iptables", "-A", _IPTABLES_CHAIN, "-j", "DROP"])

        # Insert jump to our chain at the top of OUTPUT
        _run(["sudo", "iptables", "-I", "OUTPUT", "1", "-j", _IPTABLES_CHAIN])

        # --- INPUT chain: block unsolicited inbound on non-VPN interfaces ---
        _run(["sudo", "iptables", "-N", _IPTABLES_CHAIN_IN])

        # Allow loopback inbound
        _run(
            [
                "sudo",
                "iptables",
                "-A",
                _IPTABLES_CHAIN_IN,
                "-i",
                "lo",
                "-j",
                "ACCEPT",
            ]
        )

        # Allow inbound on VPN interface families
        for prefix in ("tun+", "ppp+"):
            _run(
                [
                    "sudo",
                    "iptables",
                    "-A",
                    _IPTABLES_CHAIN_IN,
                    "-i",
                    prefix,
                    "-j",
                    "ACCEPT",
                ]
            )

        # Allow inbound from VPN server IPs (tunnel handshake)
        for ip in vpn_server_ips:
            _run(
                [
                    "sudo",
                    "iptables",
                    "-A",
                    _IPTABLES_CHAIN_IN,
                    "-s",
                    ip,
                    "-j",
                    "ACCEPT",
                ]
            )

        # Allow DHCP responses
        _run(
            [
                "sudo",
                "iptables",
                "-A",
                _IPTABLES_CHAIN_IN,
                "-p",
                "udp",
                "--sport",
                "67",
                "--dport",
                "68",
                "-j",
                "ACCEPT",
            ]
        )

        # Drop everything else (INPUT)
        _run(["sudo", "iptables", "-A", _IPTABLES_CHAIN_IN, "-j", "DROP"])

        # Insert jump to our chain at the top of INPUT
        _run(["sudo", "iptables", "-I", "INPUT", "1", "-j", _IPTABLES_CHAIN_IN])

        self._active = True
        self._log("INFO", "enabled (iptables)")
        return True

    def disable(self) -> bool:
        ok = self._flush_chain()
        self._active = False
        self._log("INFO", "disabled (iptables)")
        return ok

    def _flush_chain(self) -> bool:
        """Remove jump rules and flush/delete both chains."""
        # Remove jumps (may fail if not present - ok)
        _run(["sudo", "iptables", "-D", "OUTPUT", "-j", _IPTABLES_CHAIN])
        _run(["sudo", "iptables", "-D", "INPUT", "-j", _IPTABLES_CHAIN_IN])
        # Flush and delete OUTPUT chain
        _run(["sudo", "iptables", "-F", _IPTABLES_CHAIN])
        r1 = _run(["sudo", "iptables", "-X", _IPTABLES_CHAIN])
        # Flush and delete INPUT chain
        _run(["sudo", "iptables", "-F", _IPTABLES_CHAIN_IN])
        r2 = _run(["sudo", "iptables", "-X", _IPTABLES_CHAIN_IN])
        ok1 = r1.returncode == 0 or "No chain" in (r1.stderr or "")
        ok2 = r2.returncode == 0 or "No chain" in (r2.stderr or "")
        return ok1 and ok2


# ---------------------------------------------------------------------------
# Windows - netsh advfirewall
# ---------------------------------------------------------------------------

_WIN_RULE_PREFIX = "TunnelVault-KS"


class WindowsKillSwitch(KillSwitch):
    """Windows kill switch using netsh advfirewall rules."""

    def enable(
        self,
        *,
        vpn_interfaces: list[str],
        vpn_server_ips: list[str],
        bypass_ips: list[str],
        bypass_networks: list[str],
    ) -> bool:
        vpn_interfaces, vpn_server_ips, bypass_ips, bypass_networks = self._sanitize(
            vpn_interfaces=vpn_interfaces,
            vpn_server_ips=vpn_server_ips,
            bypass_ips=bypass_ips,
            bypass_networks=bypass_networks,
        )
        # Clean up previous rules
        self.disable()

        # Block all outbound by default
        r = _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={_WIN_RULE_PREFIX}-BlockAll",
                "dir=out",
                "action=block",
                "protocol=any",
            ]
        )
        if r.returncode != 0:
            self._log("ERROR", f"block-all rule failed: {r.stderr}")
            return False

        # Allow loopback
        _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={_WIN_RULE_PREFIX}-AllowLoopback",
                "dir=out",
                "action=allow",
                "remoteip=127.0.0.0/8",
            ]
        )

        # Allow VPN server IPs
        if vpn_server_ips:
            _run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={_WIN_RULE_PREFIX}-AllowVPNServers",
                    "dir=out",
                    "action=allow",
                    f"remoteip={','.join(vpn_server_ips)}",
                ]
            )

        # Allow bypass IPs and networks
        allow_list = bypass_ips + bypass_networks
        if allow_list:
            _run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={_WIN_RULE_PREFIX}-AllowBypass",
                    "dir=out",
                    "action=allow",
                    f"remoteip={','.join(allow_list)}",
                ]
            )

        # Allow DHCP
        _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={_WIN_RULE_PREFIX}-AllowDHCP",
                "dir=out",
                "action=allow",
                "protocol=udp",
                "localport=68",
                "remoteport=67",
            ]
        )

        # --- Inbound rules ---

        # Block all inbound by default
        _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={_WIN_RULE_PREFIX}-BlockAllIn",
                "dir=in",
                "action=block",
                "protocol=any",
            ]
        )

        # Allow inbound on loopback
        _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={_WIN_RULE_PREFIX}-AllowLoopbackIn",
                "dir=in",
                "action=allow",
                "remoteip=127.0.0.0/8",
            ]
        )

        # Allow inbound from VPN server IPs
        if vpn_server_ips:
            _run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={_WIN_RULE_PREFIX}-AllowVPNServersIn",
                    "dir=in",
                    "action=allow",
                    f"remoteip={','.join(vpn_server_ips)}",
                ]
            )

        # Allow DHCP responses
        _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={_WIN_RULE_PREFIX}-AllowDHCPIn",
                "dir=in",
                "action=allow",
                "protocol=udp",
                "localport=68",
                "remoteport=67",
            ]
        )

        self._active = True
        self._log("INFO", "enabled (netsh)")
        return True

    def disable(self) -> bool:
        # Delete all rules with our prefix (outbound + inbound)
        _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={_WIN_RULE_PREFIX}-BlockAll",
            ]
        )
        for suffix in (
            "AllowLoopback",
            "AllowVPNServers",
            "AllowBypass",
            "AllowDHCP",
            "BlockAllIn",
            "AllowLoopbackIn",
            "AllowVPNServersIn",
            "AllowDHCPIn",
        ):
            _run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"name={_WIN_RULE_PREFIX}-{suffix}",
                ]
            )

        self._active = False
        self._log("INFO", "disabled (netsh)")
        return True


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create(log: Optional[Logger] = None) -> KillSwitch:
    """Create platform-appropriate KillSwitch instance."""
    system = platform.system()
    if system == "Darwin":
        return DarwinKillSwitch(log)
    if system == "Windows":
        return WindowsKillSwitch(log)
    return LinuxKillSwitch(log)
