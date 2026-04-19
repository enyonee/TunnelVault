"""Parse user-friendly targets into routes + DNS components."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from typing import TYPE_CHECKING

from tv.i18n import t

if TYPE_CHECKING:
    from tv.vpn.base import TunnelConfig

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_WILDCARD_RE = re.compile(r"^\*\.(.+)$")

# IPv6: hex digits + ':' (минимум один ':', иначе hostname).
# Покрывает full/compressed/scoped формы. Валидируем через ipaddress.IPv6Address.
_IPv6_RE = re.compile(r"^[0-9a-fA-F:]+$")
_IPv6_CIDR_RE = re.compile(r"^[0-9a-fA-F:]+/\d{1,3}$")


@dataclass
class ParsedTargets:
    networks: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)


def validate_target(target: str) -> tuple[str, str]:
    """Validate a single target string.

    Returns (type, error):
        type: "network" | "host" | "domain" | "hostname" | "" (if invalid)
        error: human-readable error or "" if valid
    """
    target = target.strip()
    if not target:
        return "", ""

    m = _WILDCARD_RE.match(target)
    if m:
        domain = m.group(1)
        if "." not in domain:
            return "", t("routing.wildcard_no_dot", domain=domain)
        return "domain", ""

    if _CIDR_RE.match(target):
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            return "", t("routing.invalid_cidr", target=target)
        return "network", ""

    if _IP_RE.match(target):
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return "", t("routing.invalid_ip", target=target)
        return "host", ""

    # IPv6 ветки ДО hostname fallback (иначе '2001:db8::1' с двоеточиями
    # валится в hostname - гарантированно invalid по regex, но '::1' прошёл бы
    # raw fallback если раньше существовал).
    if _IPv6_CIDR_RE.match(target):
        try:
            ipaddress.IPv6Network(target, strict=False)
        except ValueError:
            return "", t("routing.invalid_cidr", target=target)
        return "network", ""

    if _IPv6_RE.match(target) and ":" in target:
        try:
            ipaddress.IPv6Address(target)
        except ValueError:
            return "", t("routing.invalid_ip", target=target)
        return "host", ""

    # Bare hostname - basic validation
    if re.match(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$",
        target,
    ):
        return "hostname", ""

    return "", t("routing.unrecognized", target=target)


def parse_targets(targets: list[str]) -> ParsedTargets:
    """Parse user-friendly targets into routes + dns components.

    Formats:
        *.domain    → dns domain
        x.x.x.x/N  → network route (CIDR)
        x.x.x.x    → host route
        hostname    → host route (resolved at connect time)
    """
    networks: list[str] = []
    hosts: list[str] = []
    domains: list[str] = []

    for entry in targets:
        entry = entry.strip()
        if not entry:
            continue

        m = _WILDCARD_RE.match(entry)
        if m:
            domains.append(m.group(1))
            continue

        if _CIDR_RE.match(entry):
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            networks.append(entry)
            continue

        if _IP_RE.match(entry):
            try:
                ipaddress.ip_address(entry)
            except ValueError:
                continue
            hosts.append(entry)
            continue

        # IPv6 ветки ДО fallback (H4): '2001:db8::1' содержит ':' не попадает
        # под hostname regex, но без этих веток попал бы в hosts как raw string,
        # а engine пытался бы resolve его через getaddrinfo.
        if _IPv6_CIDR_RE.match(entry):
            try:
                ipaddress.IPv6Network(entry, strict=False)
            except ValueError:
                continue
            networks.append(entry)
            continue

        if _IPv6_RE.match(entry) and ":" in entry:
            try:
                ipaddress.IPv6Address(entry)
            except ValueError:
                continue
            hosts.append(entry)
            continue

        # Bare hostname
        hosts.append(entry)

    return ParsedTargets(networks=networks, hosts=hosts, domains=domains)


def merge_targets_into_config(tcfg: TunnelConfig, parsed: ParsedTargets) -> None:
    """Merge parsed targets into tcfg.routes and tcfg.dns (no duplicates)."""
    existing_nets = set(tcfg.routes.get("networks", []))
    existing_hosts = set(tcfg.routes.get("hosts", []))
    existing_domains = set(tcfg.dns.get("domains", []))

    new_nets = [n for n in parsed.networks if n not in existing_nets]
    new_hosts = [h for h in parsed.hosts if h not in existing_hosts]
    new_domains = [d for d in parsed.domains if d not in existing_domains]

    if new_nets:
        tcfg.routes.setdefault("networks", []).extend(new_nets)
    if new_hosts:
        tcfg.routes.setdefault("hosts", []).extend(new_hosts)
    if new_domains:
        tcfg.dns.setdefault("domains", []).extend(new_domains)
