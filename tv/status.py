"""Status: show current VPN state without defaults.toml or Engine."""

from __future__ import annotations

import os
import platform
from typing import Optional

from tv import proc, ui
from tv.checks import get_external_ip
from tv.app_config import cfg
from tv.i18n import t
from tv.net import NetManager

IS_WINDOWS = platform.system() == "Windows"


def _section(title: str) -> None:
    print(f"\n  {ui.CYAN}{ui.BOLD}{title}{ui.NC}")


def _show_processes() -> None:
    """Show running VPN processes from plugin registry."""
    from tv.vpn.registry import available_types, get_plugin

    _section(t("status.vpn_processes"))
    found_any = False
    for type_name in available_types():
        plugin_cls = get_plugin(type_name)
        for pname in plugin_cls.process_names:
            pids = proc.find_pids(pname)
            if pids:
                found_any = True
                pid_str = ", ".join(str(p) for p in pids)
                print(f"    {ui.GREEN}●{ui.NC} {pname}: PID {pid_str}")
    if not found_any:
        print(f"    {ui.DIM}{t('status.no_vpn_processes')}{ui.NC}")


def _show_interfaces(net: NetManager) -> None:
    """Show tunnel interfaces (tun*, utun*, ppp* on Unix; all non-loopback on Windows)."""
    _section(t("status.tunnel_ifaces"))
    ifaces = net.interfaces()
    tunnel_prefixes = ("tun", "utun", "ppp")
    found = False
    for name, ip in sorted(ifaces.items()):
        if IS_WINDOWS:
            # Windows VPN adapters have arbitrary names; show all non-loopback
            if ip.startswith("127."):
                continue
        elif not any(name.startswith(p) for p in tunnel_prefixes):
            continue
        found = True
        print(f"    {ui.GREEN}●{ui.NC} {name}: {ip}")
    if not found:
        print(f"    {ui.DIM}{t('status.no_tunnel_ifaces')}{ui.NC}")


def _show_resolvers() -> None:
    """Show DNS resolver configuration created by tunnelvault."""
    _section(t("status.resolver_files"))

    if IS_WINDOWS:
        # Show NRPT rules created by tunnelvault
        import subprocess
        r = subprocess.run(
            ["powershell", "-Command",
             "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'tunnelvault' } | "
             "Format-Table Namespace, NameServers -AutoSize"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            for line in r.stdout.strip().splitlines():
                if line.strip() and not line.startswith("-"):
                    print(f"    {ui.GREEN}●{ui.NC} {line.strip()}")
        else:
            print(f"    {ui.DIM}{t('status.no_resolver_files')}{ui.NC}")
        return

    resolver_dir = cfg.paths.resolver_dir
    if not os.path.isdir(resolver_dir):
        print(f"    {ui.DIM}{t('status.no_resolver_dir', dir=resolver_dir)}{ui.NC}")
        return

    found = False
    try:
        entries = sorted(os.listdir(resolver_dir))
    except OSError:
        print(f"    {ui.DIM}{t('status.resolver_read_error', dir=resolver_dir)}{ui.NC}")
        return

    for name in entries:
        path = os.path.join(resolver_dir, name)
        try:
            with open(path) as f:
                content = f.read()
        except OSError:
            continue
        if "# tunnelvault" in content:
            found = True
            # Extract nameservers
            ns = [l.split()[-1] for l in content.splitlines()
                  if l.strip().startswith("nameserver")]
            ns_str = ", ".join(ns) if ns else "?"
            print(f"    {ui.GREEN}●{ui.NC} {name} -> {ns_str}")

    if not found:
        print(f"    {ui.DIM}{t('status.no_resolver_files')}{ui.NC}")


def _show_gateway(net: NetManager) -> None:
    """Show default gateway."""
    _section(t("status.gateway_title"))
    gw = net.default_gateway()
    if gw:
        print(f"    {gw}")
    else:
        print(f"    {ui.YELLOW}{t('status.gateway_unknown')}{ui.NC}")


def _show_external_ip() -> None:
    """Show external IP."""
    _section(t("status.external_ip"))
    ip = get_external_ip("https://ifconfig.me", timeout=3)
    if ip:
        print(f"    {ip}")
    else:
        print(f"    {ui.DIM}{t('status.external_ip_fail')}{ui.NC}")


def run(net: Optional[NetManager] = None) -> None:
    """Show current VPN state. Does not require defaults.toml."""
    if net is None:
        from tv.net import create
        net = create()

    # Ensure plugins are registered
    from tv.vpn import openvpn, fortivpn, singbox  # noqa: F401

    print(f"\n  {ui.BOLD}{t('status.title')}{ui.NC}")

    _show_processes()
    _show_interfaces(net)
    _show_resolvers()
    _show_gateway(net)
    _show_external_ip()
    print()
