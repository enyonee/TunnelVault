"""Disconnect all VPN connections and clean up."""

from __future__ import annotations

import glob
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from tv import proc
from tv.app_config import cfg
from tv.i18n import t

if TYPE_CHECKING:
    from tv.logger import Logger
    from tv.net import NetManager


def _safe(fn, description: str, log: Optional[Logger] = None) -> None:
    """Run fn, swallow exceptions so cleanup continues."""
    try:
        fn()
    except Exception as e:
        print(f"  ⚠ {description}: {e}", file=sys.stderr)
        if log:
            log.log("WARN", f"Disconnect: {description}: {e}")


def get_vpn_server_routes(defs: dict) -> dict:
    """Extract VPN server routes config from defs (supports both formats)."""
    if "global" in defs:
        return defs.get("global", {}).get("vpn_server_routes", {})
    return defs.get("routes", {}).get("vpn_servers", {})


def get_bypass_routes(defs: dict) -> dict:
    """Extract bypass routes config from defs."""
    return defs.get("global", {}).get("bypass", {})


def get_kill_switch_enabled(defs: dict) -> bool:
    """Check if kill switch is enabled in config."""
    return bool(defs.get("global", {}).get("kill_switch", False))


def cleanup_global_routes(
    net: NetManager,
    log: Optional[Logger],
    defs: dict,
    *,
    skip_dns_suffix: bool = False,
    script_dir: Optional[Path] = None,
) -> None:
    """Delete global VPN server routes, bypass routes, and DNS resolver files.

    Called from engine.disconnect_all() and emergency disconnect.
    Does NOT restore IPv6 - caller handles that separately.

    skip_dns_suffix: skip domain_suffix resolver cleanup (engine._stop_dns_proxy handles it).
    """
    routes_cfg = get_vpn_server_routes(defs)
    static_hosts = routes_cfg.get("hosts", [])
    resolve_hosts = routes_cfg.get("resolve", [])

    if static_hosts or resolve_hosts:
        print(f"🧹 {t('disc.deleting_routes')}")
        for ip in static_hosts:
            _safe(lambda ip=ip: net.delete_host_route(ip), f"del route {ip}", log)
        # Читаем кеш resolved IPs — DNS при disconnect не нужен
        resolved_cache: dict[str, list[str]] = {}
        if script_dir is not None:
            from tv.app_config import cfg as _cfg
            cache_path = script_dir / _cfg.paths.log_dir / "resolved-route-cache.json"
            try:
                resolved_cache = json.loads(cache_path.read_text())
            except (OSError, json.JSONDecodeError):
                pass
        for hostname in resolve_hosts:
            for ip in resolved_cache.get(hostname, []):
                _safe(lambda ip=ip: net.delete_host_route(ip), f"del resolved {hostname} ({ip})", log)

    # Cleanup bypass routes
    bypass_cfg = get_bypass_routes(defs)
    bypass_hosts = bypass_cfg.get("hosts", [])
    bypass_domains = bypass_cfg.get("domains", [])
    bypass_networks = bypass_cfg.get("networks", [])

    if bypass_hosts or bypass_domains or bypass_networks:
        print(f"🧹 {t('disc.deleting_bypass')}")
        for ip in bypass_hosts:
            _safe(lambda ip=ip: net.delete_host_route(ip), f"del bypass {ip}", log)
        for hostname in bypass_domains:
            _safe(
                lambda h=hostname: [
                    net.delete_host_route(ip) for ip in net.resolve_host(h)
                ],
                f"del bypass {hostname}",
                log,
            )
        for network in bypass_networks:
            _safe(
                lambda n=network: net.delete_net_route(n),
                f"del bypass net {network}",
                log,
            )

    # Cleanup domain_suffix resolver files and upstream DNS route
    # (skip when engine._stop_dns_proxy already handled this)
    if not skip_dns_suffix:
        domain_suffix = bypass_cfg.get("domain_suffix", [])
        upstream_dns = bypass_cfg.get("upstream_dns", "8.8.8.8")
        if domain_suffix:
            zones = [
                s.lstrip(".").rstrip(".")
                for s in domain_suffix
                if s.lstrip(".").rstrip(".")
            ]
            if zones:
                print(f"🧹 {t('disc.deleting_dns_bypass')}")
                _safe(
                    lambda: net.cleanup_dns_resolver(zones), "del suffix resolvers", log
                )
            _safe(
                lambda: net.delete_host_route(upstream_dns),
                f"del upstream DNS route {upstream_dns}",
                log,
            )

        # Safety net: scan /etc/resolver/ for leftover tunnelvault files
        def _scan_resolvers():
            cleaned = net.cleanup_local_dns_resolvers()
            if cleaned:
                print(f"🧹 {t('disc.extra_resolvers', files=', '.join(cleaned))}")
                if log:
                    log.log("INFO", f"Cleaned leftover resolvers: {cleaned}")

        _safe(_scan_resolvers, "scan local resolvers", log)


def _cleanup_routes_and_ipv6(
    net: NetManager,
    log: Optional[Logger],
    defs: dict,
    script_dir: Optional[Path] = None,
) -> None:
    """Shared cleanup: global routes + kill switch + IPv6 restore."""
    # Disable kill switch before restoring routes
    from tv.killswitch import create as create_killswitch

    ks = create_killswitch(log)
    _safe(lambda: ks.disable(), "disable kill switch", log)

    cleanup_global_routes(net, log, defs, script_dir=script_dir)

    print(f"🌐 {t('disc.restore_ipv6')}")
    _safe(lambda: net.restore_ipv6(), "restore IPv6", log)

    print(f"✅ {t('disc.all_disconnected')}")
    if log:
        log.log("INFO", "Disconnect complete")


def run(
    net: Optional[NetManager] = None,
    log: Optional[Logger] = None,
    defs: Optional[dict] = None,
    script_dir: Optional[Path] = None,
) -> None:
    """Emergency cleanup: kill VPN processes via plugin registry and clean routing."""
    if net is None:
        from tv.net import create

        net = create()

    if defs is None:
        defs = {}

    # Kill VPN processes via targeted patterns (not killall)
    from tv.vpn.registry import available_types, get_plugin

    for type_name in available_types():
        plugin_cls = get_plugin(type_name)
        if script_dir:
            patterns = plugin_cls.emergency_patterns(script_dir)
        else:
            patterns = plugin_cls.kill_patterns
        if patterns:
            print(f"🔌 {t('disc.disconnecting', name=type_name)}")
        for pattern in patterns:
            _safe(
                lambda p=pattern: proc.kill_pattern(p, sudo=True),
                f"kill {pattern}",
                log,
            )

    # Clean up FortiVPN temp configs containing passwords
    for conf in glob.glob(f"{cfg.paths.temp_dir}/forti_*.conf"):
        try:
            os.unlink(conf)
        except OSError:
            pass

    # Clean up sing-box proxy temp configs
    for conf in glob.glob(f"{cfg.paths.temp_dir}/sb_proxy_*.json"):
        try:
            os.unlink(conf)
        except OSError:
            pass

    # Always clean up system proxy (leaked proxy = all HTTP broken)
    _safe(lambda: net.cleanup_system_proxy(), "cleanup system proxy", log)

    _cleanup_routes_and_ipv6(net, log, defs, script_dir=script_dir)


def _discover_pid(tcfg, plugin_cls, script_dir) -> Optional[int]:
    """Best-effort PID discovery for disconnect without engine context."""
    try:
        return plugin_cls.discover_pid(tcfg, script_dir)
    except Exception:
        return None


def run_plugins(
    tunnels: list,
    net: Optional[NetManager] = None,
    log: Optional[Logger] = None,
    defs: Optional[dict] = None,
) -> None:
    """Plugin-driven disconnect: iterate tunnels in reverse order."""
    from tv.vpn.registry import get_plugin

    if net is None:
        from tv.net import create

        net = create()

    if defs is None:
        defs = {}

    script_dir = Path(__file__).parent.parent

    # Disconnect tunnels in reverse order
    for tcfg in reversed(tunnels):
        plugin_cls = get_plugin(tcfg.type)
        plugin = plugin_cls(tcfg, net, log or _null_logger(), script_dir)

        # Best-effort PID recovery (no engine context)
        plugin._pid = _discover_pid(tcfg, plugin_cls, script_dir)

        print(f"🔌 {t('disc.disconnecting', name=plugin.display_name)}")
        _safe(lambda p=plugin: p.disconnect(), f"disconnect {tcfg.name}", log)
        _safe(lambda p=plugin: p.delete_routes(), f"del routes {tcfg.name}", log)
        _safe(lambda p=plugin: p.cleanup_dns(), f"cleanup dns {tcfg.name}", log)

    # Clean up system proxy (safety net for crash/partial disconnect)
    _safe(lambda: net.cleanup_system_proxy(), "cleanup system proxy", log)

    _cleanup_routes_and_ipv6(net, log, defs, script_dir=script_dir)


class _NullLogger:
    """Minimal stub when no logger is available."""

    log_path = None

    def log(self, *a, **kw):
        pass

    def log_lines(self, *a, **kw):
        pass


_null_logger_instance = _NullLogger()


def _null_logger():
    return _null_logger_instance


if __name__ == "__main__":
    run(script_dir=Path(__file__).parent.parent)
