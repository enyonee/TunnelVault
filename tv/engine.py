"""Engine: lifecycle orchestration for tunnel connections."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

from tv import config, ui, disconnect, checks, proc
from tv.app_config import cfg
from tv.disconnect import get_vpn_server_routes, get_bypass_routes
from tv import defaults as defaults_mod
from tv.dns_proxy import BypassDNSProxy
from tv.i18n import t
from tv.logger import Logger
from tv.net import NetManager, create as create_net
from tv.vpn.base import TunnelConfig, TunnelPlugin, VPNResult
from tv.vpn.registry import get_plugin


def load_watch_state(script_dir: Path) -> dict[str, str]:
    """Read saved interface->name mapping from watch-state.json.

    Returns {interface: tunnel_name} for currently alive processes.
    """
    try:
        path = config.resolve_log_dir(script_dir) / "watch-state.json"
        if not path.exists():
            return {}
        state = json.loads(path.read_text())
        result = {}
        for name, info in state.items():
            iface = info.get("interface", "")
            pid = info.get("pid")
            if iface and pid and proc.is_alive(pid):
                result[iface] = name
        return result
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


class Engine:
    """Lifecycle orchestration for multi-VPN connections."""

    def __init__(
        self,
        script_dir: Path,
        defs: dict,
        *,
        debug: bool = False,
        net: Optional[NetManager] = None,
        log: Optional[Logger] = None,
    ) -> None:
        self.script_dir = script_dir
        self.defs = defs
        self.net = net or create_net()
        if log:
            self.log = log
        else:
            log_dir = config.ensure_log_dir(script_dir)
            self.log = Logger(log_dir / cfg.paths.main_log, debug=debug)
        self.tunnels: list[TunnelConfig] = []
        self.plugins: list[TunnelPlugin] = []
        self.results: list[VPNResult] = []
        self.skipped_binaries: dict[str, str] = {}  # {tunnel_name: binary}
        self._hooks: dict[str, list[Callable]] = defaultdict(list)
        self._dns_proxy: Optional[BypassDNSProxy] = None
        self._dns_proxy_zones: list[str] = []
        self._dns_proxy_upstream: str = ""

    # --- Hooks ---

    def on(self, event: str, fn: Callable) -> None:
        self._hooks[event].append(fn)

    def _fire(self, event: str, **ctx) -> None:
        for fn in self._hooks.get(event, []):
            fn(**ctx)

    # --- Binary checks ---

    def _filter_available(self, tunnels: list[TunnelConfig]) -> list[TunnelConfig]:
        """Remove tunnels whose VPN binary is not installed."""
        available = []
        for tcfg in tunnels:
            plugin_cls = get_plugin(tcfg.type)
            if plugin_cls.check_binary():
                available.append(tcfg)
            else:
                binary = plugin_cls.binary or tcfg.type
                ui.warn(t("engine.binary_not_found", name=tcfg.name, binary=binary))
                self.log.log(
                    "WARN",
                    f"Binary '{binary}' not found, skipping tunnel '{tcfg.name}'",
                )
                self.skipped_binaries[tcfg.name] = binary
        return available

    # --- Lifecycle ---

    def prepare(self, *, setup: bool = False, _retry: bool = False) -> None:
        """Load tunnels, resolve configs, save settings."""
        self.tunnels = []
        self.plugins = []
        self.results = []
        self.tunnels = defaults_mod.parse_tunnels(self.defs)

        # Filter out tunnels whose binary is not installed
        self.tunnels = self._filter_available(self.tunnels)
        if not self.tunnels:
            ui.warn(t("engine.no_available_tunnels"))
            self.log.log("WARN", "No tunnels available (all binaries missing)")
            return

        config.resolve_log_paths(self.tunnels, self.script_dir)

        settings_path = self.script_dir / cfg.paths.settings_file
        quiet = not setup and settings_path.exists()

        saved = config.load_settings(self.script_dir, quiet=quiet)
        if not quiet:
            print()

        for tcfg in self.tunnels:
            plugin_cls = get_plugin(tcfg.type)
            schema = plugin_cls.config_schema()
            if schema:
                if not quiet:
                    ui.section(t("engine.params_section", name=tcfg.name))
                    print()
                try:
                    config.resolve_tunnel_params(
                        tcfg,
                        plugin_cls,
                        saved,
                        self.script_dir,
                        quiet=quiet,
                        setup=setup,
                    )
                except config.SetupRequiredError:
                    if not quiet or _retry:
                        raise
                    ui.warn(t("engine.settings_incomplete"))
                    return self.prepare(setup=True, _retry=True)
                if not quiet:
                    print()

            # Resolve routes (targets -> networks/hosts/dns)
            config.resolve_tunnel_routes(tcfg, saved, quiet=quiet, setup=setup)

        # Validate config_file uniqueness after resolution
        defaults_mod.validate_config_files(self.tunnels)

        if quiet:
            names = [t_.name for t_ in self.tunnels]
            ui.info(f"📋 {t('engine.profiles', names=', '.join(names))}")
        else:
            config.save_tunnel_settings(self.tunnels, self.script_dir)
            print()

    def setup(self, *, clear: bool = False, quiet: bool = False) -> None:
        """Pre-connection setup: optional cleanup, IPv6, VPN server routes, clean logs."""
        if clear:
            if not quiet:
                ui.info(f"🧹 {t('engine.clearing')}")
            self.log.log("INFO", "--- Clearing previous connections ---")
            disconnect.run(self.net, self.log, self.defs, script_dir=self.script_dir)
            time.sleep(cfg.timeouts.cleanup_sleep)

        if not quiet:
            ui.info(f"🌐 {t('engine.disable_ipv6')}")
        self.log.log("INFO", "--- Disabling IPv6 ---")
        ipv6_ok = self.net.disable_ipv6()
        self.log.log(
            "INFO" if ipv6_ok else "WARN",
            f"IPv6 {'disabled' if ipv6_ok else 'failed to disable'}",
        )

        gw = self.net.default_gateway()
        self._setup_vpn_server_routes(gw, quiet=quiet)
        self._setup_bypass_routes(gw, quiet=quiet)
        self._start_dns_proxy(gw, quiet=quiet)

        # Pre-create log files with correct ownership (readable without sudo)
        config.prepare_log_files(self.tunnels)
        self.log.log("INFO", "VPN logs prepared")

    def connect_all(self, *, quiet: bool = False) -> None:
        """Connect all tunnels sequentially. Reuses existing connections."""
        self.plugins = []
        self.results = []
        total = len(self.tunnels)
        for i, tcfg in enumerate(self.tunnels, 1):
            plugin_cls = get_plugin(tcfg.type)
            plugin = plugin_cls(tcfg, self.net, self.log, self.script_dir)
            self.plugins.append(plugin)

            self._fire("pre_connect", tunnel=tcfg, plugin=plugin, index=i, total=total)

            if not quiet:
                ui.step(i, total, plugin.display_name, tcfg.name)
            self.log.log(
                "INFO", f"=== [{i}/{total}] {plugin.display_name} ({tcfg.name}) ==="
            )

            # Check if already running AND interface is alive
            existing_pid = plugin_cls.discover_pid(tcfg, self.script_dir)
            reuse = False
            result = VPNResult(ok=False, detail="not started")
            if existing_pid and proc.is_alive(existing_pid):
                if tcfg.interface and not self.net.check_interface(tcfg.interface):
                    # PID alive but interface gone - stale process, kill and reconnect
                    self.log.log(
                        "WARN",
                        f"{plugin.display_name} PID={existing_pid} alive but "
                        f"interface {tcfg.interface} gone, reconnecting",
                    )
                    ui.warn(
                        f"{plugin.display_name}: PID={existing_pid} alive, interface {tcfg.interface} gone"
                    )
                    try:
                        plugin._pid = existing_pid
                        plugin.disconnect()
                    except Exception as e:
                        self.log.log("WARN", f"stale disconnect: {e}")
                else:
                    reuse = True
                    plugin._pid = existing_pid
                    detail = f"already running (PID={existing_pid})"
                    ui.ok(f"{plugin.display_name} {detail}")
                    self.log.log(
                        "INFO", f"{plugin.display_name} {detail}, skipping connect"
                    )
                    result = VPNResult(ok=True, pid=existing_pid, detail=detail)

            if not reuse:
                result = plugin.connect()

            self.results.append(result)

            self._fire(
                "post_connect",
                tunnel=tcfg,
                plugin=plugin,
                result=result,
                index=i,
                total=total,
            )

        self._save_watch_state()

    def _save_watch_state(self) -> None:
        """Persist interface->name mapping for --watch.

        Merges with existing state so --only runs don't erase other tunnels.
        Dead PIDs are cleaned up on read (load_watch_state).
        Uses atomic write (tempfile + rename) to prevent corruption on crash.
        """
        import os
        import tempfile

        path = config.resolve_log_dir(self.script_dir) / "watch-state.json"
        try:
            existing = json.loads(path.read_text()) if path.exists() else {}
        except (OSError, json.JSONDecodeError):
            existing = {}

        for tcfg, result in zip(self.tunnels, self.results):
            if result.ok and tcfg.interface:
                existing[tcfg.name] = {
                    "interface": tcfg.interface,
                    "pid": result.pid,
                    "type": tcfg.type,
                }
            elif not result.ok and tcfg.name in existing:
                del existing[tcfg.name]

        try:
            fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            try:
                os.write(fd, json.dumps(existing).encode())
            finally:
                os.close(fd)
            os.rename(tmp_path, str(path))
        except OSError:
            pass

    def restart_dns_proxy_thread(self) -> None:
        """Restart DNS proxy thread after fork (socket survives, thread does not)."""
        if self._dns_proxy is not None:
            self._dns_proxy.restart_thread()

    def check_alive(self) -> list[tuple[TunnelConfig, int | None]]:
        """Return list of (tunnel_config, dead_pid) for tunnels with dead processes."""
        dead: list[tuple[TunnelConfig, int | None]] = []
        for plugin, tcfg, result in zip(self.plugins, self.tunnels, self.results):
            if result.ok and plugin._pid and not proc.is_alive(plugin._pid):
                dead.append((tcfg, plugin._pid))
        return dead

    def wait_for_network(self) -> bool:
        """Wait for network to become available (default gateway reachable).

        Returns True if network is ready, False on timeout.
        """
        timeout = cfg.timeouts.network_wait_timeout
        interval = cfg.timeouts.network_wait_interval
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            gw = self.net.default_gateway()
            if gw:
                self.log.log("INFO", f"Network ready, gateway={gw}")
                return True
            time.sleep(interval)

        self.log.log("WARN", f"Network not ready after {timeout}s")
        return False

    def reconnect_all(
        self, *, quiet: bool = True
    ) -> tuple[list[checks.CheckResult], str]:
        """Full reconnect cycle: disconnect, wait for network, setup, connect, check."""
        self.disconnect_all()
        time.sleep(cfg.timeouts.keepalive_reconnect_pause)

        if not self.wait_for_network():
            raise RuntimeError("Network not available after wake")

        self.setup(clear=False, quiet=quiet)
        self.connect_all(quiet=quiet)
        return self.check_all(quiet=quiet)

    def check_all(self, *, quiet: bool = False) -> tuple[list[checks.CheckResult], str]:
        """Run health checks for all connected tunnels."""
        check_input = [
            (tcfg.name, r.ok, tcfg.checks)
            for tcfg, r in zip(self.tunnels, self.results)
        ]
        if quiet:
            results, ext_ip = checks.run_all_quiet(check_input, logger=self.log)
        else:
            results, ext_ip = checks.run_all_from_tunnels(check_input, logger=self.log)

        failed = [r for r in results if r.status == "fail"]
        if failed:
            self._fire("on_check_fail", failed=failed, all_results=results)
        self._fire("on_all_checks_done", results=results, ext_ip=ext_ip)

        return results, ext_ip

    def disconnect_all(self) -> None:
        """Disconnect all tunnels in reverse order."""
        for plugin, tcfg in zip(reversed(self.plugins), reversed(self.tunnels)):
            self._fire("pre_disconnect", tunnel=tcfg, plugin=plugin)
            try:
                plugin.disconnect()
            except Exception as e:
                self.log.log("WARN", f"disconnect {tcfg.name}: {e}")
            try:
                plugin.delete_routes()
            except Exception as e:
                self.log.log("WARN", f"delete_routes {tcfg.name}: {e}")
            try:
                plugin.cleanup_dns()
            except Exception as e:
                self.log.log("WARN", f"cleanup_dns {tcfg.name}: {e}")
            self._fire("post_disconnect", tunnel=tcfg, plugin=plugin)

        self._stop_dns_proxy()

        # Глобальные маршруты (vpn_server_routes, bypass) - без этого
        # disconnect нужно вызывать дважды: daemon убивается, но routes остаются
        disconnect.cleanup_global_routes(
            self.net,
            self.log,
            self.defs,
            skip_dns_suffix=True,
        )
        self.net.restore_ipv6()

        self._clean_watch_state()

    def _clean_watch_state(self) -> None:
        """Remove disconnected tunnels from watch state."""
        path = config.resolve_log_dir(self.script_dir) / "watch-state.json"
        try:
            if not path.exists():
                return
            state = json.loads(path.read_text())
            for tcfg in self.tunnels:
                state.pop(tcfg.name, None)
            if state:
                path.write_text(json.dumps(state))
            else:
                path.unlink(missing_ok=True)
        except (OSError, json.JSONDecodeError):
            pass

    def _setup_vpn_server_routes(self, gw: str | None, *, quiet: bool = False) -> None:
        """Add host routes to VPN servers through the default gateway."""
        routes_cfg = get_vpn_server_routes(self.defs)

        static_hosts = routes_cfg.get("hosts", [])
        resolve_hosts = routes_cfg.get("resolve", [])

        if not gw:
            ui.fail(t("engine.no_gateway"))
            self.log.log("ERROR", "default gateway not found")
            return

        self.log.log("INFO", f"--- Host routes via GW={gw} ---")
        if not quiet:
            ui.info(f"🔌 {t('engine.host_routes', gw=gw)}")

        for hostname in resolve_hosts:
            for ip in self.net.resolve_host(hostname):
                ok = self.net.add_host_route(ip, gw)
                self.log.log(
                    "INFO" if ok else "WARN",
                    f"route add {ip} ({hostname}) -> {gw} {'OK' if ok else 'FAIL'}",
                )

        for static_ip in static_hosts:
            ok = self.net.add_host_route(static_ip, gw)
            self.log.log(
                "INFO" if ok else "WARN",
                f"route add {static_ip} {'OK' if ok else 'FAIL'}",
            )

    def _setup_bypass_routes(self, gw: str | None, *, quiet: bool = False) -> None:
        """Add bypass routes for domains/hosts/networks that should skip VPN."""
        bypass_cfg = get_bypass_routes(self.defs)
        hosts = bypass_cfg.get("hosts", [])
        domains = bypass_cfg.get("domains", [])
        networks = bypass_cfg.get("networks", [])

        if not hosts and not domains and not networks:
            return

        if not gw:
            self.log.log("WARN", "bypass: default gateway not found, skipping")
            return

        self.log.log("INFO", f"--- Bypass routes via GW={gw} ---")
        if not quiet:
            ui.info(f"🔀 {t('engine.bypass_routes', gw=gw)}")

        for hostname in domains:
            for ip in self.net.resolve_host(hostname):
                ok = self.net.add_host_route(ip, gw)
                self.log.log(
                    "INFO" if ok else "WARN",
                    f"bypass {ip} ({hostname}) -> {gw} {'OK' if ok else 'FAIL'}",
                )

        for static_ip in hosts:
            ok = self.net.add_host_route(static_ip, gw)
            self.log.log(
                "INFO" if ok else "WARN",
                f"bypass {static_ip} -> {gw} {'OK' if ok else 'FAIL'}",
            )

        for network in networks:
            ok = self.net.add_net_route(network, gw)
            self.log.log(
                "INFO" if ok else "WARN",
                f"bypass net {network} -> {gw} {'OK' if ok else 'FAIL'}",
            )

    def _start_dns_proxy(self, gw: str | None, *, quiet: bool = False) -> None:
        """Start DNS bypass proxy if domain_suffix is configured."""
        if self._dns_proxy is not None:
            self._stop_dns_proxy()

        bypass_cfg = get_bypass_routes(self.defs)
        suffixes = bypass_cfg.get("domain_suffix", [])
        if not suffixes:
            return

        upstream = bypass_cfg.get("upstream_dns", "8.8.8.8")

        if not gw:
            self.log.log("WARN", "dns_proxy: default gateway not found, skipping")
            return

        # Route upstream DNS through default GW (before VPN takes over)
        ok = self.net.add_host_route(upstream, gw)
        self.log.log(
            "INFO" if ok else "WARN",
            f"upstream DNS route {upstream} -> {gw} {'OK' if ok else 'FAIL'}",
        )

        proxy = BypassDNSProxy(
            suffixes=suffixes,
            upstream_dns=upstream,
            net=self.net,
            logger=self.log,
            gateway=gw,
        )
        try:
            proxy.start()
        except OSError as e:
            self.log.log("WARN", f"dns_proxy bind failed: {e}")
            ui.warn(t("engine.dns_proxy_failed", error=e))
            self.net.delete_host_route(upstream)
            return

        self._dns_proxy = proxy
        zones = self._suffix_zones(suffixes)
        self._dns_proxy_zones = zones
        self._dns_proxy_upstream = upstream

        # Create /etc/resolver/{zone} files pointing to 127.0.0.1
        for zone in zones:
            result = self.net.setup_dns_resolver(
                domains=[zone],
                nameservers=["127.0.0.1"],
            )
            self.log.log(
                "INFO" if result.get(zone) else "WARN",
                f"resolver {zone} -> 127.0.0.1 {'OK' if result.get(zone) else 'FAIL'}",
            )

        if not quiet:
            ui.info(f"🔀 {t('engine.dns_bypass_proxy', suffixes=', '.join(suffixes))}")

    def _stop_dns_proxy(self) -> None:
        """Stop DNS bypass proxy and clean up resolver files and routes."""
        if self._dns_proxy is None:
            return

        zones = self._dns_proxy_zones
        upstream = self._dns_proxy_upstream

        # 1. Remove resolver files (no new queries from system DNS)
        try:
            if zones:
                self.net.cleanup_dns_resolver(zones)
        except Exception as e:
            self.log.log("WARN", f"dns_proxy cleanup resolvers: {e}")

        # 2. Stop proxy thread (set frozen after this)
        try:
            self._dns_proxy.stop()
        except Exception as e:
            self.log.log("WARN", f"dns_proxy stop: {e}")

        # 3. Delete injected routes (safe - no new entries possible)
        try:
            for ip in self._dns_proxy.injected_routes():
                self.net.delete_host_route(ip)
        except Exception as e:
            self.log.log("WARN", f"dns_proxy cleanup injected routes: {e}")

        # 4. Delete upstream DNS route
        try:
            self.net.delete_host_route(upstream)
        except Exception as e:
            self.log.log("WARN", f"dns_proxy cleanup upstream route: {e}")

        self._dns_proxy = None
        self._dns_proxy_zones = []
        self._dns_proxy_upstream = ""

    @staticmethod
    def _suffix_zones(suffixes: list[str]) -> list[str]:
        """Convert suffixes like '.ru' or '.example' to resolver zone names."""
        zones = []
        for s in suffixes:
            zone = s.lstrip(".").rstrip(".")
            if zone:
                zones.append(zone)
        return zones
