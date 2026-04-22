"""Engine: lifecycle orchestration for tunnel connections."""

from __future__ import annotations

import json
import socket
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

from tv import config, ui, disconnect, checks, proc
from tv.app_config import cfg
from tv.disconnect import (
    get_vpn_server_routes,
    get_bypass_routes,
    get_kill_switch_enabled,
)
from tv import defaults as defaults_mod
from tv.killswitch import KillSwitch, create as create_killswitch
from tv.i18n import t
from tv.logger import Logger
from tv.net import NetManager, create as create_net
from tv.vpn.base import TunnelConfig, TunnelPlugin, VPNResult
from tv.vpn.registry import get_plugin


def _check_port(port: int) -> bool:
    """Check if a port is listening on localhost."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


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
        self.quiet: bool = False  # set by prepare()
        self._hooks: dict[str, list[Callable]] = defaultdict(list)
        self._killswitch: KillSwitch = create_killswitch(self.log)

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

        # NOTE: bypass domain_suffix is NOT injected into sing-box configs.
        # Domain-based route rules break TUN routing in sing-box 1.12+ on macOS.
        # Bypass is handled by DNS bypass proxy (/etc/resolver/ + BypassDNSProxy).

        # In proxy-only mode, only sing-box tunnels are useful (no TUN)
        if cfg.mode == "proxy-only":
            self.tunnels = [t_ for t_ in self.tunnels if t_.type == "singbox"]

        # Proxy modes require at least one sing-box tunnel
        if cfg.mode in ("proxy", "proxy-only"):
            has_singbox = any(t_.type == "singbox" for t_ in self.tunnels)
            if not has_singbox:
                ui.fail("Proxy mode requires at least one sing-box tunnel")
                self.log.log("ERROR", "Proxy mode but no sing-box tunnel configured")
                return

        # Filter out tunnels whose binary is not installed
        self.tunnels = self._filter_available(self.tunnels)
        if not self.tunnels:
            ui.warn(t("engine.no_available_tunnels"))
            self.log.log("WARN", "No tunnels available (all binaries missing)")
            return

        config.resolve_log_paths(self.tunnels, self.script_dir)

        quiet = not setup and config.all_required_set(self.tunnels)
        self.quiet = quiet

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
                        self.script_dir,
                        quiet=quiet,
                        setup=setup,
                    )
                except config.SetupRequiredError:
                    if _retry:
                        raise
                    return self.prepare(setup=True, _retry=True)
                if not quiet:
                    print()

            # Resolve routes (targets -> networks/hosts/dns)
            config.resolve_tunnel_routes(tcfg, quiet=quiet, setup=setup)

        # Validate config_file uniqueness after resolution
        defaults_mod.validate_config_files(self.tunnels)

        if quiet:
            print()
            for t_ in self.tunnels:
                cfg_file = t_.config_file or ""
                host = (t_.auth or {}).get("host", "")
                login = (t_.auth or {}).get("login", "")
                parts = [f"{ui.BOLD}{t_.name}{ui.NC} {ui.DIM}({t_.type}){ui.NC}"]
                if cfg_file:
                    parts.append(f"  {ui.DIM}{cfg_file}{ui.NC}")
                if host:
                    port = (t_.auth or {}).get("port", "")
                    parts.append(f"  {host}:{port}" if port else f"  {host}")
                if login:
                    parts.append(f"  user={login}")
                ui.info(f"📋 {''.join(parts)}")
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

        if cfg.mode == "proxy-only":
            self.log.log("INFO", "--- Proxy-only mode: skipping TUN setup ---")
            config.prepare_log_files(self.tunnels)
            return

        if not quiet:
            ui.info(f"🌐 {t('engine.disable_ipv6')}")
        self.log.log("INFO", "--- Disabling IPv6 ---")
        ipv6_ok = self.net.disable_ipv6()
        self.log.log(
            "INFO" if ipv6_ok else "WARN",
            f"IPv6 {'disabled' if ipv6_ok else 'failed to disable'}",
        )

        self.log.log("INFO", "--- Getting default gateway ---")
        gw = self.net.default_gateway()
        self.log.log("INFO", f"Gateway: {gw}")
        self.log.log("INFO", "--- VPN server routes ---")
        self._setup_vpn_server_routes(gw, quiet=quiet)
        self.log.log("INFO", "--- Bypass routes ---")
        self._setup_bypass_routes(gw, quiet=quiet)
        self.log.log("INFO", "--- Kill switch ---")
        self._enable_kill_switch(quiet=quiet)
        self.log.log("INFO", "--- Prepare log files ---")
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

        # In proxy/proxy-only mode, set system proxy after tunnels are connected
        if cfg.mode in ("proxy", "proxy-only") and any(r.ok for r in self.results):
            addr = f"127.0.0.1:{cfg.proxy_port}"
            if _check_port(cfg.proxy_port):
                self.net.setup_system_proxy(cfg.proxy_port)
                self.log.log("INFO", f"System proxy set to {addr}")
                if not quiet:
                    ui.info(f"🌐 {t('main.proxy_urls', addr=addr)}")
                    ui.info(f"  {ui.DIM}{t('main.proxy_env', addr=addr)}{ui.NC}")
            else:
                self.log.log(
                    "WARN",
                    f"Proxy port {cfg.proxy_port} not listening, skipping system proxy",
                )
                if not quiet:
                    ui.warn(
                        f"Proxy port {cfg.proxy_port} not listening, system proxy not set"
                    )

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

    def _find_tunnel(
        self, name: str
    ) -> tuple[int, TunnelConfig, "TunnelPlugin", VPNResult] | None:
        """Find tunnel by name. Returns (index, config, plugin, result) or None."""
        for i, (tcfg, plugin, result) in enumerate(
            zip(self.tunnels, self.plugins, self.results)
        ):
            if tcfg.name == name:
                return i, tcfg, plugin, result
        return None

    def disconnect_one(self, name: str) -> bool:
        """Disconnect a single tunnel by name. Returns True if found."""
        found = self._find_tunnel(name)
        if not found:
            return False
        idx, tcfg, plugin, result = found
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
        self.results[idx] = VPNResult(ok=False, detail="disconnected")
        self._save_watch_state()
        self.log.log("INFO", f"Disconnected tunnel: {name}")
        return True

    def reconnect_one(self, name: str, *, quiet: bool = True) -> bool:
        """Reconnect a single tunnel by name. Returns True if found."""
        found = self._find_tunnel(name)
        if not found:
            return False
        idx, tcfg, plugin, _result = found

        # Disconnect с cleanup routes/DNS (как в disconnect_all)
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

        time.sleep(cfg.timeouts.keepalive_reconnect_pause)

        # Reconnect
        plugin_cls = get_plugin(tcfg.type)
        new_plugin = plugin_cls(tcfg, self.net, self.log, self.script_dir)
        result = new_plugin.connect()

        self.plugins[idx] = new_plugin
        self.results[idx] = result
        self._save_watch_state()
        self.log.log("INFO", f"Reconnected tunnel: {name} ok={result.ok}")
        return True

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

        # Cleanup system proxy (before killing processes)
        if cfg.mode in ("proxy", "proxy-only"):
            self.net.cleanup_system_proxy()
            self.log.log("INFO", "System proxy disabled")
            ui.info(f"🌐 {t('main.proxy_removed')}")

        self._disable_kill_switch()

        if cfg.mode != "proxy-only":
            # Глобальные маршруты (vpn_server_routes, bypass) - без этого
            # disconnect нужно вызывать дважды: daemon убивается, но routes остаются
            disconnect.cleanup_global_routes(
                self.net,
                self.log,
                self.defs,
                script_dir=self.script_dir,
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

        cache_path = config.resolve_log_dir(self.script_dir) / "resolved-route-cache.json"

        # Читаем кеш — DNS может быть недоступен если уже запущен другой туннель
        cached: dict[str, list[str]] = {}
        try:
            cached = json.loads(cache_path.read_text())
        except (OSError, json.JSONDecodeError):
            pass

        resolved_ips: dict[str, list[str]] = {}
        for hostname in resolve_hosts:
            if hostname in cached:
                ips = cached[hostname]
                self.log.log("INFO", f"resolve {hostname} -> {ips} (cached)")
            else:
                ips = self.net.resolve_host(hostname, timeout=3)
                self.log.log("INFO" if ips else "WARN", f"resolve {hostname} -> {ips or 'failed'}")
            resolved_ips[hostname] = ips
            for ip in ips:
                ok = self.net.add_host_route(ip, gw)
                self.log.log(
                    "INFO" if ok else "WARN",
                    f"route add {ip} ({hostname}) -> {gw} {'OK' if ok else 'FAIL'}",
                )

        # Обновляем кеш только если был свежий resolve
        new_resolved = {h: ips for h, ips in resolved_ips.items() if h not in cached and ips}
        if new_resolved:
            try:
                cache_path.write_text(json.dumps({**cached, **new_resolved}))
            except OSError:
                pass

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

    def _enable_kill_switch(self, *, quiet: bool = False) -> None:
        """Enable kill switch if configured in [global]."""
        if not get_kill_switch_enabled(self.defs):
            return

        # Collect VPN interfaces from tunnel configs
        vpn_interfaces = [tc.interface for tc in self.tunnels if tc.interface]

        # Collect VPN server IPs (static + resolved)
        routes_cfg = get_vpn_server_routes(self.defs)
        vpn_server_ips = list(routes_cfg.get("hosts", []))
        for hostname in routes_cfg.get("resolve", []):
            vpn_server_ips.extend(self.net.resolve_host(hostname))

        # Collect bypass IPs/networks
        bypass_cfg = get_bypass_routes(self.defs)
        bypass_ips = list(bypass_cfg.get("hosts", []))
        for hostname in bypass_cfg.get("domains", []):
            bypass_ips.extend(self.net.resolve_host(hostname))
        bypass_networks = list(bypass_cfg.get("networks", []))

        ok = self._killswitch.enable(
            vpn_interfaces=vpn_interfaces,
            vpn_server_ips=vpn_server_ips,
            bypass_ips=bypass_ips,
            bypass_networks=bypass_networks,
        )
        if ok and not quiet:
            ui.info(f"🛡 {t('engine.kill_switch_enabled')}")
        elif not ok:
            ui.warn(t("engine.kill_switch_failed"))

    def _disable_kill_switch(self) -> None:
        """Disable kill switch if active."""
        if self._killswitch.active:
            self._killswitch.disable()


