#!/usr/bin/env python3
"""tunnelvault - multi-VPN connection manager."""

from __future__ import annotations

import os
import platform
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

from tv import config, ui, disconnect, checks, proc
from tv.cli import parse_args
from tv.config import SetupRequiredError
from tv import defaults as defaults_mod
from tv.app_config import cfg
from tv.engine import Engine
from tv.i18n import t
from tv.logger import Logger
from tv.vpn.base import TunnelConfig
from tv.vpn.registry import get_plugin

# Ensure all plugins are registered on import
from tv.vpn import openvpn, fortivpn, singbox, wireguard  # noqa: F401

IS_WINDOWS = platform.system() == "Windows"


def _is_admin() -> bool:
    """Check if running with elevated privileges (root on Unix, admin on Windows)."""
    if IS_WINDOWS:
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined,union-attr]
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


_log: Logger | None = None  # module-level for crash handler


def main() -> None:
    global _log
    args = parse_args()
    script_dir = Path(__file__).parent.resolve()

    # Mutual exclusion check
    exclusive = [
        args.disconnect,
        args.status,
        args.check,
        args.reset,
        args.validate,
        args.logs is not None,
        args.watch,
        args.enable,
        args.disable,
    ]
    if sum(bool(x) for x in exclusive) > 1:
        ui.fail(t("main.one_command"))
        sys.exit(1)

    # --- Read-only commands (no sudo required) ---

    if args.status:
        from tv.ipc_client import try_ipc
        from tv.ipc_protocol import socket_path as ipc_socket_path

        resp = try_ipc(ipc_socket_path(script_dir), "status")
        if resp and resp.get("ok"):
            _print_ipc_status(resp["data"])
            return

        from tv import status

        status.run()
        return

    if args.watch:
        exact_names, prefix_names = _try_load_tunnel_names(script_dir, args.only)
        from tv import watch

        show_all = getattr(args, "all", False)
        watch.run(exact_names=exact_names, prefix_names=prefix_names, show_all=show_all)
        return

    if args.enable or args.disable:
        if IS_WINDOWS:
            ui.fail("Autostart is not supported on Windows yet")
            sys.exit(1)

        from tv import daemon

        if not _is_admin():
            ui.warn(t("main.needs_sudo"))
        if args.enable:
            daemon.enable(script_dir, only=args.only)
        else:
            daemon.disable(script_dir)
        return

    # --- Commands that need root ---

    if not _is_admin():
        ui.warn(t("main.needs_sudo"))

    if args.reset:
        disconnect.run(defs={}, script_dir=script_dir)
        return

    # --- Commands that need config.toml ---

    defs = defaults_mod.load(script_dir, setup=args.setup)

    # Initialize i18n from config (after config.toml loaded [app].locale)
    from tv import i18n

    if cfg.locale:
        i18n.init(cfg.locale)

    # CLI --log-level overrides config
    if args.log_level:
        cfg.logging.level = args.log_level

    if args.validate:
        from tv import validate as validate_mod

        sys.exit(0 if validate_mod.run(defs, script_dir) else 1)

    if args.disconnect:
        # If a daemon is running, send SIGTERM and let it clean up
        if not IS_WINDOWS:
            from tv import daemon as daemon_mod

            daemon_pid = daemon_mod.read_pid(script_dir)
            if daemon_pid and daemon_mod.is_pid_alive(daemon_pid):
                # Verify PID belongs to tunnelvault before killing
                if not daemon_mod.is_tunnelvault_process(daemon_pid):
                    ui.warn(f"PID {daemon_pid} is not a tunnelvault process")
                    daemon_mod.remove_pid(script_dir)
                    # Fall through to emergency cleanup
                else:
                    os.kill(daemon_pid, signal.SIGTERM)
                    ui.info(f"  Stopping daemon (PID={daemon_pid})...")
                    # Wait for daemon to finish cleanup
                    sigkilled = False
                    for i in range(30):
                        if not daemon_mod.is_pid_alive(daemon_pid):
                            break
                        time.sleep(0.5)
                    else:
                        # SIGKILL fallback after 15s
                        ui.warn("  Daemon not responding, sending SIGKILL...")
                        os.kill(daemon_pid, signal.SIGKILL)
                        time.sleep(0.5)
                        sigkilled = True
                    daemon_mod.remove_pid(script_dir)
                    ui.ok(t("main.daemon_stopped", pid=daemon_pid))
                    if not sigkilled:
                        # Daemon handled SIGTERM and cleaned up VPN state
                        return
                    # SIGKILL: daemon didn't clean up - fall through to emergency cleanup
            elif daemon_pid:
                ui.warn(t("main.stale_pidfile", pid=daemon_pid))
                daemon_mod.remove_pid(script_dir)
                # Fall through to emergency cleanup

        tunnels = defaults_mod.parse_tunnels(defs)
        try:
            if args.only:
                tunnels = defaults_mod.filter_tunnels(tunnels, args.only)
        except ValueError as e:
            ui.fail(str(e))
            sys.exit(1)
        if tunnels:
            disconnect.run_plugins(tunnels, defs=defs)
        else:
            disconnect.run(defs=defs, script_dir=script_dir)
        return

    if args.check:
        from tv.ipc_client import try_ipc
        from tv.ipc_protocol import socket_path as ipc_socket_path

        resp = try_ipc(ipc_socket_path(script_dir), "check")
        if resp and resp.get("ok"):
            _print_ipc_check(resp["data"])
            return

        tunnels = defaults_mod.parse_tunnels(defs)
        config.resolve_log_paths(tunnels, script_dir)
        try:
            if args.only:
                tunnels = defaults_mod.filter_tunnels(tunnels, args.only)
        except ValueError as e:
            ui.fail(str(e))
            sys.exit(1)
        _run_check_only(tunnels, script_dir)
        return

    if args.logs is not None:
        tunnels = defaults_mod.parse_tunnels(defs)
        config.resolve_log_paths(tunnels, script_dir)
        _run_logs(tunnels, args.logs, script_dir)
        return

    # --- Engine (connect) ---
    engine = Engine(script_dir, defs, debug=args.debug)
    _log = engine.log

    # --- Reconnect lock (protects against signal during reconnect) ---
    import threading

    _reconnect_lock = threading.Lock()

    # --- Signal handlers ---
    _handling_signal = False

    def on_signal(sig: int, _frame) -> None:
        nonlocal _handling_signal
        if _handling_signal:
            sys.exit(128 + sig)
        _handling_signal = True
        name = signal.Signals(sig).name
        print(
            f"\n  {ui.YELLOW}{ui.BOLD}⚠ {t('main.interrupted', name=name)}{ui.NC}",
            file=sys.stderr,
        )
        engine.log.log("WARN", f"Interrupted by {name}")
        print(f"  {ui.DIM}{t('main.cleaning_vpn')}{ui.NC}", file=sys.stderr)
        # Wait for any ongoing reconnect to finish before cleanup
        _reconnect_lock.acquire(timeout=30)
        try:
            engine.disconnect_all()
        except Exception:
            # Fallback: emergency kill if engine state is broken
            try:
                disconnect.run(engine.net, engine.log, defs, script_dir=script_dir)
            except Exception as exc:
                print(f"  {ui.DIM}cleanup error: {exc}{ui.NC}", file=sys.stderr)
        finally:
            if _reconnect_lock.locked():
                _reconnect_lock.release()
        # Remove PID file if we're the daemon
        try:
            from tv import daemon as daemon_mod

            daemon_mod.remove_pid(script_dir)
        except Exception:
            pass
        print(
            f"  {ui.DIM}{t('main.log_colon', path=engine.log.log_path)}{ui.NC}",
            file=sys.stderr,
        )
        sys.exit(128 + sig)

    signal.signal(signal.SIGINT, on_signal)
    if not IS_WINDOWS:
        signal.signal(signal.SIGTERM, on_signal)

    # --- Start ---
    ui.logo()

    engine.log.log("INFO", "=" * 40)
    engine.log.log("INFO", f"tunnelvault started (PID={os.getpid()})")
    engine.log.log("INFO", f"Command line: {' '.join(sys.argv)}")
    engine.log.log_env(engine.net, script_dir)

    engine.prepare(setup=args.setup)

    if not engine.tunnels:
        engine.log.log("WARN", "No tunnels to connect")
        sys.exit(1)

    # --only filter after prepare (tunnels resolved)
    try:
        if args.only:
            engine.tunnels = defaults_mod.filter_tunnels(engine.tunnels, args.only)
    except ValueError as e:
        # Better message if tunnel was skipped due to missing binary
        requested = [n.strip() for n in args.only.split(",") if n.strip()]
        skipped = [n for n in requested if n in engine.skipped_binaries]
        if skipped:
            for name in skipped:
                binary = engine.skipped_binaries[name]
                ui.fail(t("main.skipped_binary", name=name, binary=binary))
        else:
            ui.fail(str(e))
        sys.exit(1)

    engine.setup(clear=args.clear, quiet=engine.quiet)
    engine.connect_all(quiet=engine.quiet)
    check_results, ext_ip = engine.check_all(quiet=engine.quiet)

    # --- Summary ---
    if not engine.quiet:
        _log_summary(engine, check_results, ext_ip)
    else:
        # Minimal logging only
        engine.log.log("INFO", "=== Summary ===")
        for tcfg, r in zip(engine.tunnels, engine.results):
            engine.log.log("INFO", f"{tcfg.name}: ok={r.ok}")
        engine.log.log("INFO", f"Log: {engine.log.log_path}")

    # --- Keepalive / daemon mode ---
    if args.no_daemon:
        return

    from tv import daemon as daemon_mod

    from tv.ipc_server import start_server_thread
    from tv.ipc_protocol import socket_path as ipc_socket_path

    ipc_path = ipc_socket_path(script_dir)

    if args.foreground or IS_WINDOWS:
        # Stay in foreground (for launchd/systemd or Windows)
        daemon_mod.write_pid(script_dir)
        ipc_srv, _ = start_server_thread(engine, ipc_path, engine.log, _reconnect_lock)
        try:
            _keepalive_loop(engine, reconnect_lock=_reconnect_lock)
        finally:
            ipc_srv.shutdown()
            daemon_mod.remove_pid(script_dir)
        return

    # Default: double-fork into background
    child_pid = daemon_mod.daemonize(script_dir)
    if child_pid > 0:
        # Parent: print info and exit
        log_path = daemon_mod.daemon_log_path(script_dir)
        ui.ok(t("main.backgrounded", pid=child_pid))
        ui.info(f"  {ui.DIM}{t('main.daemon_log_hint', path=log_path)}{ui.NC}")
        sys.exit(0)

    # --- Daemon (grandchild) ---
    # Fresh lock - threading primitives don't survive fork reliably
    _reconnect_lock = threading.Lock()

    # Re-register signal handlers (fork resets them in some cases)
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # Restart DNS proxy thread (socket survives fork, thread does not)
    engine.restart_dns_proxy_thread()

    engine.log.log("INFO", f"Daemonized (PID={os.getpid()})")

    ipc_srv, _ = start_server_thread(engine, ipc_path, engine.log, _reconnect_lock)
    try:
        _keepalive_loop(engine, reconnect_lock=_reconnect_lock)
    finally:
        ipc_srv.shutdown()
        daemon_mod.remove_pid(script_dir)


def _print_ipc_status(data: dict) -> None:
    """Format and print status response from IPC daemon."""
    pid = data.get("pid", "?")
    uptime = data.get("uptime", 0)
    h, m = divmod(uptime // 60, 60)
    uptime_str = f"{h}h {m}m" if h else f"{m}m"

    print(f"  {ui.BOLD}Daemon{ui.NC} PID={pid}, uptime {uptime_str}")
    print()

    tunnels = data.get("tunnels", [])
    if not tunnels:
        print(f"  {ui.DIM}No tunnels{ui.NC}")
        return

    for t_info in tunnels:
        name = t_info.get("name", "?")
        vtype = t_info.get("type", "?")
        connected = t_info.get("connected", False)
        t_pid = t_info.get("pid")
        iface = t_info.get("interface", "")
        detail = t_info.get("detail", "")

        if connected:
            status_str = f"{ui.GREEN}✓{ui.NC}"
            extras = []
            if t_pid:
                extras.append(f"PID={t_pid}")
            if iface:
                extras.append(iface)
            if detail:
                extras.append(detail)
            extra = f" ({', '.join(extras)})" if extras else ""
            print(f"  {status_str} {ui.BOLD}{name}{ui.NC} [{vtype}]{extra}")
        else:
            print(f"  {ui.RED}✗{ui.NC} {ui.BOLD}{name}{ui.NC} [{vtype}] {detail}")


def _print_ipc_check(data: dict) -> None:
    """Format and print check response from IPC daemon."""
    tunnels = data.get("tunnels", [])
    if not tunnels:
        print(f"  {ui.DIM}No tunnels{ui.NC}")
        return

    for t_info in tunnels:
        name = t_info.get("name", "?")
        alive = t_info.get("alive", False)
        t_pid = t_info.get("pid")

        if alive:
            pid_str = f" (PID={t_pid})" if t_pid else ""
            print(f"  {ui.GREEN}✓{ui.NC} {name}{pid_str} alive")
        else:
            print(f"  {ui.RED}✗{ui.NC} {name} dead")


# VPN type -> interface prefixes for dynamic matching.
# On Windows, adapters have arbitrary names (e.g. "Ethernet 2", "TAP-Windows Adapter V9"),
# so prefix matching is not useful; watch uses saved state (exact match) instead.
_TYPE_PREFIXES: dict[str, list[str]] = {
    "fortivpn": ["ppp"],
    "openvpn": ["tun", "utun"] if not IS_WINDOWS else [],
    "singbox": ["utun"] if not IS_WINDOWS else [],
}


def _try_load_tunnel_names(
    script_dir: Path,
    only: str | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Best-effort: load tunnel name mappings from config.toml + watch state.

    Returns:
        (exact_map, prefix_map):
        - exact_map: {interface: name} for tunnels with known interface
        - prefix_map: {prefix: name} for tunnels with dynamic interface (fallback)
    """
    try:
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]

        path = script_dir / cfg.paths.defaults_file
        if not path.exists():
            return {}, {}

        with open(path, "rb") as f:
            data = tomllib.load(f)

        from tv import app_config

        app_config.load(data.get("app", {}))

        tunnels = defaults_mod.parse_tunnels(data)
        if only:
            tunnels = defaults_mod.filter_tunnels(tunnels, only)

        # Priority 1: saved state from last connect (exact PID-verified interface)
        from tv.engine import load_watch_state

        exact: dict[str, str] = load_watch_state(script_dir)

        # Priority 2: configured interface from config.toml
        prefix: dict[str, str] = {}
        for t_ in tunnels:
            if t_.interface and t_.interface not in exact:
                exact[t_.interface] = t_.name
            elif not t_.interface and t_.name not in exact.values():
                for pfx in _TYPE_PREFIXES.get(t_.type, []):
                    prefix[pfx] = t_.name
        return exact, prefix
    except Exception:
        return {}, {}


def _run_check_only(tunnels: list[TunnelConfig], script_dir: Path) -> None:
    """Run health checks on existing connections without (re)connecting."""
    print(f"\n  {ui.BOLD}{t('main.check_title')}{ui.NC}")

    check_input = []
    for tcfg in tunnels:
        try:
            plugin_cls = get_plugin(tcfg.type)
            pid = plugin_cls.discover_pid(tcfg, script_dir)
            is_running = pid is not None and proc.is_alive(pid)
        except Exception:
            is_running = False

        status_str = f"PID {pid}" if is_running else t("main.not_found")
        icon = ui.GREEN + "●" + ui.NC if is_running else ui.RED + "○" + ui.NC
        print(f"  {icon} {tcfg.name}: {status_str}")
        check_input.append((tcfg.name, is_running, tcfg.checks))

    results, ext_ip = checks.run_all_from_tunnels(check_input)

    # Print compact summary
    passed = sum(1 for r in results if r.status == "ok")
    failed = sum(1 for r in results if r.status == "fail")
    skipped = sum(1 for r in results if r.status == "skip")
    print(
        f"\n  {t('main.total', passed=f'{ui.GREEN}{passed}{ui.NC}', failed=f'{ui.RED}{failed}{ui.NC}', skipped=f'{ui.DIM}{skipped}{ui.NC}')}"
    )

    if ext_ip:
        print(f"  {t('main.external_ip', ip=ext_ip)}")
    print()


def _run_logs(
    tunnels: list[TunnelConfig],
    name: str,
    script_dir: Path,
) -> None:
    """Show log paths or tail a specific log."""
    log_dir = config.resolve_log_dir(script_dir)
    main_log = str(log_dir / cfg.paths.main_log)

    # Build available logs map
    available: dict[str, str] = {}
    for tcfg in tunnels:
        if tcfg.log:
            available[tcfg.name] = tcfg.log
    available["debug"] = main_log
    available["main"] = main_log

    if not name:
        # List all log paths
        print(f"\n  {ui.BOLD}{t('main.log_files')}{ui.NC}\n")
        for log_name, path in available.items():
            if log_name == "main":
                continue  # "main" is alias for "debug"
            prefix = "cat" if log_name == "debug" else "sudo cat"
            print(f"    {log_name:<15s} {prefix} {path}")
        print()
        print(f"  {ui.DIM}{t('main.log_tail_hint')}{ui.NC}")
        print()
        return

    if name not in available:
        names_list = ", ".join(n for n in sorted(available) if n != "main")
        ui.fail(t("main.unknown_log", name=name, available=names_list))
        sys.exit(1)

    path = available[name]
    if not Path(path).exists():
        ui.fail(t("main.file_not_found", path=path))
        sys.exit(1)

    if IS_WINDOWS:
        print(f"  {ui.DIM}Get-Content -Wait {path}{ui.NC}\n")
        try:
            rc = subprocess.call(
                ["powershell", "-Command", f"Get-Content -Wait '{path}'"]
            )
        except KeyboardInterrupt:
            rc = 0
        sys.exit(rc)
    else:
        print(f"  {ui.DIM}tail -f {path}{ui.NC}\n")
        os.execlp("tail", "tail", "-f", path)


def _log_summary(engine: Engine, check_results: list, ext_ip: str) -> None:
    """Log results and print summary."""
    engine.log.log("INFO", "=== Summary ===")
    for tcfg, r in zip(engine.tunnels, engine.results):
        engine.log.log("INFO", f"{tcfg.name}: ok={r.ok}")
    engine.log.log("INFO", f"Log: {engine.log.log_path}")
    engine.log.log("INFO", "=" * 40)

    summary_tunnels = []
    for tcfg, r in zip(engine.tunnels, engine.results):
        detail = r.detail or ("up" if r.ok else t("main.not_connected"))
        if tcfg.type == "openvpn" and r.ok and ext_ip:
            detail = detail if detail != "up" else ext_ip
        summary_tunnels.append((tcfg.name, r.ok, detail))

    log_paths = {}
    for tcfg in engine.tunnels:
        if tcfg.log:
            log_paths[tcfg.name] = tcfg.log
    log_paths["debug"] = str(engine.log.log_path)

    ui.print_summary(
        tunnels=summary_tunnels,
        checks=[(r.label, r.status, r.detail) for r in check_results],
        log_paths=log_paths,
    )


def _keepalive_loop(engine: Engine, reconnect_lock=None) -> None:
    """Monitor VPN processes, reconnect when dead (e.g. after macOS sleep)."""
    interval = cfg.timeouts.keepalive_interval
    ui.info(f"🔄 {t('main.keepalive_started', interval=interval)}")
    engine.log.log("INFO", f"Keepalive mode: checking every {interval}s")

    last_tick = time.monotonic()
    last_reconnect = 0.0
    reconnect_count = 0
    reconnect_cooldown = 5.0  # seconds between reconnect attempts (debounce)

    while True:
        time.sleep(interval)
        now = time.monotonic()
        elapsed = now - last_tick
        last_tick = now

        # Detect sleep: elapsed >> interval means system was suspended
        slept = elapsed > interval * 2

        dead = engine.check_alive()

        if not slept and not dead:
            continue

        # Debounce: skip if reconnect was done recently (lid dance protection)
        if now - last_reconnect < reconnect_cooldown:
            engine.log.log(
                "INFO",
                f"Skipping reconnect (cooldown: {reconnect_cooldown - (now - last_reconnect):.1f}s remaining)",
            )
            continue

        # Determine reason
        if slept and dead:
            reason = "wake"
            dead_names = ", ".join(tc.name for tc, _ in dead)
            engine.log.log(
                "INFO",
                f"Sleep detected (elapsed={elapsed:.0f}s), dead: {dead_names}",
            )
        elif slept:
            reason = "wake"
            engine.log.log(
                "INFO",
                f"Sleep detected (elapsed={elapsed:.0f}s), proactive reconnect",
            )
        else:
            reason = "dead"
            dead_names = ", ".join(tc.name for tc, pid in dead)
            engine.log.log("WARN", f"Keepalive: dead processes: {dead_names}")

        reason_display = (
            t("main.keepalive_reason_wake")
            if reason == "wake"
            else t("main.keepalive_reason_dead")
        )
        print(
            f"\n  {ui.YELLOW}🔄 {t('main.keepalive_reconnecting', reason=reason_display)}{ui.NC}"
        )

        # Hold lock during reconnect to prevent signal handler from
        # calling disconnect_all() concurrently
        if reconnect_lock:
            if not reconnect_lock.acquire(timeout=30):
                engine.log.log("WARN", "Reconnect lock timeout, skipping")
                continue
        try:
            if reason == "wake":
                check_results, ext_ip = engine.reconnect_all(quiet=True)
            else:
                # Reconnect only dead tunnels, leave healthy ones running
                for tc, pid in dead:
                    engine.log.log(
                        "INFO", f"Reconnecting dead tunnel: {tc.name} (was PID={pid})"
                    )
                    engine.reconnect_one(tc.name, quiet=True)
                check_results, ext_ip = engine.check_all(quiet=True)
            reconnect_count += 1
            last_reconnect = time.monotonic()
        except Exception as e:
            engine.log.log("ERROR", f"Keepalive reconnect failed: {e}")
            ui.fail(t("main.keepalive_failed", error=str(e)))
            # Update last_reconnect even on failure to prevent retry storm
            last_reconnect = time.monotonic()
            continue
        finally:
            if reconnect_lock:
                reconnect_lock.release()

        ok_count = sum(1 for r in engine.results if r.ok)
        total = len(engine.results)
        names = ", ".join(
            tc.name for tc, r in zip(engine.tunnels, engine.results) if r.ok
        )
        ui.ok(t("main.keepalive_reconnected", ok=ok_count, total=total, names=names))
        engine.log.log(
            "INFO",
            f"Keepalive: reconnected {ok_count}/{total} (total reconnects: {reconnect_count})",
        )


def _crash_diagnostics(log: Logger | None, exc: BaseException) -> None:
    """Log crash state for post-mortem debugging."""
    print(f"\n  {ui.RED}{ui.BOLD}💥 {t('main.crashed')}{ui.NC}", file=sys.stderr)
    print(f"  {ui.RED}├─ {type(exc).__name__}: {exc}{ui.NC}", file=sys.stderr)
    if log:
        print(
            f"  {ui.RED}└─ {t('main.log_colon', path=log.log_path)}{ui.NC}",
            file=sys.stderr,
        )
        log.log("FATAL", f"{type(exc).__name__}: {exc}")
        log.log("FATAL", traceback.format_exc())
        from tv.vpn.registry import available_types, get_plugin

        vpn_keywords = []
        for tp in available_types():
            vpn_keywords.extend(get_plugin(tp).process_names)

        if IS_WINDOWS:
            ps_cmd = ["tasklist", "/V"]
        else:
            ps_cmd = ["ps", "aux"]
        r = subprocess.run(
            ps_cmd,
            capture_output=True,
            text=True,
            timeout=cfg.timeouts.ps_aux,
        )
        for line in r.stdout.splitlines():
            if any(kw in line for kw in vpn_keywords):
                log.log("FATAL", f"  {line.strip()}")


if __name__ == "__main__":
    try:
        main()
    except SetupRequiredError as e:
        print(f"\n  {ui.RED}❌ {e}{ui.NC}", file=sys.stderr)
        sys.exit(1)
    except SystemExit:
        raise
    except BaseException as e:
        _crash_diagnostics(_log, e)
        sys.exit(1)
