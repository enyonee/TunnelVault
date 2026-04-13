"""sing-box tunnel connection."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register

_LOCAL_BINARY = "bin/sing-box"
_version_logged = False


def _resolve_binary(script_dir: Path | None = None) -> str:
    """Prefer local bin/sing-box over system PATH."""
    if script_dir:
        local = script_dir / _LOCAL_BINARY
        if local.is_file():
            return str(local)
    return "sing-box"


def _log_version(sb: str, log: Logger) -> None:
    """Log sing-box version on first use."""
    global _version_logged
    if _version_logged:
        return
    _version_logged = True
    try:
        r = subprocess.run([sb, "version"], capture_output=True, text=True, timeout=5)
        version_line = r.stdout.strip().split("\n")[0] if r.stdout else "unknown"
        log.log("INFO", f"sing-box binary: {sb}")
        log.log("INFO", f"sing-box version: {version_line}")
    except Exception:
        log.log("WARN", f"sing-box version check failed: {sb}")


@register("singbox")
class SingBoxPlugin(TunnelPlugin):
    """sing-box tunnel plugin."""

    binary = "sing-box"
    type_display_name = "sing-box"
    process_names = ("sing-box",)
    version_cmd = ("sing-box", "version")

    @classmethod
    def get_version(cls) -> str:
        """Get sing-box version, preferring local binary."""
        from pathlib import Path

        script_dir = Path(__file__).parent.parent.parent
        sb = _resolve_binary(script_dir)
        try:
            r = subprocess.run([sb, "version"], capture_output=True, text=True, timeout=5)
            first = (r.stdout or "").strip().split("\n")[0]
            return first.replace("sing-box version ", "sing-box ") if first else ""
        except Exception:
            return ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._patched_config: str | None = None

    @classmethod
    def emergency_patterns(cls, script_dir) -> list[str]:
        return [f"sing-box run -c {script_dir}"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        config_path = script_dir / tcfg.config_file
        pids = proc.find_pids(f"sing-box run -c {config_path}")
        if not pids:
            # Also match local binary path
            sb = _resolve_binary(script_dir)
            if sb != "sing-box":
                pids = proc.find_pids(f"{sb} run -c {config_path}")
        if pids:
            return pids[0]
        # Also check patched config pattern (proxy mode)
        pids = proc.find_pids(f"sing-box run -c {cfg.paths.temp_dir}/sb_proxy_")
        return pids[0] if pids else None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(
                "config_file",
                "param.sb_config",
                default=cfg.defaults.singbox_config,
                env_var="VPN_SINGBOX_CONFIG",
                target="config_file",
            ),
        ]

    @property
    def process_name(self) -> str:
        return "sing-box"

    @property
    def display_name(self) -> str:
        return "sing-box"

    def connect(self) -> VPNResult:
        if cfg.mode == "proxy-only":
            return self._connect_proxy()
        return self._connect_tun()

    def _connect_proxy(self) -> VPNResult:
        """Connect in proxy mode: mixed inbound, no TUN, no routes, no sudo."""
        config_path = self.script_dir / self.cfg.config_file
        log_path = self._default_log_path()
        port = cfg.proxy_port

        self.log.log("INFO", f"Proxy mode: config={config_path}, port={port}")

        if err := self._check_config_file("vpn.sb.config_not_found"):
            return err

        # Patch config: replace tun inbound with mixed inbound
        patched = _patch_for_proxy(config_path, port, self.log)
        if not patched:
            ui.fail("Failed to generate proxy config")
            return VPNResult(ok=False)

        run_config = patched
        self._patched_config = patched

        # Launch without sudo (no TUN = no root needed)
        sb = _resolve_binary(self.script_dir)
        _log_version(sb, self.log)
        self.log.log("INFO", f"Launch: {sb} run -c {run_config}")
        sb_proc = proc.run_background(
            [sb, "run", "-c", run_config],
            sudo=False,
            log_path=str(log_path),
        )
        sb_pid = sb_proc.pid
        self._pid = sb_pid
        self.log.log("INFO", f"sing-box proxy PID={sb_pid}")

        # Wait for proxy port to be listening
        if not proc.wait_for(
            f"sing-box proxy (:{port})",
            lambda: _check_port_listening(port),
            cfg.timeouts.singbox_iface,
            self.log,
        ):
            _show_error(sb_proc, log_path, self.log)
            return VPNResult(ok=False, pid=sb_pid)

        ui.ok(f"sing-box proxy listening on 127.0.0.1:{port}")
        self.log.log("INFO", f"sing-box proxy connected (:{port})")

        return VPNResult(ok=True, pid=sb_pid)

    def _connect_tun(self) -> VPNResult:
        """Connect in TUN mode (original behavior)."""
        config_path = self.script_dir / self.cfg.config_file
        log_path = self._default_log_path()
        interface = self.cfg.interface

        self.log.log("INFO", f"Config: {config_path}")

        if err := self._check_config_file("vpn.sb.config_not_found"):
            return err

        # Use original config as-is.
        # Domain-based route rules break TUN routing in sing-box 1.12+ on macOS
        # (any domain_suffix/domain rule triggers sniff-first mode that disrupts
        # packet flow). Bypass for .ru domains is handled by TunnelVault's
        # DNS bypass proxy (/etc/resolver/ + BypassDNSProxy).
        run_config = str(config_path)

        # Launch in background
        sb = _resolve_binary(self.script_dir)
        _log_version(sb, self.log)
        self.log.log("INFO", f"Launch: sudo {sb} run -c {run_config}")
        sb_proc = proc.run_background(
            [sb, "run", "-c", run_config],
            sudo=True,
            log_path=str(log_path),
        )
        sb_pid = sb_proc.pid
        self._pid = sb_pid
        self.log.log("INFO", f"sing-box PID={sb_pid}")

        # Wait for interface (abort early if process dies)
        if not proc.wait_for(
            f"sing-box ({interface})",
            lambda: self.net.check_interface(interface),
            cfg.timeouts.singbox_iface,
            self.log,
            abort_fn=lambda: not proc.is_alive(sb_pid),
        ):
            _show_error(sb_proc, log_path, self.log)
            return VPNResult(ok=False, pid=sb_pid)

        # Connected
        ui.ok(t("vpn.sb.connected", iface=interface))
        self.log.log("INFO", f"sing-box connected ({interface})")
        self.log.log_lines(
            "INFO", f"ifconfig {interface}:\n{self.net.iface_info(interface)}"
        )

        # Routes through interface (hosts + networks from config/targets)
        self.add_routes()

        # DNS resolver (domains + nameservers from config/targets)
        self.setup_dns()

        self.log.log("INFO", f"Routes after sing-box:\n{self.net.route_table()}")

        # Connectivity probe through this tunnel
        self._probe_connectivity(interface)

        return VPNResult(ok=True, pid=sb_pid)

    def disconnect(self) -> None:
        super().disconnect()
        # Clean up patched config file
        if self._patched_config:
            try:
                os.unlink(self._patched_config)
            except OSError:
                pass
            self._patched_config = None

    def _probe_connectivity(self, interface: str) -> None:
        """Quick connectivity probe through tunnel, results logged."""
        try:
            r = subprocess.run(
                [
                    "curl",
                    "-sS",
                    "--max-time",
                    "5",
                    "--interface",
                    interface,
                    "https://ifconfig.me",
                ],
                capture_output=True,
                text=True,
                timeout=8,
            )
            exit_ip = r.stdout.strip()
            self.log.log(
                "CHECK",
                f"probe exit-ip via {interface}: {exit_ip} (exit={r.returncode})",
            )
            if r.stderr.strip():
                self.log.log("CHECK", f"probe exit-ip stderr: {r.stderr.strip()}")
        except Exception as e:
            self.log.log("WARN", f"probe exit-ip: {e}")

    def _kill_by_pattern(self) -> None:
        config_path = self.script_dir / self.cfg.config_file
        proc.kill_pattern(f"sing-box run -c {config_path}", sudo=True)
        # Also kill by patched config pattern (proxy mode)
        if self._patched_config:
            proc.kill_pattern(f"sing-box run -c {self._patched_config}", sudo=True)


def _patch_for_proxy(
    config_path: Path,
    port: int,
    log: Logger,
) -> str | None:
    """Replace TUN inbound with mixed (HTTP+SOCKS5) inbound for proxy mode.

    Reads user's sing-box config, removes all tun/mixed inbounds, adds a single
    mixed inbound on 127.0.0.1:port. Returns temp file path, or None on error.
    """
    try:
        data = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        log.log("WARN", f"proxy patch: cannot read {config_path}: {e}")
        return None

    # Replace inbounds: remove tun, add mixed
    mixed_inbound = {
        "type": "mixed",
        "tag": "proxy-in",
        "listen": "127.0.0.1",
        "listen_port": port,
    }
    # Keep non-tun inbounds (e.g. dns), replace/add mixed
    old_inbounds = data.get("inbounds", [])
    new_inbounds = [ib for ib in old_inbounds if ib.get("type") not in ("tun", "mixed")]
    new_inbounds.insert(0, mixed_inbound)
    data["inbounds"] = new_inbounds

    # Remove auto_route and strict_route from route (TUN-specific)
    route = data.get("route", {})
    route.pop("auto_detect_interface", None)

    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix="sb_proxy_",
            suffix=".json",
            dir=cfg.paths.temp_dir,
        )
        os.write(fd, json.dumps(data, indent=2).encode())
        os.close(fd)
    except OSError as e:
        log.log("WARN", f"proxy patch: cannot write temp config: {e}")
        return None

    log.log("INFO", f"proxy patch: mixed inbound on :{port} ({tmp_path})")
    return tmp_path


def _check_port_listening(port: int) -> bool:
    """Check if a port is listening on localhost."""
    import socket

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


def _show_error(sb_proc, log_path: Path, log: Logger) -> None:
    """Display sing-box error details."""
    ui.fail(t("vpn.sb.not_connected", timeout=cfg.timeouts.singbox_iface))
    log.log("ERROR", f"sing-box did not start within {cfg.timeouts.singbox_iface}s")

    pid = sb_proc.pid
    if proc.is_alive(pid):
        details = [("", t("vpn.sb.alive_no_iface", pid=pid))]
        log.log("WARN", f"sing-box PID={pid} alive but interface not found")
    else:
        rc = sb_proc.poll()
        rc_display = rc if rc is not None else "?"
        details = [("", t("vpn.sb.exited", rc=rc_display))]
        log.log("ERROR", f"sing-box process exited with code {rc}")

    details.append(("", t("vpn.sb.log_hint", path=log_path)))
    ui.error_tree(details)
