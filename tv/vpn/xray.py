"""xray-core tunnel connection (TUN + proxy modes)."""

from __future__ import annotations

import shutil
import socket
import subprocess
from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger
from tv.vpn.base import ConfigParam, TunnelPlugin, TunnelConfig, VPNResult
from tv.vpn.registry import register

_LOCAL_BINARY = "bin/xray"
_version_logged = False


def _resolve_binary(script_dir: Path | None = None) -> str:
    """Prefer local bin/xray, fallback to PATH."""
    if script_dir:
        local = script_dir / _LOCAL_BINARY
        if local.is_file():
            return str(local)
    which = shutil.which("xray")
    return which or "xray"


def _log_version(binary: str, log: Logger) -> None:
    """Log xray version on first use."""
    global _version_logged
    if _version_logged:
        return
    _version_logged = True
    try:
        r = subprocess.run(
            [binary, "version"], capture_output=True, text=True, timeout=5
        )
        version_line = r.stdout.strip().split("\n")[0] if r.stdout else "unknown"
        log.log("INFO", f"xray binary: {binary}")
        log.log("INFO", f"xray version: {version_line}")
    except Exception:
        log.log("WARN", f"xray version check failed: {binary}")


def _check_port_listening(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is listening on given host."""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


@register("xray")
class XrayPlugin(TunnelPlugin):
    """xray-core tunnel plugin (supports TUN + proxy mode)."""

    binary = "xray"
    type_display_name = "xray-core"
    process_names = ("xray",)
    version_cmd = ("xray", "version")

    @classmethod
    def get_version(cls) -> str:
        """Get xray version, preferring local binary."""
        bin_path = _resolve_binary(Path(__file__).parent.parent.parent)
        try:
            r = subprocess.run(
                [bin_path, "version"], capture_output=True, text=True, timeout=5
            )
            first = (r.stdout or "").strip().split("\n")[0]
            return first if first else ""
        except Exception:
            return ""

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(
                key="config_file",
                target="config_file",
                label="param.xray_config",
                default=cfg.defaults.xray_config,
                env_var="VPN_XRAY_CONFIG",
            ),
        ]

    @classmethod
    def emergency_patterns(cls, script_dir: Path) -> list[str]:
        return [f"xray run -c {script_dir}"]

    @classmethod
    def discover_pid(cls, tcfg: TunnelConfig, script_dir: Path) -> int | None:
        config_path = script_dir / tcfg.config_file
        pids = proc.find_pids(f"xray run -c {config_path}")
        if not pids:
            bin_path = _resolve_binary(script_dir)
            if bin_path != "xray":
                pids = proc.find_pids(f"{bin_path} run -c {config_path}")
        return pids[0] if pids else None

    @property
    def process_name(self) -> str:
        return "xray"

    @property
    def display_name(self) -> str:
        return self.cfg.name or "xray"

    def _get_mode(self) -> str:
        # mode из [tunnels.xray] extra; default "tun"
        return self.cfg.extra.get("mode", "tun")

    def _get_socks_port(self) -> int:
        raw = self.cfg.extra.get("socks_port", cfg.defaults.xray_socks_port)
        return int(raw)

    def connect(self) -> VPNResult:
        if self._get_mode() == "proxy":
            return self._connect_proxy()
        return self._connect_tun()

    def _connect_tun(self) -> VPNResult:
        """TUN mode: запуск с sudo, ожидание интерфейса."""
        config_path = self.script_dir / self.cfg.config_file
        log_path = self._default_log_path()
        interface = self.cfg.interface

        self.log.log("INFO", f"Config: {config_path}")

        if err := self._check_config_file("vpn.xray.config_not_found"):
            return err

        bin_path = _resolve_binary(self.script_dir)
        _log_version(bin_path, self.log)
        self.log.log("INFO", f"Launch: sudo {bin_path} run -c {config_path}")
        xr_proc = proc.run_background(
            [bin_path, "run", "-c", str(config_path)],
            sudo=True,
            log_path=str(log_path),
        )
        xr_pid = xr_proc.pid
        self._pid = xr_pid
        self.log.log("INFO", f"xray PID={xr_pid}")

        if not proc.wait_for(
            f"xray ({interface})",
            lambda: self.net.check_interface(interface),
            cfg.timeouts.xray_iface,
            self.log,
            abort_fn=lambda: not proc.is_alive(xr_pid),
        ):
            _show_error(xr_proc, log_path, self.log)
            return VPNResult(ok=False, pid=xr_pid)

        # Late crash detection: процесс мог умереть сразу после появления iface
        if not proc.is_alive(xr_pid):
            rc = xr_proc.poll()
            rc_display = rc if rc is not None else "?"
            ui.fail(t("vpn.xray.late_crash", pid=xr_pid, rc=rc_display))
            self.log.log("ERROR", f"xray died after interface appeared (rc={rc})")
            return VPNResult(ok=False, pid=xr_pid)

        ui.ok(t("vpn.xray.connected", iface=interface))
        self.log.log("INFO", f"xray connected ({interface})")
        self.log.log_lines(
            "INFO", f"ifconfig {interface}:\n{self.net.iface_info(interface)}"
        )

        self.add_routes()
        self.setup_dns()

        self.log.log("INFO", f"Routes after xray:\n{self.net.route_table()}")
        self._probe_connectivity(interface)

        return VPNResult(ok=True, pid=xr_pid)

    def _connect_proxy(self) -> VPNResult:
        """Proxy mode: запуск без sudo, ожидание SOCKS порта.

        В proxy режиме user в config.json настраивает socks/http inbound
        на 127.0.0.1:<socks_port>. Плагин не патчит config - только ждёт порт.
        Routes/DNS не применяются - клиенты используют через SOCKS.
        """
        config_path = self.script_dir / self.cfg.config_file
        log_path = self._default_log_path()
        port = self._get_socks_port()

        self.log.log("INFO", f"Proxy mode: config={config_path}, port={port}")

        if err := self._check_config_file("vpn.xray.config_not_found"):
            return err

        bin_path = _resolve_binary(self.script_dir)
        _log_version(bin_path, self.log)
        self.log.log("INFO", f"Launch: {bin_path} run -c {config_path}")
        xr_proc = proc.run_background(
            [bin_path, "run", "-c", str(config_path)],
            sudo=False,
            log_path=str(log_path),
        )
        xr_pid = xr_proc.pid
        self._pid = xr_pid
        self.log.log("INFO", f"xray proxy PID={xr_pid}")

        if not proc.wait_for(
            f"xray proxy (:{port})",
            lambda: _check_port_listening(port),
            cfg.timeouts.xray_iface,
            self.log,
            abort_fn=lambda: not proc.is_alive(xr_pid),
        ):
            _show_error(xr_proc, log_path, self.log, port=port)
            return VPNResult(ok=False, pid=xr_pid)

        # Late crash detection
        if not proc.is_alive(xr_pid):
            rc = xr_proc.poll()
            rc_display = rc if rc is not None else "?"
            ui.fail(t("vpn.xray.late_crash", pid=xr_pid, rc=rc_display))
            self.log.log("ERROR", f"xray died after port opened (rc={rc})")
            return VPNResult(ok=False, pid=xr_pid)

        ui.ok(t("vpn.xray.connected_proxy", port=port))
        self.log.log("INFO", f"xray proxy connected (:{port})")

        return VPNResult(ok=True, pid=xr_pid, detail=f"socks5://127.0.0.1:{port}")

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
        # В proxy mode запускали без sudo - но kill_pattern(sudo=True) не навредит,
        # так как pkill с sudo убивает и процессы текущего user-а
        proc.kill_pattern(f"xray run -c {config_path}", sudo=True)


def _show_error(
    xr_proc,
    log_path: Path,
    log: Logger,
    *,
    port: int | None = None,
) -> None:
    """Display xray error details."""
    ui.fail(t("vpn.xray.not_connected", timeout=cfg.timeouts.xray_iface))
    log.log("ERROR", f"xray did not start within {cfg.timeouts.xray_iface}s")

    pid = xr_proc.pid
    if proc.is_alive(pid):
        if port is not None:
            details = [("", t("vpn.xray.alive_no_port", pid=pid, port=port))]
            log.log("WARN", f"xray PID={pid} alive but port {port} not listening")
        else:
            details = [("", t("vpn.xray.alive_no_iface", pid=pid))]
            log.log("WARN", f"xray PID={pid} alive but interface not found")
    else:
        rc = xr_proc.poll()
        rc_display = rc if rc is not None else "?"
        details = [("", t("vpn.xray.exited", rc=rc_display))]
        log.log("ERROR", f"xray process exited with code {rc}")

    details.append(("", t("vpn.xray.log_hint", path=log_path)))
    ui.error_tree(details)
