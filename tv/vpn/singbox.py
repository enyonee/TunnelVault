"""sing-box tunnel connection."""

from __future__ import annotations

import subprocess
from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register


@register("singbox")
class SingBoxPlugin(TunnelPlugin):
    """sing-box tunnel plugin."""

    binary = "sing-box"
    type_display_name = "sing-box"
    process_names = ("sing-box",)

    @classmethod
    def emergency_patterns(cls, script_dir) -> list[str]:
        return [f"sing-box run -c {script_dir}"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        config_path = script_dir / tcfg.config_file
        pids = proc.find_pids(f"sing-box run -c {config_path}")
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

    def _singbox_bin(self) -> str:
        """Return path to sing-box binary: local bin/ first, then PATH."""
        local = self.script_dir / "bin" / "sing-box"
        if local.exists():
            return str(local)
        return "sing-box"

    def connect(self) -> VPNResult:
        config_path = self.script_dir / self.cfg.config_file
        log_path = self._default_log_path()
        interface = self.cfg.interface
        sb_bin = self._singbox_bin()

        self.log.log("INFO", f"Config: {config_path}")
        self.log.log("INFO", f"Binary: {sb_bin}")

        if err := self._check_config_file("vpn.sb.config_not_found"):
            return err

        run_config = str(config_path)

        # Launch in background
        self.log.log("INFO", f"Launch: sudo {sb_bin} run -c {run_config}")
        sb_proc = proc.run_background(
            [sb_bin, "run", "-c", run_config],
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

    def _probe_connectivity(self, interface: str) -> None:
        """Quick connectivity probe through tunnel, results logged."""
        try:
            r = subprocess.run(
                [
                    "curl", "-sS", "--max-time", "5",
                    "--interface", interface,
                    "https://ifconfig.me",
                ],
                capture_output=True, text=True, timeout=8,
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
