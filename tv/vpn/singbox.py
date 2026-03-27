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


@register("singbox")
class SingBoxPlugin(TunnelPlugin):
    """sing-box tunnel plugin."""

    binary = "sing-box"
    type_display_name = "sing-box"
    process_names = ("sing-box",)

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
        if pids:
            return pids[0]
        pids = proc.find_pids(f"sing-box run -c {cfg.paths.temp_dir}/sb_iface_")
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
        config_path = self.script_dir / self.cfg.config_file
        log_path = self._default_log_path()
        interface = self.cfg.interface

        self.log.log("INFO", f"Config: {config_path}")

        if err := self._check_config_file("vpn.sb.config_not_found"):
            return err

        # Sync interface_name in JSON config with the resolved interface.
        # JSON may have "utun98" (macOS) but on Linux interface is "tun0".
        run_config = str(config_path)
        patched = _sync_interface(config_path, interface, self.log)
        if patched:
            run_config = patched
            self._patched_config = patched

        # Launch in background
        self.log.log("INFO", f"Launch: sudo sing-box run -c {run_config}")
        sb_proc = proc.run_background(
            ["sing-box", "run", "-c", run_config],
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

    def disconnect(self) -> None:
        super().disconnect()
        if self._patched_config:
            try:
                os.unlink(self._patched_config)
            except OSError:
                pass
            self._patched_config = None

    def _kill_by_pattern(self) -> None:
        config_path = self.script_dir / self.cfg.config_file
        proc.kill_pattern(f"sing-box run -c {config_path}", sudo=True)
        if self._patched_config:
            proc.kill_pattern(f"sing-box run -c {self._patched_config}", sudo=True)


def _sync_interface(
    config_path: Path,
    interface: str,
    log: "Logger",
) -> str | None:
    """Patch interface_name in sing-box JSON if it differs from resolved interface.

    Returns temp file path if patched, None if no change needed.
    """
    try:
        data = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None

    changed = False
    for inb in data.get("inbounds", []):
        if inb.get("type") == "tun" and inb.get("interface_name") != interface:
            log.log(
                "INFO",
                f"interface sync: {inb.get('interface_name')} -> {interface}",
            )
            inb["interface_name"] = interface
            changed = True

    if not changed:
        return None

    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix="sb_iface_",
            suffix=".json",
            dir=cfg.paths.temp_dir,
        )
        os.write(fd, json.dumps(data, indent=2).encode())
        os.close(fd)
    except OSError as e:
        log.log("WARN", f"interface sync: cannot write temp config: {e}")
        return None

    return tmp_path


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
