"""OpenVPN connection with Tunnelblick detection."""

from __future__ import annotations

import time

from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger
from tv.proc import IS_WINDOWS
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register


def _show_error(pid: int | None, log_path: Path, log: Logger) -> None:
    """Display OpenVPN error details to user and log."""
    ui.fail(t("vpn.ovpn.not_connected", timeout=cfg.timeouts.openvpn_init))
    log.log("ERROR", f"OpenVPN did not connect within {cfg.timeouts.openvpn_init}s")

    details: list[tuple[str, str]] = []
    if pid and proc.is_alive(pid):
        details.append(("", t("vpn.ovpn.alive_no_iface", pid=pid)))
        log.log("WARN", f"OpenVPN PID={pid} alive but interface not found")
    elif pid:
        details.append(("", t("vpn.ovpn.exited", pid=pid)))
        log.log("ERROR", f"OpenVPN PID={pid} exited")
    else:
        details.append(("", t("vpn.ovpn.pid_not_found")))
        log.log("ERROR", "OpenVPN PID not found after launch")

    details.append(("", t("vpn.ovpn.log_hint", path=log_path)))
    ui.error_tree(details)


@register("openvpn")
class OpenVPNPlugin(TunnelPlugin):
    """OpenVPN tunnel plugin with Tunnelblick detection."""

    binary = "openvpn"
    type_display_name = "OpenVPN"
    process_names = ("openvpn",)
    kill_patterns = (
        "openvpn --config .*/tunnelvault/",
    )

    @classmethod
    def emergency_patterns(cls, script_dir) -> list[str]:
        return [f"openvpn --config {script_dir}"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        config_path = script_dir / tcfg.config_file
        pids = proc.find_pids(f"openvpn --config {config_path}")
        return pids[0] if pids else None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam("config_file", "param.ovpn_config", default=cfg.defaults.openvpn_config,
                         env_var="VPN_OVPN_CONFIG", target="config_file"),
        ]

    @property
    def process_name(self) -> str:
        return "openvpn"

    @property
    def display_name(self) -> str:
        return "OpenVPN"

    def connect(self) -> VPNResult:
        config_path = self.script_dir / self.cfg.config_file
        log_path = self._default_log_path()

        self.log.log("INFO", f"Config: {config_path}")

        if err := self._check_config_file("vpn.ovpn.config_not_found"):
            return err

        # --- Tunnelblick detection (macOS only) ---
        if not IS_WINDOWS and proc.find_pids("Tunnelblick"):
            tb_ovpn = proc.find_pids("Tunnelblick.*openvpn")
            if tb_ovpn:
                pid = tb_ovpn[0]
                ui.warn(t("vpn.ovpn.tunnelblick_active", pid=pid))
                self.log.log("WARN", f"Tunnelblick openvpn PID={pid}, skipping launch")
                ui.ok(f"{t('vpn.ovpn.using_tunnelblick')}")
                self.log.log("INFO", "OpenVPN: using Tunnelblick")
                return VPNResult(ok=True, detail="Tunnelblick")

        # Snapshot interfaces BEFORE connect (for interface detection)
        ifaces_before = set(self.net.interfaces().keys())

        # --- Launch ---
        if IS_WINDOWS:
            # Windows: no --daemon (POSIX-only), use run_background()
            self.log.log("INFO", f"Launch: openvpn --config {config_path} --log {log_path}")
            ovpn_proc = proc.run_background(
                ["openvpn", "--config", str(config_path), "--log", str(log_path)],
                sudo=True,
            )
            pid = ovpn_proc.pid
        else:
            self.log.log("INFO", f"Launch: sudo openvpn --config {config_path} --daemon --log {log_path}")
            proc.run(
                ["openvpn", "--config", str(config_path), "--daemon", "--log", str(log_path)],
                sudo=True,
            )
            # Find PID (openvpn --daemon forks; poll up to 1.5s for forked process)
            pid = None
            for _ in range(3):
                time.sleep(0.5)
                pids = proc.find_pids(f"openvpn --config {config_path}")
                if pids:
                    pid = pids[0]
                    break
        self._pid = pid

        if pid:
            detected_iface = None

            def _check_new_iface():
                nonlocal detected_iface
                ifaces_now = set(self.net.interfaces().keys())
                new_ifaces = list(ifaces_now - ifaces_before)
                if IS_WINDOWS:
                    # Windows: TAP-Windows/Wintun adapters have arbitrary names
                    if new_ifaces:
                        detected_iface = sorted(new_ifaces)[0]
                        return True
                else:
                    new_tun = [
                        i for i in new_ifaces
                        if i.startswith("tun") or i.startswith("utun")
                    ]
                    if new_tun:
                        detected_iface = sorted(new_tun)[0]
                        return True
                return False

            if proc.wait_for("OpenVPN", _check_new_iface, cfg.timeouts.openvpn_init, self.log):
                if not self.cfg.interface:
                    self.cfg.interface = detected_iface

                ui.ok(t("vpn.ovpn.connected", iface=detected_iface))
                self.log.log("INFO", f"OpenVPN connected ({detected_iface})")

                # Extra routes/DNS from TOML (beyond what .ovpn pushes)
                self.add_routes()
                self.setup_dns()

                self.log.log("INFO", f"Routes after OpenVPN:\n{self.net.route_table()}")
                return VPNResult(ok=True, pid=pid)

        # --- Failed ---
        _show_error(pid, log_path, self.log)
        return VPNResult(ok=False)

    def _kill_by_pattern(self) -> None:
        config_path = self.script_dir / self.cfg.config_file
        proc.kill_pattern(f"openvpn --config {config_path}", sudo=True)
        log_path = self._default_log_path()
        proc.kill_pattern(f"openvpn.*--log {log_path}", sudo=True)
