"""WireGuard tunnel connection via wg-quick."""

from __future__ import annotations

import platform

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register

_IS_LINUX = platform.system() == "Linux"


@register("wireguard")
class WireGuardPlugin(TunnelPlugin):
    """WireGuard tunnel plugin (client mode via wg-quick)."""

    binary = "wg-quick"
    type_display_name = "WireGuard"
    process_names = ("wireguard-go", "wg-quick")

    @classmethod
    def emergency_patterns(cls, script_dir) -> list[str]:
        return ["wireguard-go"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        if _IS_LINUX:
            return None
        iface = tcfg.interface
        if iface:
            pids = proc.find_pids(f"wireguard-go {iface}")
            return pids[0] if pids else None
        return None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(
                "config_file", "param.wg_config",
                default=cfg.defaults.wireguard_config,
                env_var="VPN_WG_CONFIG", target="config_file",
            ),
        ]

    @property
    def process_name(self) -> str:
        return "wireguard-go"

    @property
    def display_name(self) -> str:
        return "WireGuard"

    def connect(self) -> VPNResult:
        config_path = self.script_dir / self.cfg.config_file

        self.log.log("INFO", f"Config: {config_path}")

        # Snapshot interfaces before connect (for auto-detection)
        ifaces_before = set(self.net.interfaces().keys())

        # wg-quick up runs synchronously and exits
        self.log.log("INFO", f"Launch: sudo wg-quick up {config_path}")
        result = proc.run(
            ["wg-quick", "up", str(config_path)],
            sudo=True,
        )

        if result.returncode != 0:
            ui.fail(t("vpn.wg.setup_failed", rc=result.returncode))
            self.log.log("ERROR", f"wg-quick up failed (exit code {result.returncode})")
            details: list[tuple[str, str]] = []
            stderr = (result.stderr or "").strip()
            if stderr:
                details.append(("", stderr.splitlines()[-1]))
                self.log.log("ERROR", f"wg-quick stderr: {stderr}")
            details.append(("", t("vpn.wg.log_hint", path=config_path)))
            ui.error_tree(details)
            return VPNResult(ok=False)

        # Detect interface
        interface = self.cfg.interface
        detected_iface = None

        if interface:
            # Explicit interface - wait for it
            if not proc.wait_for(
                f"WireGuard ({interface})",
                lambda: self.net.check_interface(interface),
                cfg.timeouts.wireguard_iface,
                self.log,
            ):
                ui.fail(t("vpn.wg.not_connected", timeout=cfg.timeouts.wireguard_iface))
                self.log.log("ERROR", f"WireGuard interface {interface} did not appear")
                return VPNResult(ok=False)
            detected_iface = interface
        else:
            # Auto-detect new interface
            def _check_new_iface():
                nonlocal detected_iface
                ifaces_now = set(self.net.interfaces().keys())
                new_ifaces = list(ifaces_now - ifaces_before)
                wg_ifaces = [
                    i for i in new_ifaces
                    if i.startswith("utun") or i.startswith("wg")
                ]
                if wg_ifaces:
                    detected_iface = sorted(wg_ifaces)[0]
                    return True
                return False

            if not proc.wait_for(
                "WireGuard",
                _check_new_iface,
                cfg.timeouts.wireguard_iface,
                self.log,
            ):
                ui.fail(t("vpn.wg.not_connected", timeout=cfg.timeouts.wireguard_iface))
                self.log.log("ERROR", "WireGuard interface did not appear")
                return VPNResult(ok=False)
            self.cfg.interface = detected_iface

        # Find PID (macOS: wireguard-go process; Linux: kernel WG, no PID)
        pid = None
        if not _IS_LINUX and detected_iface:
            pids = proc.find_pids(f"wireguard-go {detected_iface}")
            if pids:
                pid = pids[0]
        self._pid = pid

        ui.ok(t("vpn.wg.connected", iface=detected_iface))
        self.log.log("INFO", f"WireGuard connected ({detected_iface})")
        self.log.log_lines("INFO", f"ifconfig {detected_iface}:\n{self.net.iface_info(detected_iface)}")

        self.add_routes()
        self.setup_dns()

        self.log.log("INFO", f"Routes after WireGuard:\n{self.net.route_table()}")

        return VPNResult(ok=True, pid=pid)

    def disconnect(self) -> None:
        """Override: use wg-quick down instead of kill by PID."""
        config_path = self.script_dir / self.cfg.config_file
        self.log.log("INFO", f"Disconnect: sudo wg-quick down {config_path}")
        proc.run(["wg-quick", "down", str(config_path)], sudo=True)

    def _kill_by_pattern(self) -> None:
        iface = self.cfg.interface
        if iface and not _IS_LINUX:
            proc.kill_pattern(f"wireguard-go {iface}", sudo=True)
        else:
            # Fallback: wg-quick down
            config_path = self.script_dir / self.cfg.config_file
            proc.run(["wg-quick", "down", str(config_path)], sudo=True)
