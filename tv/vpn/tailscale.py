"""Tailscale/Headscale tunnel connection via tailscale CLI."""

from __future__ import annotations

import json
import platform
import subprocess

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register

_IS_LINUX = platform.system() == "Linux"


@register("tailscale")
class TailscalePlugin(TunnelPlugin):
    """Tailscale/Headscale tunnel plugin."""

    binary = "tailscale"
    type_display_name = "Tailscale"
    process_names = ("tailscaled",)
    version_cmd = ("tailscale", "version")

    @classmethod
    def emergency_patterns(cls, script_dir) -> list[str]:
        return ["tailscaled"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        pids = proc.find_pids("tailscaled")
        return pids[0] if pids else None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(
                "auth_key",
                "param.ts_auth_key",
                required=True,
                secret=True,
                env_var="VPN_TS_AUTH_KEY",
                target="auth",
            ),
            ConfigParam(
                "login_server",
                "param.ts_login_server",
                required=False,
                env_var="VPN_TS_LOGIN_SERVER",
                target="auth",
            ),
            ConfigParam(
                "exit_node",
                "param.ts_exit_node",
                required=False,
                target="extra",
                prompt=False,
            ),
        ]

    @property
    def process_name(self) -> str:
        return "tailscaled"

    @property
    def display_name(self) -> str:
        return "Tailscale"

    def connect(self) -> VPNResult:
        auth_key = self.cfg.auth.get("auth_key", "")
        if not auth_key:
            ui.fail(t("vpn.ts.auth_required"))
            self.log.log("ERROR", "Tailscale auth key not set")
            return VPNResult(ok=False, detail="auth key missing")

        login_server = self.cfg.auth.get("login_server", "")
        exit_node = self.cfg.extra.get("exit_node", "")

        # Snapshot interfaces before connect (for auto-detection)
        ifaces_before = set(self.net.interfaces().keys())

        # Build tailscale up command
        cmd = ["tailscale", "up", "--reset", f"--auth-key={auth_key}"]
        if login_server:
            cmd.append(f"--login-server={login_server}")
        if exit_node:
            cmd.append(f"--exit-node={exit_node}")
        cmd.append("--accept-routes")

        self.log.log("INFO", f"Launch: {' '.join(cmd[:3])} --auth-key=*** ...")
        result = proc.run(cmd, sudo=True)

        if result.returncode != 0:
            ui.fail(t("vpn.ts.setup_failed", rc=result.returncode))
            self.log.log(
                "ERROR", f"tailscale up failed (exit code {result.returncode})"
            )
            details: list[tuple[str, str]] = []
            stderr = (result.stderr or "").strip()
            if stderr:
                details.append(("", stderr.splitlines()[-1]))
                self.log.log("ERROR", f"tailscale stderr: {stderr}")
            details.append(("", t("vpn.ts.log_hint")))
            ui.error_tree(details)
            return VPNResult(ok=False)

        # Detect interface
        interface = self.cfg.interface
        detected_iface = None

        if interface:
            # Explicit interface - wait for it
            if not proc.wait_for(
                f"Tailscale ({interface})",
                lambda: self.net.check_interface(interface),
                cfg.timeouts.tailscale_iface,
                self.log,
            ):
                # Fallback: check tailscale status
                detected_iface = self._detect_iface_from_status()
                if not detected_iface:
                    ui.fail(
                        t("vpn.ts.not_connected", timeout=cfg.timeouts.tailscale_iface)
                    )
                    self.log.log(
                        "ERROR", f"Tailscale interface {interface} did not appear"
                    )
                    return VPNResult(ok=False)
            else:
                detected_iface = interface
        else:
            # Auto-detect new interface
            def _check_new_iface():
                nonlocal detected_iface
                ifaces_now = set(self.net.interfaces().keys())
                new_ifaces = list(ifaces_now - ifaces_before)
                ts_ifaces = [
                    i
                    for i in new_ifaces
                    if i.startswith("tailscale")
                    or i.startswith("utun")
                    or i.startswith("ts")
                ]
                if ts_ifaces:
                    detected_iface = sorted(ts_ifaces)[0]
                    return True
                return False

            if not proc.wait_for(
                "Tailscale",
                _check_new_iface,
                cfg.timeouts.tailscale_iface,
                self.log,
            ):
                # Fallback: check tailscale status --json
                detected_iface = self._detect_iface_from_status()
                if not detected_iface:
                    ui.fail(
                        t("vpn.ts.not_connected", timeout=cfg.timeouts.tailscale_iface)
                    )
                    self.log.log("ERROR", "Tailscale interface did not appear")
                    return VPNResult(ok=False)
            self.cfg.interface = detected_iface

        # Find tailscaled PID
        pid = None
        pids = proc.find_pids("tailscaled")
        if pids:
            pid = pids[0]
        self._pid = pid

        ui.ok(t("vpn.ts.connected", iface=detected_iface))
        self.log.log("INFO", f"Tailscale connected ({detected_iface})")
        self.log.log_lines(
            "INFO", f"ifconfig {detected_iface}:\n{self.net.iface_info(detected_iface)}"
        )

        self.add_routes()
        self.setup_dns()

        self.log.log("INFO", f"Routes after Tailscale:\n{self.net.route_table()}")

        return VPNResult(ok=True, pid=pid)

    def disconnect(self) -> None:
        """Override: use tailscale down instead of kill by PID."""
        self.log.log("INFO", "Disconnect: sudo tailscale down")
        proc.run(["tailscale", "down"], sudo=True)

    def _kill_by_pattern(self) -> None:
        proc.kill_pattern("tailscaled", sudo=True)

    def _detect_iface_from_status(self) -> str | None:
        """Fallback interface detection via tailscale status --json."""
        try:
            r = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0 and r.stdout:
                data = json.loads(r.stdout)
                iface = data.get("TUN", "") or data.get("TUNName", "")
                if iface:
                    self.log.log(
                        "INFO", f"Detected interface from tailscale status: {iface}"
                    )
                    return iface
        except Exception as e:
            self.log.log("WARN", f"tailscale status --json failed: {e}")
        return None
