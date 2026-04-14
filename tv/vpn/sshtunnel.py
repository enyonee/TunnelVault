"""SSH tunnel connection: SOCKS proxy (-D) or sshuttle mode."""

from __future__ import annotations

import shutil
import socket
import time
from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.vpn.base import ConfigParam, TunnelConfig, TunnelPlugin, VPNResult
from tv.vpn.registry import register


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is listening."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@register("sshtunnel")
class SSHTunnelPlugin(TunnelPlugin):
    """SSH tunnel plugin supporting SOCKS proxy and sshuttle modes."""

    binary = "ssh"
    type_display_name = "SSH Tunnel"
    process_names = ("ssh", "sshuttle")
    version_cmd = ("ssh", "-V")

    @classmethod
    def get_version(cls) -> str:
        """ssh -V prints to stderr."""
        if not cls.binary or not shutil.which(cls.binary):
            return ""
        import subprocess

        try:
            r = subprocess.run(
                cls.version_cmd, capture_output=True, text=True, timeout=5
            )
            out = (r.stderr or r.stdout or "").strip()
            return out.split("\n")[0] if out else ""
        except Exception:
            return ""

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(
                "host",
                "param.ssh_host",
                required=True,
                env_var="VPN_SSH_HOST",
                target="auth",
            ),
            ConfigParam(
                "mode",
                "param.ssh_mode",
                default=cfg.defaults.sshtunnel_mode,
                env_var="",
                target="extra",
            ),
            ConfigParam(
                "port",
                "param.ssh_port",
                default=cfg.defaults.sshtunnel_socks_port,
                env_var="VPN_SSH_PORT",
                target="auth",
                prompt=False,
            ),
            ConfigParam(
                "identity_file",
                "param.ssh_identity",
                env_var="",
                target="extra",
                prompt=False,
            ),
            ConfigParam(
                "socks_port",
                "param.ssh_socks_port",
                default=cfg.defaults.sshtunnel_socks_port,
                env_var="",
                target="extra",
                prompt=False,
            ),
            ConfigParam(
                "subnets",
                "param.ssh_subnets",
                env_var="",
                target="extra",
                prompt=False,
            ),
        ]

    @classmethod
    def emergency_patterns(cls, script_dir: Path) -> list[str]:
        return ["ssh -D", "sshuttle"]

    @classmethod
    def discover_pid(cls, tcfg: TunnelConfig, script_dir: Path) -> int | None:
        host = tcfg.auth.get("host", "")
        if not host:
            return None
        # Try SOCKS mode pattern first
        pids = proc.find_pids(f"ssh -D.*{host}")
        if pids:
            return pids[0]
        # Try sshuttle pattern
        pids = proc.find_pids(f"sshuttle.*{host}")
        if pids:
            return pids[0]
        return None

    @property
    def process_name(self) -> str:
        mode = self.cfg.extra.get("mode", "socks")
        return "sshuttle" if mode == "sshuttle" else "ssh"

    @property
    def display_name(self) -> str:
        mode = self.cfg.extra.get("mode", "socks")
        return f"SSH Tunnel ({mode})"

    def _get_mode(self) -> str:
        return self.cfg.extra.get("mode", "socks")

    def _get_host(self) -> str:
        return self.cfg.auth.get("host", "")

    def _get_ssh_port(self) -> str:
        return self.cfg.auth.get("port", "22")

    def _get_socks_port(self) -> int:
        return int(self.cfg.extra.get("socks_port", "1080"))

    def _get_identity_file(self) -> str:
        return self.cfg.extra.get("identity_file", "")

    def _get_subnets(self) -> list[str]:
        raw = self.cfg.extra.get("subnets", "")
        if not raw:
            return []
        return [s.strip() for s in raw.split(",") if s.strip()]

    def connect(self) -> VPNResult:
        mode = self._get_mode()
        host = self._get_host()

        if not host:
            ui.fail(t("vpn.ssh.setup_failed", detail="host not set"))
            self.log.log("ERROR", "SSH tunnel: host not configured")
            return VPNResult(ok=False, detail="host not set")

        if mode == "sshuttle":
            return self._connect_sshuttle(host)
        return self._connect_socks(host)

    def _connect_socks(self, host: str) -> VPNResult:
        """SOCKS proxy mode: ssh -D <port> -N."""
        socks_port = self._get_socks_port()
        ssh_port = self._get_ssh_port()
        identity = self._get_identity_file()

        cmd = [
            "ssh",
            "-D",
            str(socks_port),
            "-N",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ExitOnForwardFailure=yes",
        ]
        if identity:
            cmd.extend(["-i", identity])
        if ssh_port != "22":
            cmd.extend(["-p", ssh_port])
        cmd.append(host)

        self.log.log("INFO", f"Launch: {' '.join(cmd)}")

        ssh_proc = proc.run_background(cmd)
        pid = ssh_proc.pid
        self._pid = pid

        # Wait for SOCKS port to become available
        if not proc.wait_for(
            f"SSH SOCKS (:{socks_port})",
            lambda: _port_open("127.0.0.1", socks_port),
            cfg.timeouts.sshtunnel_connect,
            self.log,
            abort_fn=lambda: not proc.is_alive(pid),
        ):
            # Check if process died
            if not proc.is_alive(pid):
                ui.fail(t("vpn.ssh.setup_failed", detail=f"ssh exited (PID={pid})"))
                self.log.log("ERROR", f"ssh exited prematurely (PID={pid})")
            else:
                ui.fail(
                    t(
                        "vpn.ssh.not_connected",
                        timeout=cfg.timeouts.sshtunnel_connect,
                    )
                )
                self.log.log(
                    "ERROR",
                    f"SOCKS port {socks_port} did not open within "
                    f"{cfg.timeouts.sshtunnel_connect}s",
                )
            details: list[tuple[str, str]] = [
                ("", t("vpn.ssh.log_hint")),
            ]
            ui.error_tree(details)
            return VPNResult(ok=False)

        ui.ok(t("vpn.ssh.connected_socks", port=socks_port))
        self.log.log("INFO", f"SSH SOCKS connected (PID={pid}, port={socks_port})")

        return VPNResult(ok=True, pid=pid, detail=f"socks5://127.0.0.1:{socks_port}")

    def _connect_sshuttle(self, host: str) -> VPNResult:
        """sshuttle mode: route subnets through SSH."""
        if not shutil.which("sshuttle"):
            ui.fail(t("vpn.ssh.setup_failed", detail="sshuttle not installed"))
            self.log.log("ERROR", "sshuttle binary not found")
            return VPNResult(ok=False, detail="sshuttle not found")

        subnets = self._get_subnets()
        if not subnets:
            subnets = ["0/0"]

        ssh_port = self._get_ssh_port()
        identity = self._get_identity_file()

        cmd = ["sshuttle", "-r", host] + subnets + ["--dns"]

        # Build ssh sub-command if non-default port or identity
        ssh_args: list[str] = []
        if identity:
            ssh_args.extend(["-i", identity])
        if ssh_port != "22":
            ssh_args.extend(["-p", ssh_port])
        if ssh_args:
            cmd.extend(["-e", "ssh " + " ".join(ssh_args)])

        self.log.log("INFO", f"Launch: {' '.join(cmd)}")

        shuttle_proc = proc.run_background(cmd, sudo=True)
        pid = shuttle_proc.pid
        self._pid = pid

        # sshuttle takes a moment to set up iptables/pf rules.
        # Poll for process staying alive as success indicator.
        if not proc.wait_for(
            "sshuttle",
            lambda: proc.is_alive(pid),
            cfg.timeouts.sshtunnel_connect,
            self.log,
        ):
            ui.fail(t("vpn.ssh.setup_failed", detail="sshuttle did not start"))
            self.log.log("ERROR", "sshuttle process did not stay alive")
            return VPNResult(ok=False)

        # Give sshuttle a moment to establish the tunnel
        time.sleep(1)

        if not proc.is_alive(pid):
            ui.fail(t("vpn.ssh.setup_failed", detail=f"sshuttle exited (PID={pid})"))
            self.log.log("ERROR", f"sshuttle exited prematurely (PID={pid})")
            return VPNResult(ok=False)

        ui.ok(t("vpn.ssh.connected_sshuttle", host=host))
        self.log.log("INFO", f"sshuttle connected (PID={pid}, host={host})")

        return VPNResult(ok=True, pid=pid, detail=f"sshuttle via {host}")

    def disconnect(self) -> None:
        """Kill ssh/sshuttle process by PID."""
        if not self._kill_by_pid():
            self._kill_by_pattern()

    def _kill_by_pattern(self) -> None:
        host = self._get_host()
        mode = self._get_mode()
        if mode == "sshuttle" and host:
            proc.kill_pattern(f"sshuttle.*{host}", sudo=True)
        elif host:
            proc.kill_pattern(f"ssh -D.*{host}", sudo=True)
