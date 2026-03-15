"""OpenConnect (Fortinet protocol) connection with TUN gateway detection."""

from __future__ import annotations

import os
import platform
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger
from tv.net import NetManager
from tv.proc import IS_WINDOWS
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register


@dataclass
class OpenConnectInfo:
    """Connection info parsed from openconnect output."""

    address: str
    nameservers: list[str]
    search_domains: list[str]
    connected: bool = False


_RE_OC_ADDRESS = re.compile(r"Got address:\s*(\S+)")
_RE_OC_DNS = re.compile(r"Got DNS\s+(\S+)")
_RE_OC_DOMAIN = re.compile(r"Got search domain\s+(\S+)")
_RE_OC_CONNECTED = re.compile(r"Connected as\s+(\S+)")


def parse_openconnect_output(output: str) -> OpenConnectInfo | None:
    """Extract connection info from openconnect stdout/stderr output."""
    addr_m = _RE_OC_ADDRESS.search(output)
    conn_m = _RE_OC_CONNECTED.search(output)
    
    if not addr_m:
        return None
    
    return OpenConnectInfo(
        address=addr_m.group(1),
        nameservers=_RE_OC_DNS.findall(output),
        search_domains=_RE_OC_DOMAIN.findall(output),
        connected=bool(conn_m),
    )


def _read_log_tail(log_path: Path, max_bytes: int = 4096) -> str:
    """Read the tail of a log file (last max_bytes). Returns empty string on error."""
    try:
        size = log_path.stat().st_size
        with open(log_path, "r", errors="replace") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
            return f.read()
    except OSError:
        return ""


def _show_error(oc_proc, oc_log: Path, log: Logger, label: str = "tun") -> None:
    """Display OpenConnect error details to user and log."""
    ui.fail(t("vpn.openconnect.not_connected", timeout=cfg.timeouts.fortivpn_ppp))
    log.log("ERROR", f"OpenConnect did not start within {cfg.timeouts.fortivpn_ppp}s")

    pid = oc_proc.pid
    if proc.is_alive(pid):
        details = [("", t("vpn.openconnect.alive_no_iface", pid=pid, label=label))]
        log.log("WARN", f"OpenConnect PID={pid} alive but {label} not found")
    else:
        rc = oc_proc.poll()
        rc_display = rc if rc is not None else "?"
        details = [("", t("vpn.openconnect.exited", rc=rc_display))]
        log.log("ERROR", f"OpenConnect process exited with code {rc}")

    details.append(("", t("vpn.openconnect.log_hint", path=oc_log)))
    ui.error_tree(details)


@register("openconnect")
class OpenConnectPlugin(TunnelPlugin):
    """OpenConnect tunnel plugin with TUN interface and Fortinet protocol support."""

    binary = "openconnect"
    type_display_name = "OpenConnect (Fortinet)"
    process_names = ("openconnect",)

    @classmethod
    def emergency_patterns(cls, script_dir) -> list[str]:
        return ["openconnect.*--protocol=fortinet"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        host = tcfg.auth.get("host", "")
        pids = proc.find_pids(f"openconnect.*--protocol=fortinet.*{host}")
        return pids[0] if pids else None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(
                "host",
                "param.host",
                required=True,
                env_var="VPN_OC_HOST",
                target="auth",
            ),
            ConfigParam(
                "port",
                "param.port",
                default="443",
                env_var="VPN_OC_PORT",
                target="auth",
            ),
            ConfigParam(
                "login",
                "param.login",
                required=True,
                env_var="VPN_OC_LOGIN",
                target="auth",
            ),
            ConfigParam(
                "pass",
                "param.password",
                required=True,
                secret=True,
                env_var="VPN_OC_PASS",
                target="auth",
            ),
            ConfigParam(
                "protocol",
                "param.protocol",
                default="fortinet",
                env_var="VPN_OC_PROTOCOL",
                target="auth",
                prompt=False,
            ),
            ConfigParam(
                "cert_mode",
                "param.cert_mode",
                default="pin",
                env_var="VPN_CERT_MODE",
                target="auth",
            ),
            ConfigParam(
                "servercert",
                "param.cert_sha256",
                env_var="VPN_SERVERCERT",
                target="auth",
            ),
        ]

    @property
    def process_name(self) -> str:
        return "openconnect"

    @property
    def display_name(self) -> str:
        return "OpenConnect"

    def _apply_discovered_dns(self, log_path: Path) -> None:
        """Parse OpenConnect log for DNS info and merge into self.cfg.dns.

        Config-first: manual nameservers take priority, discovery is fallback.
        Domains are always merged (config + discovered, deduplicated).
        """
        content = _read_log_tail(log_path)
        info = parse_openconnect_output(content)
        if not info:
            self.log.log("DEBUG", "DNS auto-discovery: no 'Got address' in log")
            return

        self.log.log(
            "INFO",
            f"DNS auto-discovery: ns={info.nameservers}, domains={info.search_domains}",
        )

        # Nameservers: fill only if user didn't set manually
        if not self.cfg.dns.get("nameservers") and info.nameservers:
            self.cfg.dns["nameservers"] = info.nameservers
            self.log.log("INFO", f"DNS nameservers from discovery: {info.nameservers}")

        # Domains: merge config + discovered, deduplicate, preserve order
        existing = self.cfg.dns.get("domains", [])
        merged = list(existing)
        for domain in info.search_domains:
            if domain not in merged:
                merged.append(domain)
        if merged != existing:
            self.cfg.dns["domains"] = merged
            self.log.log("INFO", f"DNS domains after merge: {merged}")

    def connect(self) -> VPNResult:
        if IS_WINDOWS:
            ui.warn(t("vpn.openconnect.unsupported_windows"))
            self.log.log("WARN", "openconnect is not available on Windows")
            return VPNResult(ok=False, detail="unsupported on Windows")

        auth = self.cfg.auth
        host = auth.get("host", "")
        port = auth.get("port", "443")
        login = auth.get("login", "")
        password = auth.get("pass", "")
        protocol = auth.get("protocol", "fortinet")
        cert_mode = auth.get("cert_mode", "pin")
        servercert = auth.get("servercert", "")

        log_path = self._default_log_path()

        self.log.log("INFO", f"Host: {host}:{port}  Login: {login}  Protocol: {protocol}")
        if servercert:
            self.log.log("INFO", f"Cert: {servercert[:24]}...")

        # Snapshot interfaces BEFORE connect (for TUN detection)
        ifaces_before = set(self.net.interfaces().keys())

        has_custom_routes = bool(
            self.cfg.routes.get("hosts") or self.cfg.routes.get("networks")
        )
        has_custom_dns = bool(
            self.cfg.dns.get("nameservers") and self.cfg.dns.get("domains")
        )
        managed = has_custom_routes or has_custom_dns

        # Build CLI args
        cmd = [
            "openconnect",
            f"{host}:{port}",
            "--protocol=" + protocol,
            "-u", login,
            "--passwd-on-stdin",
        ]

        # Certificate handling
        if cert_mode == "pin" and servercert:
            cmd.append(f"--servercert={servercert}")
        elif cert_mode == "system":
            # Use system CA store, no additional args
            pass

        # Managed mode: disable default routing
        if managed:
            cmd += ["--no-default-route"]
            self.log.log("INFO", "Mode: managed (--no-default-route)")
        else:
            self.log.log("INFO", "Mode: native (routing from openconnect)")

        # Launch in background with stdin pipe for password
        self.log.log("INFO", f"Launch: sudo {' '.join(cmd)}")
        
        # Manually create process with stdin=PIPE to send password
        sudo_cmd = ["sudo"] + cmd if not IS_WINDOWS else cmd
        log_file = open(str(log_path), "w")
        
        try:
            oc_proc = subprocess.Popen(
                sudo_cmd,
                stdin=subprocess.PIPE,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
            )
            # Write password immediately to avoid race condition
            if oc_proc.stdin:
                oc_proc.stdin.write(password + "\n")
                oc_proc.stdin.flush()
                oc_proc.stdin.close()
        except Exception as e:
            self.log.log("ERROR", f"Failed to launch openconnect: {e}")
            log_file.close()
            return VPNResult(ok=False, detail=str(e))
        
        oc_pid = oc_proc.pid
        self._pid = oc_pid
        self.log.log("INFO", f"OpenConnect PID={oc_pid}")

        # Wait for NEW tun/utun interface (snapshot diff)
        detected_iface = None
        is_macos = platform.system() == "Darwin"
        tun_prefix = "utun" if is_macos else "tun"

        def _check_new_tun():
            nonlocal detected_iface
            ifaces_now = set(self.net.interfaces().keys())
            new_tun = [i for i in (ifaces_now - ifaces_before) if i.startswith(tun_prefix)]
            if new_tun:
                detected_iface = sorted(new_tun)[0]
                return True
            return False

        if not proc.wait_for(
            f"OpenConnect ({self.cfg.name} {tun_prefix})",
            _check_new_tun,
            cfg.timeouts.fortivpn_ppp,
            self.log,
        ):
            _show_error(oc_proc, log_path, self.log, label=f"{tun_prefix} interface")
            return VPNResult(ok=False, pid=oc_pid)

        tun_iface = detected_iface
        if not self.cfg.interface:
            self.cfg.interface = tun_iface

        # --- Connected ---
        ui.ok(t("vpn.openconnect.connected", iface=tun_iface))
        self.log.log("INFO", f"OpenConnect connected ({tun_iface})")
        self.log.log_lines(
            "INFO", f"ifconfig {tun_iface}:\n{self.net.iface_info(tun_iface)}"
        )

        # Native mode: openconnect handles routes/DNS
        if not managed:
            self.log.log(
                "INFO", f"Routes after OpenConnect (native):\n{self.net.route_table()}"
            )
            return VPNResult(ok=True, pid=oc_pid)

        # Managed mode: DNS auto-discovery (before routes)
        self._apply_discovered_dns(log_path)

        # Routes via TUN interface (no gateway IP needed for TUN)
        self.add_routes()

        # Background ping to warm up
        dns_servers = self.cfg.dns.get("nameservers", [])
        if dns_servers:
            warmup = cfg.timeouts.ping_warmup
            system = platform.system()
            if system == "Windows":
                ping_cmd = ["ping", "-n", "2", "-w", str(warmup * 1000), dns_servers[0]]
            elif system == "Darwin":
                ping_cmd = ["ping", "-c", "2", "-t", str(warmup), dns_servers[0]]
            else:
                ping_cmd = ["ping", "-c", "2", "-W", str(warmup), dns_servers[0]]
            proc.run_background(ping_cmd)
            self.log.log("INFO", f"Background ping {dns_servers[0]} started")

        # DNS resolver
        dns_domains = self.cfg.dns.get("domains", [])
        if dns_domains and dns_servers:
            dns_iface = self.cfg.interface or tun_iface
            results = self.net.setup_dns_resolver(dns_domains, dns_servers, dns_iface)
            for domain, ok in results.items():
                self.log.log(
                    "INFO" if ok else "WARN",
                    f"Resolver for {domain} {'created' if ok else 'FAIL'}",
                )

        # Route snapshot
        self.log.log("INFO", f"Routes after OpenConnect:\n{self.net.route_table()}")

        return VPNResult(ok=True, pid=oc_pid)

    def _kill_by_pattern(self) -> None:
        host = self.cfg.auth.get("host", "")
        protocol = self.cfg.auth.get("protocol", "fortinet")
        proc.kill_pattern(f"openconnect.*--protocol={protocol}.*{host}", sudo=True)

    def disconnect(self) -> None:
        """Kill OpenConnect process with graceful SIGINT first."""
        # Try graceful shutdown with SIGINT first (better for TUN cleanup)
        if self._pid and proc.is_alive(self._pid):
            self.log.log("INFO", f"Sending SIGINT to OpenConnect PID={self._pid}")
            try:
                os.kill(self._pid, signal.SIGINT)
            except (OSError, ProcessLookupError):
                pass
            
            # Wait for graceful shutdown (5 seconds)
            for _ in range(10):
                if not proc.is_alive(self._pid):
                    self.log.log("INFO", "OpenConnect gracefully stopped")
                    return
                time.sleep(0.5)
            
            # Fall back to SIGTERM/SIGKILL if still alive
            self.log.log("WARN", "OpenConnect didn't respond to SIGINT, using SIGTERM")
            if not self._kill_by_pid():
                self._kill_by_pattern()
        else:
            self._kill_by_pattern()
