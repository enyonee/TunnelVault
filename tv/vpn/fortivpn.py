"""FortiVPN (openfortivpn) connection with PPP gateway detection."""

from __future__ import annotations

import atexit
import os
import platform
import re
import time
from dataclasses import dataclass
from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger
from tv.net import NetManager
from tv.proc import IS_WINDOWS
from tv.vpn.base import ConfigParam, TunnelConfig, TunnelPlugin, VPNResult
from tv.vpn.cert import generate_cert_sha256
from tv.vpn.registry import register


@dataclass
class FortiDNSInfo:
    """DNS info parsed from openfortivpn log."""

    nameservers: list[str]
    suffixes: list[str]


_RE_FORTI_DNS = re.compile(r"Got addresses:.*?ns \[([^\]]*)\].*?ns_suffix \[([^\]]*)\]")


def parse_forti_dns(log_content: str) -> FortiDNSInfo | None:
    """Extract nameservers and domain suffixes from openfortivpn log output."""
    m = _RE_FORTI_DNS.search(log_content)
    if not m:
        return None
    ns_raw, suffix_raw = m.group(1).strip(), m.group(2).strip()
    nameservers = [s.strip() for s in ns_raw.split(",") if s.strip()] if ns_raw else []
    suffixes = (
        [s.strip() for s in suffix_raw.split(";") if s.strip()] if suffix_raw else []
    )
    return FortiDNSInfo(nameservers=nameservers, suffixes=suffixes)


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


def _safe_unlink(path: str) -> None:
    """Remove file if it exists. Silently ignore errors (atexit safety net)."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _detect_ppp_gateway(net: NetManager, interface: str = "ppp0") -> str:
    """Detect PPP peer gateway from interface via system call."""
    for _ in range(cfg.timeouts.fortivpn_gw_attempts):
        peer = net.ppp_peer(interface)
        if peer:
            return peer
        time.sleep(cfg.timeouts.fortivpn_gw_poll)
    return ""


def _show_error(forti_proc, forti_log: Path, log: Logger, label: str = "ppp") -> None:
    """Display FortiVPN error details to user and log."""
    ui.fail(t("vpn.forti.not_connected", timeout=cfg.timeouts.fortivpn_ppp))
    log.log("ERROR", f"FortiVPN did not start within {cfg.timeouts.fortivpn_ppp}s")

    pid = forti_proc.pid
    if proc.is_alive(pid):
        details = [("", t("vpn.forti.alive_no_iface", pid=pid, label=label))]
        log.log("WARN", f"FortiVPN PID={pid} alive but {label} not found")
    else:
        rc = forti_proc.poll()
        rc_display = rc if rc is not None else "?"
        details = [("", t("vpn.forti.exited", rc=rc_display))]
        log.log("ERROR", f"FortiVPN process exited with code {rc}")

    details.append(("", t("vpn.forti.log_hint", path=forti_log)))
    ui.error_tree(details)


@register("fortivpn")
class FortiVPNPlugin(TunnelPlugin):
    """FortiVPN tunnel plugin with PPP gateway detection."""

    binary = "openfortivpn"
    type_display_name = "FortiVPN"
    process_names = ("openfortivpn",)
    kill_patterns = (f"openfortivpn -c {cfg.paths.temp_dir}/forti_",)

    @classmethod
    def get_version(cls) -> str:
        raw = super().get_version()
        return f"openfortivpn {raw}" if raw else ""

    @classmethod
    def emergency_patterns(cls, script_dir) -> list[str]:
        return [f"openfortivpn -c {cfg.paths.temp_dir}/forti_"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        conf_path = f"{cfg.paths.temp_dir}/forti_{tcfg.name}.conf"
        pids = proc.find_pids(f"openfortivpn -c {conf_path}")
        return pids[0] if pids else None

    @classmethod
    def post_resolve_params(
        cls,
        tcfg: TunnelConfig,
        *,
        quiet: bool = False,
    ) -> None:
        """Auto-generate FortiVPN trusted cert if cert_mode=auto."""
        cert_mode = tcfg.auth.get("cert_mode", "")
        if cert_mode != "auto":
            return
        if tcfg.auth.get("trusted_cert"):
            return

        env_val = os.environ.get("VPN_TRUSTED_CERT", "")
        if env_val:
            if not quiet:
                ui.param_found("param.cert_sha256", env_val, "$VPN_TRUSTED_CERT", False)
            tcfg.auth["trusted_cert"] = env_val
            return

        host = tcfg.auth.get("host", "")
        port = tcfg.auth.get("port", cfg.defaults.fortivpn_port)
        if not host:
            return

        if not quiet:
            print(f"  🔑 {t('config.cert_generating', host=host, port=port)}")
        cert = generate_cert_sha256(host, port)
        if cert:
            if not quiet:
                print(
                    f"  {ui.GREEN}✅{ui.NC} {t('config.cert_generated', cert=cert[:24])}"
                )
            tcfg.auth["trusted_cert"] = cert
        else:
            ui.warn(t("config.cert_unreachable", host=host, port=port))
            ui.info(
                f"  {ui.DIM}{t('config.cert_hint', env='VPN_TRUSTED_CERT', file=cfg.paths.defaults_file)}{ui.NC}"
            )

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(
                "host",
                "param.host",
                required=True,
                env_var="VPN_FORTI_HOST",
                target="auth",
            ),
            ConfigParam(
                "port",
                "param.port",
                default=cfg.defaults.fortivpn_port,
                env_var="VPN_FORTI_PORT",
                target="auth",
            ),
            ConfigParam(
                "login",
                "param.login",
                required=True,
                env_var="VPN_FORTI_LOGIN",
                target="auth",
            ),
            ConfigParam(
                "pass",
                "param.password",
                required=True,
                secret=True,
                env_var="VPN_FORTI_PASS",
                target="auth",
            ),
            ConfigParam(
                "cert_mode",
                "param.cert_mode",
                default=cfg.defaults.fortivpn_cert_mode,
                env_var="VPN_CERT_MODE",
                target="auth",
            ),
            ConfigParam(
                "trusted_cert",
                "param.cert_sha256",
                env_var="VPN_TRUSTED_CERT",
                target="auth",
            ),
            ConfigParam(
                "fallback_gateway",
                "param.fallback_gw",
                env_var="VPN_FORTI_FALLBACK_GW",
                target="extra",
                prompt=False,
            ),
        ]

    @property
    def process_name(self) -> str:
        return "openfortivpn"

    @property
    def display_name(self) -> str:
        return "FortiVPN"

    def _apply_discovered_dns(self, log_path: Path) -> None:
        """Parse FortiVPN log for DNS info and merge into self.cfg.dns.

        Config-first: manual nameservers take priority, discovery is fallback.
        Domains are always merged (config + discovered, deduplicated).
        """
        content = _read_log_tail(log_path)
        info = parse_forti_dns(content)
        if not info:
            self.log.log("DEBUG", "DNS auto-discovery: no 'Got addresses' in log")
            return

        self.log.log(
            "INFO",
            f"DNS auto-discovery: ns={info.nameservers}, suffixes={info.suffixes}",
        )

        # Nameservers: fill only if user didn't set manually
        if not self.cfg.dns.get("nameservers") and info.nameservers:
            self.cfg.dns["nameservers"] = info.nameservers
            self.log.log("INFO", f"DNS nameservers from discovery: {info.nameservers}")

        # Domains: merge config + discovered, deduplicate, preserve order
        existing = self.cfg.dns.get("domains", [])
        merged = list(existing)
        for suffix in info.suffixes:
            if suffix not in merged:
                merged.append(suffix)
        if merged != existing:
            self.cfg.dns["domains"] = merged
            self.log.log("INFO", f"DNS domains after merge: {merged}")

    def _add_dns_routes(self, ppp_iface: str) -> None:
        """Add host routes to each DNS nameserver through PPP interface.

        Prevents OpenVPN catch-all routes from intercepting DNS traffic.
        """
        self._dns_routes: list[str] = []
        nameservers = self.cfg.dns.get("nameservers", [])
        if not nameservers:
            return

        for ns in nameservers:
            ok = self.net.add_iface_route(ns, ppp_iface, host=True)
            self.log.log(
                "INFO" if ok else "WARN",
                f"DNS route {ns} -> {ppp_iface} {'OK' if ok else 'FAIL'}",
            )
            if ok:
                self._dns_routes.append(ns)

    def _cleanup_dns_routes(self) -> None:
        """Remove DNS server routes added by _add_dns_routes."""
        for ns in getattr(self, "_dns_routes", []):
            self.net.delete_host_route(ns)
        self._dns_routes = []

    def connect(self) -> VPNResult:
        if IS_WINDOWS:
            ui.warn(t("vpn.forti.unsupported_windows"))
            self.log.log("WARN", "openfortivpn is not available on Windows")
            return VPNResult(ok=False, detail="unsupported on Windows")

        auth = self.cfg.auth
        host = auth.get("host", "")
        port = auth.get("port", cfg.defaults.fortivpn_port)
        login = auth.get("login", "")
        password = auth.get("pass", "")
        trusted_cert = auth.get("trusted_cert", "")

        dns_servers = self.cfg.dns.get("nameservers", [])
        dns_domains = self.cfg.dns.get("domains", [])
        fallback_gw = self.cfg.extra.get("fallback_gateway", "")

        log_path = self._default_log_path()

        self.log.log("INFO", f"Host: {host}:{port}  Login: {login}")
        self.log.log("INFO", f"Cert: {trusted_cert[:24]}...")

        # Snapshot interfaces BEFORE connect (for ppp detection)
        ifaces_before = set(self.net.interfaces().keys())

        # Predictable config path (per tunnel name, not random)
        conf_path = f"{cfg.paths.temp_dir}/forti_{self.cfg.name}.conf"
        conf_fd = os.open(conf_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            conf_content = (
                f"host = {host}\n"
                f"port = {port}\n"
                f"username = {login}\n"
                f"password = {password}\n"
                f"trusted-cert = {trusted_cert}\n"
            )
            os.write(conf_fd, conf_content.encode())
        finally:
            os.close(conf_fd)
        self._conf_path = conf_path
        atexit.register(_safe_unlink, conf_path)

        has_custom_routes = bool(
            self.cfg.routes.get("hosts") or self.cfg.routes.get("networks")
        )
        has_custom_dns = bool(
            self.cfg.dns.get("nameservers") and self.cfg.dns.get("domains")
        )
        managed = has_custom_routes or has_custom_dns

        cmd = ["openfortivpn", "-c", conf_path]
        if managed:
            cmd += ["--no-routes", "--no-dns"]
            self.log.log("INFO", "Mode: managed (--no-routes --no-dns)")
        else:
            self.log.log("INFO", "Mode: native (routing from openfortivpn)")

        # Launch in background (log file created as current user)
        self.log.log("INFO", f"Launch: sudo {' '.join(cmd)}")
        forti_proc = proc.run_background(
            cmd,
            sudo=True,
            log_path=str(log_path),
        )
        forti_pid = forti_proc.pid
        self._pid = forti_pid
        self.log.log("INFO", f"FortiVPN PID={forti_pid}")

        # Wait for NEW ppp interface (snapshot diff, not hardcoded ppp0)
        detected_iface = None

        def _check_new_ppp():
            nonlocal detected_iface
            ifaces_now = set(self.net.interfaces().keys())
            new_ppp = [i for i in (ifaces_now - ifaces_before) if i.startswith("ppp")]
            if new_ppp:
                detected_iface = sorted(new_ppp)[0]
                return True
            return False

        if not proc.wait_for(
            f"FortiVPN ({self.cfg.name} ppp)",
            _check_new_ppp,
            cfg.timeouts.fortivpn_ppp,
            self.log,
        ):
            _show_error(forti_proc, log_path, self.log, label="ppp interface")
            return VPNResult(ok=False, pid=forti_pid)

        ppp_iface = detected_iface
        if not self.cfg.interface:
            self.cfg.interface = ppp_iface

        # --- Connected ---
        ui.ok(t("vpn.forti.connected", iface=ppp_iface))
        self.log.log("INFO", f"FortiVPN connected ({ppp_iface})")
        self.log.log_lines(
            "INFO", f"ifconfig {ppp_iface}:\n{self.net.iface_info(ppp_iface)}"
        )

        # Native mode: openfortivpn handles routes/DNS, just log PPP gateway
        if not managed:
            ppp_gw = _detect_ppp_gateway(self.net, interface=ppp_iface)
            if ppp_gw:
                print(f"  ↳ peer: {ui.YELLOW}{ppp_gw}{ui.NC}")
                self.log.log("INFO", f"PPP_GW={ppp_gw}")
            self.log.log(
                "INFO", f"Routes after FortiVPN (native):\n{self.net.route_table()}"
            )
            return VPNResult(ok=True, pid=forti_pid)

        # Managed mode: DNS auto-discovery (before routes)
        self._apply_discovered_dns(log_path)
        dns_servers = self.cfg.dns.get("nameservers", [])
        dns_domains = self.cfg.dns.get("domains", [])

        # PPP gateway for custom routes
        ppp_gw = _detect_ppp_gateway(self.net, interface=ppp_iface)
        if not ppp_gw:
            if fallback_gw:
                ui.warn(t("vpn.forti.no_gw_fallback", gw=fallback_gw))
                self.log.log("WARN", f"PPP_GW not found, fallback={fallback_gw}")
                ppp_gw = fallback_gw
            else:
                ui.warn(t("vpn.forti.no_gw"))
                self.log.log("WARN", "PPP_GW not found, no fallback set")
                return VPNResult(ok=True, pid=forti_pid)

        print(f"  ↳ peer: {ui.YELLOW}{ppp_gw}{ui.NC}")
        self.log.log("INFO", f"PPP_GW={ppp_gw}")

        # Routes via PPP gateway (networks + hosts from config/targets)
        self.add_routes(gateway=ppp_gw)

        # DNS server routes (prevent OpenVPN catch-all from intercepting)
        self._add_dns_routes(ppp_iface)

        # Background ping to warm up
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
        if dns_domains and dns_servers:
            dns_iface = self.cfg.interface or ppp_iface
            results = self.net.setup_dns_resolver(dns_domains, dns_servers, dns_iface)
            for domain, ok in results.items():
                self.log.log(
                    "INFO" if ok else "WARN",
                    f"Resolver for {domain} {'created' if ok else 'FAIL'}",
                )

        # Route snapshot
        self.log.log("INFO", f"Routes after FortiVPN:\n{self.net.route_table()}")

        return VPNResult(ok=True, pid=forti_pid)

    def _kill_by_pattern(self) -> None:
        conf_path = self._effective_conf_path()
        proc.kill_pattern(f"openfortivpn -c {conf_path}", sudo=True)

    def disconnect(self) -> None:
        """Kill FortiVPN + clean up DNS routes + temp config."""
        if not self._kill_by_pid():
            self._kill_by_pattern()
        self._cleanup_dns_routes()
        try:
            os.unlink(self._effective_conf_path())
        except OSError:
            pass

    def _effective_conf_path(self) -> str:
        return getattr(
            self, "_conf_path", f"{cfg.paths.temp_dir}/forti_{self.cfg.name}.conf"
        )
