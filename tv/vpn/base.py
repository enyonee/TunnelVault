"""VPN connection result, tunnel config, plugin base class, and config schema."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger
from tv.net import NetManager


def _cidr_version(cidr: str) -> Optional[int]:
    """Безопасно определить version IP-network. None если невалидно.

    M8 митигация: try/except ValueError - не падаем на плохом конфиге,
    логирование и skip (то же поведение что add_net_route возвращает False)."""
    try:
        return ipaddress.ip_network(cidr, strict=False).version
    except ValueError:
        return None


def _ip_version(ip: str) -> Optional[int]:
    """Определить version IP-адреса. None если невалидно."""
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


@dataclass
class VPNResult:
    ok: bool = False
    pid: Optional[int] = None
    detail: str = ""


@dataclass
class ConfigParam:
    """Declarative description of a single config parameter for a plugin."""

    key: str  # key in TunnelConfig.auth / .config_file / .extra
    label: str  # i18n key for UI label (e.g. "param.host")
    required: bool = False
    secret: bool = False
    default: str = ""
    env_var: str = ""  # e.g. "VPN_FORTI_HOST"
    target: str = "auth"  # "auth" | "config_file" | "extra"
    prompt: bool = True  # False = resolve from TOML/ENV/saved only, never wizard


@dataclass
class TunnelConfig:
    """Declarative description of a single tunnel."""

    name: str = ""
    type: str = ""
    order: int = 0
    enabled: bool = True
    config_file: str = ""
    log: str = ""
    interface: str = ""
    routes: dict = field(default_factory=dict)
    dns: dict = field(default_factory=dict)
    checks: dict = field(default_factory=dict)
    auth: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)
    _auto_config_file: bool = False


class TunnelPlugin(ABC):
    """Base class for all tunnel plugins.

    Each VPN type implements connect() and the process_name property.
    Routes, DNS, disconnect get sensible defaults that can be overridden.
    """

    # Executable binary name (e.g. "openvpn", "sing-box", "openfortivpn").
    # Override in subclasses. Used by check_binary() to verify the package is installed.
    binary: str = ""

    # Human-readable name for the tunnel TYPE (used in proto line, no instance needed).
    # Override in subclasses. Falls back to registry key if empty.
    type_display_name: str = ""

    # Process names for emergency cleanup (without plugin instance).
    # Override in subclasses. Used by disconnect.run() to kill lingering processes.
    process_names: tuple[str, ...] = ()

    # Regex patterns for kill_pattern() during emergency cleanup.
    # Override in subclasses that need pattern-based kill (e.g. to avoid killing Tunnelblick).
    kill_patterns: tuple[str, ...] = ()

    # Command to get version. Override in subclasses if different.
    # Default: [binary, "--version"]. Set to None to skip.
    version_cmd: tuple[str, ...] | None = None

    @classmethod
    def get_version(cls) -> str:
        """Get version string from binary. Returns empty string on failure."""
        if not cls.binary or not shutil.which(cls.binary):
            return ""
        cmd = cls.version_cmd or (cls.binary, "--version")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            out = (r.stdout or r.stderr or "").strip()
            return out.split("\n")[0] if out else ""
        except Exception:
            return ""

    def __init__(
        self,
        tcfg: TunnelConfig,
        net: NetManager,
        log: Logger,
        script_dir: Path,
    ) -> None:
        self.cfg = tcfg
        self.net = net
        self.log = log
        self.script_dir = script_dir
        self._pid: Optional[int] = None

    @classmethod
    def check_binary(cls) -> bool:
        """Check if the plugin's binary is available on PATH."""
        return bool(cls.binary and shutil.which(cls.binary))

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        """Declare config params this plugin needs. Override in subclasses."""
        return []

    @classmethod
    def post_resolve_params(
        cls,
        tcfg: TunnelConfig,
        *,
        quiet: bool = False,
    ) -> None:
        """Hook called after config params resolved. Override for post-processing."""

    @classmethod
    def discover_pid(cls, tcfg: TunnelConfig, script_dir: Path) -> Optional[int]:
        """Best-effort PID discovery without engine context.

        Used by run_plugins() to find processes from a previous run.
        Override in subclasses with type-specific pgrep patterns.
        """
        return None

    @classmethod
    def emergency_patterns(cls, script_dir: Path) -> list[str]:
        """Patterns for emergency process kill (no tunnel configs available).

        Returns patterns specific to this script_dir so only processes
        started by THIS tunnelvault instance are killed.
        Override in subclasses. Falls back to kill_patterns.
        """
        return cls.kill_patterns

    def _check_config_file(self, i18n_key: str) -> Optional[VPNResult]:
        """Check config_file exists. Returns VPNResult(ok=False) if missing, None if ok."""
        config_path = self.script_dir / self.cfg.config_file
        if not config_path.exists():
            msg = t(i18n_key, path=config_path)
            ui.fail(msg)
            self.log.log("ERROR", f"Config file not found: {config_path}")
            return VPNResult(ok=False, detail="config not found")
        return None

    @abstractmethod
    def connect(self) -> VPNResult:
        """Establish the tunnel. Return VPNResult."""

    @property
    @abstractmethod
    def process_name(self) -> str:
        """Main process name (e.g. 'openvpn', 'openfortivpn', 'sing-box')."""

    @property
    def display_name(self) -> str:
        """Human-readable name for UI. Override for custom display."""
        return self.cfg.name or self.cfg.type

    def _default_log_path(self) -> Path:
        """Per-instance log path (uses cfg.log or generates from name)."""
        if self.cfg.log:
            return Path(self.cfg.log)
        name = self.cfg.name or self.cfg.type
        log_dir = Path(cfg.paths.log_dir)
        if not log_dir.is_absolute():
            log_dir = self.script_dir / log_dir
        return log_dir / f"{self.cfg.type}-{name}.log"

    def _kill_by_pid(self) -> bool:
        """Kill process by PID with timeout. Returns True if killed."""
        if not self._pid or not proc.is_alive(self._pid):
            return False
        proc.kill_by_pid(self._pid, sudo=True)
        steps = int(cfg.timeouts.pid_kill / cfg.timeouts.pid_kill_interval)
        for _ in range(steps):
            if not proc.is_alive(self._pid):
                return True
            time.sleep(cfg.timeouts.pid_kill_interval)
        self.log.log(
            "WARN",
            f"{self.process_name} PID={self._pid} did not exit within "
            f"{cfg.timeouts.pid_kill}s, pattern fallback",
        )
        return False

    def _kill_by_pattern(self) -> None:
        """Per-instance pattern kill. Override in subclasses."""

    def disconnect(self) -> None:
        """Kill by PID, fallback to per-instance pattern."""
        if not self._kill_by_pid():
            self._kill_by_pattern()

    def add_routes(self, gateway: Optional[str] = None) -> None:
        """Add host and network routes from cfg.routes.

        Dispatch IPv4/IPv6 через ipaddress.version (H1). Невалидный CIDR/IP -
        WARN + skip (M8)."""
        hosts = self.cfg.routes.get("hosts", [])
        networks = self.cfg.routes.get("networks", [])
        iface = self.cfg.interface

        for host in hosts:
            v = _ip_version(host)
            if v is None:
                self.log.log("WARN", f"invalid host (skip): {host!r}")
                continue
            if iface:
                if v == 6:
                    ok = self.net.add_iface_route6(host, iface, host=True)
                else:
                    ok = self.net.add_iface_route(host, iface, host=True)
            elif gateway:
                if v == 6:
                    ok = self.net.add_host_route6(host, gateway)
                else:
                    ok = self.net.add_host_route(host, gateway)
            else:
                continue
            self.log.log(
                "INFO" if ok else "WARN",
                f"route add {host} {'OK' if ok else 'FAIL'}",
            )

        for network in networks:
            v = _cidr_version(network)
            if v is None:
                self.log.log("WARN", f"invalid network (skip): {network!r}")
                continue
            if iface:
                if v == 6:
                    ok = self.net.add_iface_route6(network, iface, host=False)
                else:
                    ok = self.net.add_iface_route(network, iface, host=False)
            elif gateway:
                if v == 6:
                    ok = self.net.add_net_route6(network, gateway)
                else:
                    ok = self.net.add_net_route(network, gateway)
            else:
                continue
            self.log.log(
                "INFO" if ok else "WARN",
                f"route add {network} {'OK' if ok else 'FAIL'}",
            )

    def setup_dns(self) -> None:
        """Set up DNS resolver from cfg.dns."""
        nameservers = self.cfg.dns.get("nameservers", [])
        domains = self.cfg.dns.get("domains", [])
        if nameservers and domains:
            results = self.net.setup_dns_resolver(
                domains,
                nameservers,
                self.cfg.interface,
            )
            for domain, ok in results.items():
                self.log.log(
                    "INFO" if ok else "WARN",
                    f"Resolver for {domain} {'created' if ok else 'FAIL'}",
                )

    def cleanup_dns(self) -> None:
        """Remove DNS resolver entries."""
        domains = self.cfg.dns.get("domains", [])
        if domains:
            self.net.cleanup_dns_resolver(domains, self.cfg.interface)

    def delete_routes(self) -> None:
        """Remove routes added by add_routes().

        Dispatch IPv4/IPv6 (H1): иначе IPv6 маршруты не удаляются при disconnect -
        утечка трафика. Невалидные CIDR/IP молча skip (что добавлено невалидным,
        того и так нет в routing table)."""
        for host in self.cfg.routes.get("hosts", []):
            v = _ip_version(host)
            if v == 6:
                self.net.delete_host_route6(host)
            elif v == 4:
                self.net.delete_host_route(host)
            # v is None - skip
        for network in self.cfg.routes.get("networks", []):
            v = _cidr_version(network)
            if v == 6:
                self.net.delete_net_route6(network)
            elif v == 4:
                self.net.delete_net_route(network)
