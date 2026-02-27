"""Centralized application config with sensible defaults.

All hardcoded constants live here. Override via [app] section in defaults.toml.
Singleton ``cfg`` is created at import time with defaults. ``load()`` mutates
the existing object so every module that imported ``cfg`` sees updates.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, fields


@dataclass
class Timeouts:
    pid_kill: float = 2.0
    pid_kill_interval: float = 0.2
    process: int = 30
    net_command: int = 10
    openvpn_init: int = 30
    fortivpn_ppp: int = 20
    singbox_iface: int = 15
    fortivpn_gw_poll: float = 0.5
    fortivpn_gw_attempts: int = 10
    check_subprocess: int = 15
    check_port: int = 5
    check_ping: int = 3
    check_dns: int = 10
    check_http: int = 5
    check_external_ip: int = 5
    cert_generation: int = 15
    cert_openssl: int = 5
    cleanup_sleep: float = 1.0
    ping_warmup: int = 2
    ps_aux: int = 10
    keepalive_interval: int = 30
    keepalive_reconnect_pause: float = 2.0


def _default_temp_dir() -> str:
    import platform
    if platform.system() == "Windows":
        import tempfile
        return tempfile.gettempdir()
    return "/tmp"


@dataclass
class Paths:
    log_dir: str = "logs"
    temp_dir: str = ""
    settings_file: str = ".vpn-settings.json"
    defaults_file: str = "defaults.toml"
    main_log: str = "tunnelvault.log"
    resolver_dir: str = "/etc/resolver"

    def __post_init__(self):
        if not self.temp_dir:
            self.temp_dir = _default_temp_dir()


@dataclass
class Defaults:
    fortivpn_port: str = "44333"
    fortivpn_cert_mode: str = "auto"
    openvpn_config: str = "client.ovpn"
    singbox_config: str = "singbox.json"
    singbox_interface: str = "utun99"
    network_service: str = "Wi-Fi"


@dataclass
class Display:
    route_table_lines: int = 30
    box_width: int = 60


@dataclass
class Logging:
    level: str = "DEBUG"
    truncate_on_start: bool = True


@dataclass
class AppConfig:
    timeouts: Timeouts
    paths: Paths
    defaults: Defaults
    display: Display
    logging: Logging
    locale: str = ""


def _make_default() -> AppConfig:
    return AppConfig(
        timeouts=Timeouts(),
        paths=Paths(),
        defaults=Defaults(),
        display=Display(),
        logging=Logging(),
    )


cfg = _make_default()

_SECTION_MAP = {
    "timeouts": "timeouts",
    "paths": "paths",
    "defaults": "defaults",
    "display": "display",
    "logging": "logging",
}


def load(app_dict: dict) -> None:
    """Mutate ``cfg`` from TOML ``[app]`` section. Warns on unknown keys."""
    if not app_dict:
        return
    # Top-level scalar keys (not nested sections)
    _TOP_LEVEL = {"locale"}
    for tk in _TOP_LEVEL:
        if tk in app_dict:
            setattr(cfg, tk, app_dict[tk])

    known_sections = set(_SECTION_MAP)
    for k in app_dict:
        if k in _TOP_LEVEL:
            continue
        if k not in known_sections and isinstance(app_dict[k], dict):
            warnings.warn(f"Unknown [app] section: '{k}'", stacklevel=2)
    for section_key, attr_name in _SECTION_MAP.items():
        sub = app_dict.get(section_key)
        if not sub or not isinstance(sub, dict):
            continue
        group = getattr(cfg, attr_name)
        valid_names = {f.name for f in fields(group)}
        for k, v in sub.items():
            if k in valid_names:
                setattr(group, k, v)
            else:
                warnings.warn(
                    f"Unknown key in [app.{section_key}]: '{k}'", stacklevel=2,
                )


def reset() -> None:
    """Restore ``cfg`` to defaults (preserves object identity)."""
    fresh = _make_default()
    for f in fields(cfg):
        setattr(cfg, f.name, getattr(fresh, f.name))
