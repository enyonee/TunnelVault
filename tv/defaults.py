"""Load and validate config.toml, parse tunnel configs."""

from __future__ import annotations

import copy
import platform
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        print("Python < 3.11 requires 'tomli': pip install tomli", file=sys.stderr)
        sys.exit(1)

from tv import ui
from tv.app_config import cfg
from tv.i18n import t
from tv.vpn.base import TunnelConfig


def load(script_dir: Path, *, setup: bool = False) -> dict:
    """Load config.toml with [tunnels.*] format.

    Requires at least one [tunnels.<name>] section.
    When *setup=True* and file is missing, copies from config.toml.example.
    """
    defaults_file = cfg.paths.defaults_file
    path = script_dir / defaults_file
    if not path.exists():
        if setup:
            example = script_dir / f"{defaults_file}.example"
            if example.exists():
                import shutil

                shutil.copy2(str(example), str(path))
                print(
                    f"  {ui.GREEN}📋{ui.NC} {t('defaults.created_from_example', file=defaults_file)}"
                )
            else:
                print(
                    f"  {ui.RED}❌ {t('defaults.not_found', file=defaults_file)}{ui.NC}"
                )
                print(f"  {ui.DIM}{t('defaults.expected_at', path=path)}{ui.NC}")
                sys.exit(1)
        else:
            print(f"  {ui.RED}❌ {t('defaults.not_found', file=defaults_file)}{ui.NC}")
            print(f"  {ui.DIM}{t('defaults.expected_at', path=path)}{ui.NC}")
            sys.exit(1)

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        print(
            f"  {ui.RED}❌ {t('defaults.parse_error', file=defaults_file, error=e)}{ui.NC}"
        )
        sys.exit(1)

    if "tunnels" not in data:
        print(f"  {ui.RED}❌ {t('defaults.no_tunnels', file=defaults_file)}{ui.NC}")
        print(f"  {ui.DIM}{t('defaults.format_hint')}{ui.NC}")
        sys.exit(1)

    # Load [app] section into centralized config
    from tv import app_config

    app_config.load(data.get("app", {}))
    app_config.load_reconnect(data.get("reconnect", {}))

    print(
        f"  {ui.GREEN}📋{ui.NC} {t('defaults.loaded')} {ui.DIM}({defaults_file}){ui.NC}"
    )
    return data


def parse_tunnels(defs: dict) -> list[TunnelConfig]:
    """Parse [tunnels.*] sections into TunnelConfig list.

    Returns list sorted by order, filtered by enabled=True.
    Order: parse -> log defaults -> config_file defaults -> singbox interfaces -> validate.
    """
    tunnels_section = defs.get("tunnels", {})
    if not tunnels_section:
        return []

    result = []
    for name, raw in tunnels_section.items():
        if not isinstance(raw, dict):
            continue

        tc = TunnelConfig(
            name=name,
            type=raw.get("type", ""),
            order=raw.get("order", 0),
            enabled=raw.get("enabled", True),
            config_file=raw.get("config_file", ""),
            log=raw.get("log", ""),
            interface=raw.get("interface", ""),
            routes=copy.deepcopy(raw.get("routes", {})),
            dns=copy.deepcopy(raw.get("dns", {})),
            checks=copy.deepcopy(raw.get("checks", {})),
            auth=copy.deepcopy(raw.get("auth", {})),
        )

        # Collect type-specific extra fields
        known_keys = {
            "type",
            "order",
            "enabled",
            "config_file",
            "log",
            "interface",
            "routes",
            "dns",
            "checks",
            "auth",
        }
        tc.extra = copy.deepcopy({k: v for k, v in raw.items() if k not in known_keys})

        if not tc.type:
            continue

        result.append(tc)

    result.sort(key=lambda t_: t_.order)
    enabled = [t_ for t_ in result if t_.enabled]

    # On macOS: auto-migrate fortivpn -> openconnect (TUN instead of PPP)
    # Must run before log path generation so log names reflect actual type
    _migrate_fortivpn_to_openconnect(enabled)

    # Auto-generate unique log paths for tunnels without explicit log
    for tc in enabled:
        if not tc.log:
            tc.log = f"{cfg.paths.log_dir}/{tc.type}-{tc.name}.log"

    # Resolve defaults early so validation catches collisions at startup
    _apply_config_defaults(enabled)
    _assign_singbox_interfaces(enabled)

    _validate_tunnels(enabled)
    return enabled


def _migrate_fortivpn_to_openconnect(tunnels: list[TunnelConfig]) -> None:
    """On macOS, transparently replace fortivpn with openconnect.

    openfortivpn uses PPP (pppd) which is deprecated on macOS and unstable
    after sleep/wake. openconnect with --protocol=fortinet uses TUN instead.

    Auth params are remapped: trusted_cert -> servercert (with sha256: prefix),
    protocol=fortinet is added. The user's config.toml stays unchanged.
    """
    if platform.system() != "Darwin":
        return

    for tc in tunnels:
        if tc.type != "fortivpn":
            continue

        tc.type = "openconnect"

        # Remap auth params
        auth = tc.auth
        auth.setdefault("protocol", "fortinet")

        # Drop fortivpn trusted_cert - incompatible format (DER hash vs SPKI pin).
        # Set cert_mode=auto so openconnect plugin generates correct pin-sha256.
        auth.pop("trusted_cert", "")
        if not auth.get("servercert"):
            auth.setdefault("cert_mode", "auto")

        # Remove fortivpn-specific params
        tc.extra.pop("fallback_gateway", None)

        ui.info(
            f"  {ui.DIM}{tc.name}: fortivpn -> openconnect (TUN instead of PPP){ui.NC}"
        )


_IFACE_RE = re.compile(r"^([a-zA-Z]+)(\d+)$")


def _parse_iface_name(name: str) -> tuple[str, int]:
    """Split interface name into prefix and numeric suffix: 'utun99' -> ('utun', 99)."""
    m = _IFACE_RE.match(name)
    if m:
        return m.group(1), int(m.group(2))
    return name, 0


def _apply_config_defaults(tunnels: list[TunnelConfig]) -> None:
    """Fill in default config_file for tunnels that don't specify one."""
    type_defaults = {
        "singbox": cfg.defaults.singbox_config,
        "openvpn": cfg.defaults.openvpn_config,
        "wireguard": cfg.defaults.wireguard_config,
    }
    for tc in tunnels:
        if not tc.config_file and tc.type in type_defaults:
            tc.config_file = type_defaults[tc.type]
            tc._auto_config_file = True


def _assign_singbox_interfaces(tunnels: list[TunnelConfig]) -> None:
    """Auto-assign unique interfaces to singbox tunnels without one."""
    used = {tc.interface for tc in tunnels if tc.interface}
    base = cfg.defaults.singbox_interface  # "utun99"
    prefix, counter = _parse_iface_name(base)

    for tc in tunnels:
        if tc.type != "singbox" or tc.interface:
            continue
        while f"{prefix}{counter}" in used:
            counter += 1
        tc.interface = f"{prefix}{counter}"
        used.add(tc.interface)
        counter += 1


def _validate_tunnels(tunnels: list[TunnelConfig]) -> None:
    """Validate tunnel configs for multi-instance conflicts."""
    # Check interface uniqueness (only for tunnels that specify one)
    ifaces: dict[str, str] = {}
    for tc in tunnels:
        if tc.interface:
            if tc.interface in ifaces:
                raise ValueError(
                    t(
                        "defaults.iface_conflict",
                        a=tc.name,
                        b=ifaces[tc.interface],
                        iface=tc.interface,
                    )
                )
            ifaces[tc.interface] = tc.name

    # Check log path uniqueness
    logs: dict[str, str] = {}
    for tc in tunnels:
        if tc.log:
            if tc.log in logs:
                raise ValueError(
                    t("defaults.log_conflict", a=tc.name, b=logs[tc.log], log=tc.log)
                )
            logs[tc.log] = tc.name


def filter_tunnels(tunnels: list[TunnelConfig], names: str) -> list[TunnelConfig]:
    """Filter tunnels by comma-separated names. Raises ValueError for unknown."""
    requested = [n.strip() for n in names.split(",") if n.strip()]
    if not requested:
        return tunnels

    known = {t_.name for t_ in tunnels}
    unknown = [n for n in requested if n not in known]
    if unknown:
        available = ", ".join(sorted(known)) or t("defaults.no_tunnels_available")
        raise ValueError(
            t(
                "defaults.unknown_tunnels",
                unknown=", ".join(unknown),
                available=available,
            )
        )

    requested_set = set(requested)
    return [t_ for t_ in tunnels if t_.name in requested_set]


def validate_config_files(tunnels: list[TunnelConfig]) -> None:
    """Validate config_file uniqueness within same type."""
    configs_by_type: dict[str, dict[str, str]] = {}
    for tc in tunnels:
        if tc.config_file:
            by_type = configs_by_type.setdefault(tc.type, {})
            if tc.config_file in by_type:
                raise ValueError(
                    t(
                        "defaults.config_conflict",
                        a=tc.name,
                        b=by_type[tc.config_file],
                        type=tc.type,
                        cf=tc.config_file,
                    )
                )
            by_type[tc.config_file] = tc.name
