"""Validate defaults.toml configuration without connecting."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from tv import ui, routing
from tv.disconnect import get_vpn_server_routes
from tv.i18n import t
from tv.vpn.registry import available_types, get_plugin


def run(defs: dict, script_dir: Path) -> bool:
    """Validate tunnel configuration. Returns True if valid."""
    print(f"\n  {ui.BOLD}{t('validate.title')}{ui.NC}\n")

    errors: list[str] = []
    warnings: list[str] = []

    tunnels_section = defs.get("tunnels", {})
    if not tunnels_section:
        warnings.append(t("validate.no_tunnels"))
        _print_results(errors, warnings)
        return len(errors) == 0

    known_types = set(available_types())

    # Track config_file per type for duplicate detection
    config_files_by_type: dict[str, dict[str, str]] = {}

    for name, raw in tunnels_section.items():
        if not isinstance(raw, dict):
            continue

        prefix = f"[tunnels.{name}]"

        # Tunnel type
        ttype = raw.get("type", "")
        if not ttype:
            errors.append(f"{prefix}: {t('validate.missing_type')}")
            continue
        if ttype not in known_types:
            errors.append(
                f"{prefix}: {t('validate.unknown_type', type=ttype, available=', '.join(sorted(known_types)))}"
            )

        # binary availability
        if ttype in known_types:
            plugin_cls = get_plugin(ttype)
            if not plugin_cls.check_binary():
                binary = plugin_cls.binary or ttype
                warnings.append(
                    f"{prefix}: {t('validate.binary_not_found', binary=binary)}"
                )

        # config_file
        cf = raw.get("config_file", "")
        if cf:
            if Path(cf).is_absolute():
                errors.append(f"{prefix}: {t('validate.absolute_path', cf=cf)}")
            else:
                full = script_dir / cf
                if not full.exists():
                    warnings.append(
                        f"{prefix}: {t('validate.config_not_found', cf=cf)}"
                    )

            # Duplicate detection within same type
            by_type = config_files_by_type.setdefault(ttype, {})
            if cf in by_type:
                errors.append(
                    f"{prefix}: {t('validate.config_duplicate', cf=cf, other=by_type[cf])}"
                )
            else:
                by_type[cf] = name

        # routes.targets
        targets = raw.get("routes", {}).get("targets", [])
        for tgt in targets:
            _, err = routing.validate_target(tgt)
            if err:
                errors.append(f"{prefix}: routes.targets: {err}")

        # routes.networks - must be CIDR, not bare IP
        networks = raw.get("routes", {}).get("networks", [])
        for n in networks:
            try:
                ipaddress.ip_network(n, strict=False)
            except ValueError:
                errors.append(
                    f"{prefix}: routes.networks: {t('validate.invalid_cidr', n=n)}"
                )
            else:
                if "/" not in n:
                    errors.append(
                        f"{prefix}: routes.networks: {t('validate.ip_no_mask', n=n)}"
                    )

        # dns: domains without nameservers
        dns_cfg = raw.get("dns", {})
        if dns_cfg.get("domains") and not dns_cfg.get("nameservers"):
            warnings.append(f"{prefix}: {t('validate.dns_no_ns')}")

        # auth: required params from plugin schema
        if ttype in known_types:
            auth = raw.get("auth", {})
            try:
                plugin_cls = get_plugin(ttype)
                for param in plugin_cls.config_schema():
                    if not param.required:
                        continue
                    # Check if value present in TOML auth or config_file
                    if param.target == "auth" and not auth.get(param.key):
                        warnings.append(
                            f"{prefix}: {t('validate.param_needs_env', key=param.key, label=t(param.label))}"
                        )
                    elif param.target == "config_file" and not cf:
                        warnings.append(
                            f"{prefix}: {t('validate.config_will_default', label=t(param.label))}"
                        )
            except KeyError:
                pass

        # checks.ports
        for entry in raw.get("checks", {}).get("ports", []):
            if not entry.get("host"):
                errors.append(f"{prefix}: {t('validate.missing_check_host')}")
            if not entry.get("port"):
                errors.append(f"{prefix}: {t('validate.missing_check_port')}")

    # Global: vpn_server_routes.hosts
    server_routes = get_vpn_server_routes(defs)
    for host in server_routes.get("hosts", []):
        _, err = routing.validate_target(host)
        if err:
            errors.append(f"vpn_server_routes.hosts: {err}")

    # Global: bypass.domain_suffix
    bypass = defs.get("global", {}).get("bypass", {})
    for suffix in bypass.get("domain_suffix", []):
        if not suffix.startswith("."):
            warnings.append(
                f"bypass.domain_suffix: {t('validate.suffix_no_dot', suffix=suffix)}"
            )

    _print_results(errors, warnings)
    return len(errors) == 0


def _print_results(errors: list[str], warnings: list[str]) -> None:
    """Print validation results."""
    if errors:
        print(
            f"  {ui.RED}{ui.BOLD}{t('validate.errors_title', count=len(errors))}{ui.NC}"
        )
        for e in errors:
            print(f"    {ui.RED}✗{ui.NC} {e}")
        print()

    if warnings:
        print(
            f"  {ui.YELLOW}{ui.BOLD}{t('validate.warnings_title', count=len(warnings))}{ui.NC}"
        )
        for w in warnings:
            print(f"    {ui.YELLOW}⚠{ui.NC} {w}")
        print()

    if not errors and not warnings:
        print(f"  {ui.GREEN}✅ {t('validate.config_valid')}{ui.NC}\n")
    elif not errors:
        print(f"  {ui.GREEN}✅ {t('validate.no_critical_errors')}{ui.NC}\n")
