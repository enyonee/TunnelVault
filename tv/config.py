"""Config: ENV, TOML-driven param resolution, save back to config.toml."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from tv import ui, routing
from tv.app_config import cfg
from tv.i18n import t

if TYPE_CHECKING:
    from tv.vpn.base import TunnelConfig

from tv.vpn.base import ConfigParam


class SetupRequiredError(Exception):
    """Raised when interactive setup is needed but quiet mode is active."""


# --- Tunnel param resolution via plugin config_schema() ---


def _get_param_value(tcfg: TunnelConfig, param: ConfigParam) -> str:
    """Get current value of a param from TunnelConfig."""
    if param.target == "auth":
        return tcfg.auth.get(param.key, "")
    if param.target == "config_file":
        return tcfg.config_file
    if param.target == "extra":
        return str(tcfg.extra.get(param.key, ""))
    return ""


def _set_param_value(tcfg: TunnelConfig, param: ConfigParam, value: str) -> None:
    """Set param value on TunnelConfig."""
    if param.target == "auth":
        tcfg.auth[param.key] = value
    elif param.target == "config_file":
        tcfg.config_file = value
    elif param.target == "extra":
        tcfg.extra[param.key] = value


def all_required_set(tunnels: list[TunnelConfig]) -> bool:
    """Check if all tunnels have their required params populated."""
    from tv.vpn.registry import get_plugin

    for tcfg in tunnels:
        try:
            plugin_cls = get_plugin(tcfg.type)
        except KeyError:
            continue
        for param in plugin_cls.config_schema():
            if param.required and not _get_param_value(tcfg, param):
                return False
    return True


def resolve_tunnel_params(
    tcfg: TunnelConfig,
    plugin_cls: type,
    script_dir: Path,
    *,
    quiet: bool = False,
    setup: bool = False,
) -> None:
    """Resolve missing params for a tunnel using plugin's config_schema().

    Mutates tcfg.auth / tcfg.config_file / tcfg.extra in place.
    Priority: TOML value -> ENV -> wizard input.
    In quiet mode: no prints, no wizard. Raises SetupRequiredError if required param missing.
    When *setup=True*: show wizard with current values as defaults, letting user override.
    """
    schema = plugin_cls.config_schema()
    if not schema:
        return

    for param in schema:
        # Current value from TOML (includes wizard-saved values from previous runs)
        current = _get_param_value(tcfg, param)
        if current:
            # In setup mode, let user override values via wizard
            if setup and param.prompt:
                ui.param_found(param.label, current, "config.toml", param.secret)
                new_value = ui.wizard_input(t(param.label), current, param.secret)
                _set_param_value(tcfg, param, new_value)
                continue

            # Auto-applied config_file defaults can be overridden by ENV
            if param.target == "config_file" and tcfg._auto_config_file:
                env_val = os.environ.get(param.env_var, "") if param.env_var else ""
                if env_val:
                    _set_param_value(tcfg, param, env_val)
                    if not quiet:
                        ui.param_found(
                            param.label, env_val, f"${param.env_var}", param.secret
                        )
                    continue
                if not quiet:
                    ui.param_found(
                        param.label, current, t("config.source_auto"), param.secret
                    )
                continue
            if not quiet:
                ui.param_found(param.label, current, "config.toml", param.secret)
            continue

        # Cert with cert_mode=auto: skip wizard, handled by post_resolve_params
        if tcfg.auth.get("cert_mode") == "auto" and param.key in (
            "trusted_cert",
            "servercert",
        ):
            continue

        # Non-interactive params: resolve from ENV only, no wizard
        if not param.prompt:
            value = _resolve_silent(param, quiet=quiet)
            if value:
                _set_param_value(tcfg, param, value)
            continue

        # Resolve: ENV -> wizard (or default/error in quiet mode)
        value = _resolve_param(
            param.label,
            env_name=param.env_var,
            default=param.default,
            secret=param.secret,
            quiet=quiet,
            setup=setup,
        )
        _set_param_value(tcfg, param, value)

    # Plugin-specific post-processing (e.g. FortiVPN cert auto-generation)
    plugin_cls.post_resolve_params(tcfg, quiet=quiet)


def resolve_tunnel_routes(
    tcfg: TunnelConfig,
    *,
    quiet: bool = False,
    setup: bool = False,
) -> None:
    """Resolve routes for a tunnel: TOML targets -> parse, or wizard.

    When *setup=True*: show wizard with current targets as defaults.
    """
    # Advanced mode: TOML already has explicit routes - skip wizard
    has_advanced = bool(tcfg.routes.get("networks") or tcfg.routes.get("hosts"))
    if has_advanced and not quiet:
        nets = tcfg.routes.get("networks", [])
        hosts = tcfg.routes.get("hosts", [])
        ui.param_found(
            t("config.routes_label", name=tcfg.name),
            t("config.routes_count", nets=len(nets), hosts=len(hosts)),
            "config.toml",
            False,
        )

    # Get targets from TOML (includes wizard-saved values from previous runs)
    targets = tcfg.routes.get("targets", [])
    resolved = ("targets" in tcfg.routes) or has_advanced

    # In setup mode, show wizard with current targets as defaults
    if setup and not has_advanced:
        if targets:
            ui.param_found("Targets", ", ".join(targets), "config.toml", False)
        targets = ui.wizard_targets(tcfg.name, default=targets)
    elif not resolved:
        if quiet:
            targets = []  # Native routing in quiet mode
        else:
            targets = ui.wizard_targets(tcfg.name)
    elif not quiet:
        if targets:
            ui.param_found("Targets", ", ".join(targets), "config.toml", False)

    # Always store targets for saving ([] = native routing, remembered)
    tcfg.routes["targets"] = targets

    if targets:
        # Parse and merge into tcfg.routes / tcfg.dns
        parsed = routing.parse_targets(targets)
        routing.merge_targets_into_config(tcfg, parsed)

    # DNS nameservers needed for domains (from targets or TOML)?
    all_domains = tcfg.dns.get("domains", [])
    if all_domains and not tcfg.dns.get("nameservers"):
        if not quiet:
            ns = ui.wizard_nameservers(all_domains)
            if ns:
                tcfg.dns["nameservers"] = ns


def save_tunnel_settings(tunnels: list[TunnelConfig], script_dir: Path) -> None:
    """Save resolved auth/config params back to config.toml."""
    from tv.vpn.registry import get_plugin
    from tv import toml_writer

    data: dict = {}
    for tcfg in tunnels:
        tunnel_data: dict = {"auth": {}, "extra": {}}

        # Auth/config params from plugin schema
        try:
            plugin_cls = get_plugin(tcfg.type)
            schema = plugin_cls.config_schema()
            for param in schema:
                value = _get_param_value(tcfg, param)
                if not value:
                    continue
                if param.target == "auth":
                    tunnel_data["auth"][param.key] = value
                elif param.target == "extra":
                    tunnel_data["extra"][param.key] = value
                elif param.target == "config_file":
                    tunnel_data["config_file"] = value
        except KeyError:
            pass

        # Targets (from wizard or TOML; [] = native routing, save explicitly)
        if "targets" in tcfg.routes:
            tunnel_data["routes"] = {"targets": tcfg.routes["targets"]}

        # DNS nameservers (from wizard)
        ns = tcfg.dns.get("nameservers", [])
        if ns:
            tunnel_data["dns"] = {"nameservers": ns}

        # Clean empty sections
        if not tunnel_data["auth"]:
            del tunnel_data["auth"]
        if not tunnel_data["extra"]:
            del tunnel_data["extra"]

        if tunnel_data:
            data[tcfg.name] = tunnel_data

    toml_writer.save_tunnel_data(data, script_dir)
    print(
        f"  {ui.GREEN}💾 {t('config.settings_saved')}{ui.NC} {ui.DIM}({cfg.paths.defaults_file}){ui.NC}"
    )


def _chown_to_real_user(path: str) -> None:
    """Chown file/dir to real user when running under sudo."""
    uid_s = os.environ.get("SUDO_UID", "")
    gid_s = os.environ.get("SUDO_GID", "")
    if uid_s and gid_s:
        try:
            os.chown(path, int(uid_s), int(gid_s))
        except OSError:
            pass


def resolve_log_dir(script_dir: Path) -> Path:
    """Resolve log_dir to absolute path (relative to script_dir if needed)."""
    d = Path(cfg.paths.log_dir)
    if not d.is_absolute():
        d = script_dir / d
    return d


def ensure_log_dir(script_dir: Path) -> Path:
    """Create log directory with correct ownership. Returns absolute path."""
    d = resolve_log_dir(script_dir)
    d.mkdir(parents=True, exist_ok=True)
    _chown_to_real_user(str(d))
    return d


def resolve_log_paths(tunnels: list[TunnelConfig], script_dir: Path) -> None:
    """Resolve relative tunnel log paths to absolute (relative to script_dir)."""
    for tc in tunnels:
        if tc.log:
            p = Path(tc.log)
            if not p.is_absolute():
                tc.log = str(script_dir / p)


def prepare_log_files(tunnels: list[TunnelConfig]) -> None:
    """Pre-create log files with correct ownership and readable permissions."""
    for tc in tunnels:
        if not tc.log:
            continue
        p = Path(tc.log)
        p.parent.mkdir(parents=True, exist_ok=True)
        _chown_to_real_user(str(p.parent))
        if not p.exists():
            p.touch()
        os.chmod(str(p), 0o644)
        _chown_to_real_user(str(p))


# --- Param resolution: ENV -> wizard ---


def _resolve_silent(
    param: ConfigParam,
    *,
    quiet: bool = False,
) -> str:
    """Resolve param from ENV only (no wizard prompt)."""
    if param.env_var:
        env_val = os.environ.get(param.env_var, "")
        if env_val:
            if not quiet:
                ui.param_found(param.label, env_val, f"${param.env_var}", param.secret)
            return env_val
    return param.default


def _resolve_param(
    label: str,
    env_name: str = "",
    default: str = "",
    secret: bool = False,
    quiet: bool = False,
    setup: bool = False,
) -> str:
    """Resolve single param with priority chain: ENV -> wizard.

    TOML values are checked before this function is called.
    """
    # 1. ENV
    env_val = os.environ.get(env_name, "") if env_name else ""
    if env_val:
        if not quiet:
            ui.param_found(label, env_val, f"${env_name}", secret)
        return env_val

    # 2. Quiet mode: use default or error
    if quiet:
        if default:
            return default
        raise SetupRequiredError(t("config.param_not_set", label=t(label)))

    # 3. Default (show as placeholder in wizard)
    if default and not secret:
        ui.param_missing(label)
        return ui.wizard_input(t(label), default, secret)

    # 4. Wizard without default
    ui.param_missing(label)
    return ui.wizard_input(t(label), "", secret)
