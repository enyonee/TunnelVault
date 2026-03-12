"""Config: CLI args, ENV, settings file, plugin-driven param resolution."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
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


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=t("cli.desc"),
    )
    p.add_argument("--disconnect", action="store_true", help=t("cli.disconnect"))
    p.add_argument("--clear", action="store_true", help=t("cli.clear"))
    p.add_argument("--setup", action="store_true", help=t("cli.setup"))
    p.add_argument("--debug", action="store_true", help=t("cli.debug"))
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
        default=None,
        help=t("cli.log_level"),
    )
    p.add_argument("--status", action="store_true", help=t("cli.status"))
    p.add_argument("--check", action="store_true", help=t("cli.check"))
    p.add_argument("--reset", action="store_true", help=t("cli.reset"))
    p.add_argument("--validate", action="store_true", help=t("cli.validate"))
    p.add_argument("--only", type=str, default=None, help=t("cli.only"))
    p.add_argument("--logs", nargs="?", const="", default=None, help=t("cli.logs"))
    p.add_argument("--watch", action="store_true", help=t("cli.watch"))
    p.add_argument("--all", action="store_true", help=t("cli.all"))
    run_mode = p.add_mutually_exclusive_group()
    run_mode.add_argument("--no-daemon", action="store_true", help=t("cli.no_daemon"))
    run_mode.add_argument("--foreground", action="store_true", help=t("cli.foreground"))
    autostart = p.add_mutually_exclusive_group()
    autostart.add_argument("--enable", action="store_true", help=t("cli.enable"))
    autostart.add_argument("--disable", action="store_true", help=t("cli.disable"))
    return p.parse_args()


# --- Settings file (JSON) ---


def load_settings(script_dir: Path, *, quiet: bool = False) -> dict:
    path = script_dir / cfg.paths.settings_file
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if not quiet:
                print(
                    f"  {ui.GREEN}📂{ui.NC} {t('config.settings_loaded')} {ui.DIM}({cfg.paths.settings_file}){ui.NC}"
                )
            return data
        except (json.JSONDecodeError, OSError) as e:
            if not quiet:
                print(
                    f"  {ui.RED}⚠{ui.NC}  {t('config.settings_error')} {ui.DIM}({e}){ui.NC}"
                )
            # Fall through to try bash settings migration

    # Try migrating from old bash format
    old_path = script_dir / ".vpn-settings"
    if old_path.exists():
        migrated = _migrate_bash_settings(old_path)
        if migrated:
            if not quiet:
                print(f"  {ui.GREEN}📂{ui.NC} {t('config.settings_migrated')}")
            return migrated

    if not quiet:
        print(
            f"  {ui.YELLOW}📂{ui.NC} {t('config.settings_not_found')} {ui.DIM}{t('config.settings_will_create', file=cfg.paths.settings_file)}{ui.NC}"
        )
    return {}


def _migrate_bash_settings(path: Path) -> dict:
    """Parse old bash SAVED_FOO=\"bar\" format into per-tunnel nested dict."""
    result: dict = {}
    key_map: dict[str, tuple[str, str]] = {
        "SAVED_OVPN_CONFIG": ("openvpn", "config_file"),
        "SAVED_PIKLEMA_CONFIG": ("singbox", "config_file"),
        "SAVED_SINGBOX_CONFIG": ("singbox", "config_file"),
        "SAVED_FORTI_HOST": ("fortivpn", "host"),
        "SAVED_FORTI_PORT": ("fortivpn", "port"),
        "SAVED_FORTI_LOGIN": ("fortivpn", "login"),
        "SAVED_FORTI_PASS": ("fortivpn", "pass"),
        "SAVED_TRUSTED_CERT": ("fortivpn", "trusted_cert"),
        "SAVED_CERT_MODE": ("fortivpn", "cert_mode"),
    }
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"')
            if key in key_map:
                tunnel_name, param_key = key_map[key]
                result.setdefault(tunnel_name, {})[param_key] = value
    except OSError:
        pass
    return result


# --- Tunnel param resolution via plugin config_schema() ---


def _tunnel_saved(saved: dict, tcfg: TunnelConfig) -> dict:
    """Lookup saved settings for a tunnel: by name, then by type."""
    return saved.get(tcfg.name) or saved.get(tcfg.type, {})


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


def resolve_tunnel_params(
    tcfg: TunnelConfig,
    plugin_cls: type,
    saved: dict,
    script_dir: Path,
    *,
    quiet: bool = False,
    setup: bool = False,
) -> None:
    """Resolve missing params for a tunnel using plugin's config_schema().

    Mutates tcfg.auth / tcfg.config_file / tcfg.extra in place.
    Priority: TOML value -> ENV -> saved -> wizard input.
    In quiet mode: no prints, no wizard. Raises SetupRequiredError if required param missing.
    When *setup=True*: show wizard with current values as defaults, letting user override.
    """
    schema = plugin_cls.config_schema()
    if not schema:
        return

    tunnel_saved = _tunnel_saved(saved, tcfg)

    for param in schema:
        # Current value from TOML (or auto-applied default)
        current = _get_param_value(tcfg, param)
        if current:
            # In setup mode, let user override TOML values via wizard
            if setup and param.prompt:
                ui.param_found(param.label, current, "defaults.toml", param.secret)
                new_value = ui.wizard_input(t(param.label), current, param.secret)
                _set_param_value(tcfg, param, new_value)
                continue

            # Auto-applied config_file defaults can be overridden by ENV/saved
            if param.target == "config_file" and tcfg._auto_config_file:
                env_val = os.environ.get(param.env_var, "") if param.env_var else ""
                if env_val:
                    _set_param_value(tcfg, param, env_val)
                    if not quiet:
                        ui.param_found(
                            param.label, env_val, f"${param.env_var}", param.secret
                        )
                    continue
                saved_val = tunnel_saved.get(param.key, "")
                if saved_val:
                    _set_param_value(tcfg, param, saved_val)
                    if not quiet:
                        ui.param_found(
                            param.label,
                            saved_val,
                            cfg.paths.settings_file,
                            param.secret,
                        )
                    continue
                if not quiet:
                    ui.param_found(
                        param.label, current, t("config.source_auto"), param.secret
                    )
                continue
            if not quiet:
                ui.param_found(param.label, current, "defaults.toml", param.secret)
            continue

        # FortiVPN trusted_cert with cert_mode=auto: skip wizard, handled below
        if (
            tcfg.type == "fortivpn"
            and param.key == "trusted_cert"
            and tcfg.auth.get("cert_mode") == "auto"
        ):
            continue

        # Non-interactive params: resolve from ENV/saved only, no wizard
        if not param.prompt:
            value = _resolve_silent(param, tunnel_saved, quiet=quiet)
            if value:
                _set_param_value(tcfg, param, value)
            continue

        # Resolve: ENV -> saved -> wizard (or default/error in quiet mode)
        value = _resolve_param(
            param.label,
            env_name=param.env_var,
            saved=tunnel_saved.get(param.key, ""),
            default=param.default,
            secret=param.secret,
            quiet=quiet,
            setup=setup,
        )
        _set_param_value(tcfg, param, value)

    # FortiVPN cert_mode=auto: generate cert after all params resolved
    if tcfg.type == "fortivpn":
        _handle_forti_cert(tcfg, tunnel_saved, quiet=quiet)


def _handle_forti_cert(
    tcfg: TunnelConfig,
    tunnel_saved: dict,
    *,
    quiet: bool = False,
) -> None:
    """Handle FortiVPN trusted_cert: auto-generate or resolve from ENV/saved."""
    cert_mode = tcfg.auth.get("cert_mode", "")
    if cert_mode != "auto":
        return
    if tcfg.auth.get("trusted_cert"):
        return

    # Check ENV
    env_val = os.environ.get("VPN_TRUSTED_CERT", "")
    if env_val:
        if not quiet:
            ui.param_found("param.cert_sha256", env_val, "$VPN_TRUSTED_CERT", False)
        tcfg.auth["trusted_cert"] = env_val
        return

    # Check saved (reject sha256 of empty - broken cert generation)
    saved_val = tunnel_saved.get("trusted_cert", "")
    if saved_val and saved_val != _SHA256_EMPTY:
        if not quiet:
            ui.param_found(
                "param.cert_sha256", saved_val, cfg.paths.settings_file, False
            )
        tcfg.auth["trusted_cert"] = saved_val
        return

    # Auto-generate
    host = tcfg.auth.get("host", "")
    port = tcfg.auth.get("port", cfg.defaults.fortivpn_port)
    if not host:
        return

    if not quiet:
        print(f"  🔑 {t('config.cert_generating', host=host, port=port)}")
    cert = _generate_cert(host, port)
    if cert:
        if not quiet:
            print(f"  {ui.GREEN}✅{ui.NC} {t('config.cert_generated', cert=cert[:24])}")
        tcfg.auth["trusted_cert"] = cert
    else:
        ui.warn(t("config.cert_unreachable", host=host, port=port))
        ui.info(
            f"  {ui.DIM}{t('config.cert_hint', env='VPN_TRUSTED_CERT', file=cfg.paths.settings_file)}{ui.NC}"
        )


def resolve_tunnel_routes(
    tcfg: TunnelConfig,
    saved: dict,
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
            "defaults.toml",
            False,
        )

    # Get targets: TOML -> saved -> wizard
    targets = tcfg.routes.get("targets", [])
    source = "defaults.toml"
    resolved = bool(targets) or has_advanced

    if not resolved:
        tunnel_saved = _tunnel_saved(saved, tcfg)
        if "targets" in tunnel_saved:
            targets = tunnel_saved["targets"]
            source = cfg.paths.settings_file
            resolved = True

    # In setup mode, show wizard with current targets as defaults
    if setup and not has_advanced:
        if targets:
            ui.param_found("Targets", ", ".join(targets), source, False)
        targets = ui.wizard_targets(tcfg.name, default=targets)
    elif not resolved:
        if quiet:
            targets = []  # Native routing in quiet mode
        else:
            targets = ui.wizard_targets(tcfg.name)
    elif not quiet:
        if targets:
            ui.param_found("Targets", ", ".join(targets), source, False)
        elif source == cfg.paths.settings_file:
            ui.param_found(
                t("config.routes_label", name=tcfg.name),
                t("config.routes_native"),
                source,
                False,
            )

    # Always store targets for saving ([] = native routing, remembered)
    tcfg.routes["targets"] = targets

    if targets:
        # Parse and merge into tcfg.routes / tcfg.dns
        parsed = routing.parse_targets(targets)
        routing.merge_targets_into_config(tcfg, parsed)

    # DNS nameservers needed for domains (from targets or TOML)?
    all_domains = tcfg.dns.get("domains", [])
    if all_domains and not tcfg.dns.get("nameservers"):
        tunnel_saved = _tunnel_saved(saved, tcfg)
        ns = tunnel_saved.get("dns_nameservers", [])
        if ns:
            if not quiet:
                ui.param_found("DNS", ", ".join(ns), cfg.paths.settings_file, False)
        elif not quiet:
            ns = ui.wizard_nameservers(all_domains)
        if ns:
            tcfg.dns["nameservers"] = ns


def save_tunnel_settings(tunnels: list[TunnelConfig], script_dir: Path) -> None:
    """Save resolved auth/config params to .vpn-settings.json."""
    from tv.vpn.registry import get_plugin

    data: dict = {}
    for tcfg in tunnels:
        tunnel_data: dict = {}

        # Auth/config params from plugin schema
        try:
            plugin_cls = get_plugin(tcfg.type)
            schema = plugin_cls.config_schema()
            for param in schema:
                value = _get_param_value(tcfg, param)
                if value:
                    tunnel_data[param.key] = value
        except KeyError:
            pass

        # Targets (from wizard or TOML; [] = native routing, save explicitly)
        if "targets" in tcfg.routes:
            tunnel_data["targets"] = tcfg.routes["targets"]

        # DNS nameservers (from wizard)
        ns = tcfg.dns.get("nameservers", [])
        if ns:
            tunnel_data["dns_nameservers"] = ns

        if tunnel_data:
            data[tcfg.name] = tunnel_data

    _write_settings(data, script_dir)


def _write_settings(data: dict, script_dir: Path) -> None:
    """Write settings dict to JSON with 0o600 permissions (atomic via rename)."""
    import tempfile

    path = script_dir / cfg.paths.settings_file
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, tmp_path = tempfile.mkstemp(dir=str(script_dir), suffix=".tmp")
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)
    try:
        os.chmod(tmp_path, 0o600)
        _chown_to_real_user(tmp_path)
        os.replace(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    print(
        f"  {ui.GREEN}💾 {t('config.settings_saved')}{ui.NC} {ui.DIM}({cfg.paths.settings_file}){ui.NC}"
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


# --- Param resolution: ENV -> saved -> wizard ---


def _resolve_silent(
    param: ConfigParam,
    tunnel_saved: dict,
    *,
    quiet: bool = False,
) -> str:
    """Resolve param from ENV/saved only (no wizard prompt)."""
    if param.env_var:
        env_val = os.environ.get(param.env_var, "")
        if env_val:
            if not quiet:
                ui.param_found(param.label, env_val, f"${param.env_var}", param.secret)
            return env_val
    saved_val = tunnel_saved.get(param.key, "")
    if saved_val:
        if not quiet:
            ui.param_found(
                param.label, saved_val, cfg.paths.settings_file, param.secret
            )
        return saved_val
    return param.default


def _resolve_param(
    label: str,
    env_name: str = "",
    saved: str = "",
    default: str = "",
    secret: bool = False,
    quiet: bool = False,
    setup: bool = False,
) -> str:
    """Resolve single param with priority chain: ENV -> saved -> wizard.

    When *setup=True*: saved value shown as wizard default instead of accepted silently.
    """
    # 1. ENV
    env_val = os.environ.get(env_name, "") if env_name else ""
    if env_val:
        if not quiet:
            ui.param_found(label, env_val, f"${env_name}", secret)
        return env_val

    # 2. Saved (.vpn-settings.json)
    if saved:
        if setup:
            # Show wizard with saved value as default
            ui.param_found(label, saved, cfg.paths.settings_file, secret)
            return ui.wizard_input(t(label), saved, secret)
        if not quiet:
            ui.param_found(label, saved, cfg.paths.settings_file, secret)
        return saved

    # 3. Quiet mode: use default or error
    if quiet:
        if default:
            return default
        raise SetupRequiredError(t("config.param_not_set", label=t(label)))

    # 4. Default from defaults.toml (show as placeholder in wizard)
    if default and not secret:
        ui.param_missing(label)
        return ui.wizard_input(t(label), default, secret)

    # 5. Wizard without default
    ui.param_missing(label)
    return ui.wizard_input(t(label), "", secret)


_SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _generate_cert(host: str, port: str) -> str:
    """Generate SHA256 cert fingerprint via openssl pipe chain."""
    procs: list[subprocess.Popen] = []
    try:
        s_client = subprocess.Popen(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        procs.append(s_client)
        x509 = subprocess.Popen(
            ["openssl", "x509", "-outform", "DER"],
            stdin=s_client.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(x509)
        s_client.stdout.close()

        # Send empty line to s_client (like "echo |")
        s_client.stdin.write(b"\n")
        s_client.stdin.close()

        # Read x509 DER output first - if empty, server didn't return a cert
        der_out, x509_err = x509.communicate(timeout=cfg.timeouts.cert_generation)
        s_client.wait(timeout=cfg.timeouts.cert_openssl)

        if not der_out:
            return ""

        # Hash the DER cert
        dgst = subprocess.Popen(
            ["openssl", "dgst", "-sha256"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        procs.append(dgst)
        out, _ = dgst.communicate(input=der_out, timeout=cfg.timeouts.cert_openssl)

        if dgst.returncode == 0 and out:
            text = out.decode().strip()
            if "= " in text:
                cert = text.split("= ", 1)[1].strip()
            else:
                cert = text
            # Reject sha256 of empty input (broken pipe produced no cert data)
            if cert == _SHA256_EMPTY:
                return ""
            return cert
    except (subprocess.TimeoutExpired, OSError):
        pass
    finally:
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass
        for p in procs:
            try:
                p.wait(timeout=2)
            except Exception:
                pass
    return ""
