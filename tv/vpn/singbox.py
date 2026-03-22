"""sing-box tunnel connection."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from tv import proc, ui
from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger
from tv.vpn.base import ConfigParam, TunnelPlugin, VPNResult
from tv.vpn.registry import register


@register("singbox")
class SingBoxPlugin(TunnelPlugin):
    """sing-box tunnel plugin."""

    binary = "sing-box"
    type_display_name = "sing-box"
    process_names = ("sing-box",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._patched_config: str | None = None

    @classmethod
    def emergency_patterns(cls, script_dir) -> list[str]:
        return [f"sing-box run -c {script_dir}"]

    @classmethod
    def discover_pid(cls, tcfg, script_dir) -> int | None:
        config_path = script_dir / tcfg.config_file
        pids = proc.find_pids(f"sing-box run -c {config_path}")
        if pids:
            return pids[0]
        # Also check patched config pattern
        pids = proc.find_pids(f"sing-box run -c {cfg.paths.temp_dir}/sb_bypass_")
        return pids[0] if pids else None

    @classmethod
    def config_schema(cls) -> list[ConfigParam]:
        return [
            ConfigParam(
                "config_file",
                "param.sb_config",
                default=cfg.defaults.singbox_config,
                env_var="VPN_SINGBOX_CONFIG",
                target="config_file",
            ),
        ]

    @property
    def process_name(self) -> str:
        return "sing-box"

    @property
    def display_name(self) -> str:
        return "sing-box"

    def connect(self) -> VPNResult:
        config_path = self.script_dir / self.cfg.config_file
        log_path = self._default_log_path()
        interface = self.cfg.interface

        self.log.log("INFO", f"Config: {config_path}")

        if err := self._check_config_file("vpn.sb.config_not_found"):
            return err

        # Inject bypass domain rules into sing-box config if configured
        run_config = str(config_path)
        bypass_suffixes = self.cfg.extra.get("bypass_domain_suffix", [])
        if bypass_suffixes:
            patched = _inject_bypass_rules(config_path, bypass_suffixes, self.log)
            if patched:
                run_config = patched
                self._patched_config = patched

        # Launch in background
        self.log.log("INFO", f"Launch: sudo sing-box run -c {run_config}")
        sb_proc = proc.run_background(
            ["sing-box", "run", "-c", run_config],
            sudo=True,
            log_path=str(log_path),
        )
        sb_pid = sb_proc.pid
        self._pid = sb_pid
        self.log.log("INFO", f"sing-box PID={sb_pid}")

        # Wait for interface
        if not proc.wait_for(
            f"sing-box ({interface})",
            lambda: self.net.check_interface(interface),
            cfg.timeouts.singbox_iface,
            self.log,
        ):
            _show_error(sb_proc, log_path, self.log)
            return VPNResult(ok=False, pid=sb_pid)

        # Connected
        ui.ok(t("vpn.sb.connected", iface=interface))
        self.log.log("INFO", f"sing-box connected ({interface})")
        self.log.log_lines(
            "INFO", f"ifconfig {interface}:\n{self.net.iface_info(interface)}"
        )

        # Routes through interface (hosts + networks from config/targets)
        self.add_routes()

        # DNS resolver (domains + nameservers from config/targets)
        self.setup_dns()

        self.log.log("INFO", f"Routes after sing-box:\n{self.net.route_table()}")

        return VPNResult(ok=True, pid=sb_pid)

    def disconnect(self) -> None:
        super().disconnect()
        # Clean up patched config file
        if self._patched_config:
            try:
                os.unlink(self._patched_config)
            except OSError:
                pass
            self._patched_config = None

    def _kill_by_pattern(self) -> None:
        config_path = self.script_dir / self.cfg.config_file
        proc.kill_pattern(f"sing-box run -c {config_path}", sudo=True)
        # Also kill by patched config pattern
        if self._patched_config:
            proc.kill_pattern(f"sing-box run -c {self._patched_config}", sudo=True)


def _inject_bypass_rules(
    config_path: Path,
    suffixes: list[str],
    log: Logger,
) -> str | None:
    """Inject bypass domain_suffix rules into sing-box JSON config.

    Creates a temp file with domain_suffix rules added as the first route
    rule with outbound "direct". Returns the temp file path, or None on error.
    """
    try:
        data = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        log.log("WARN", f"bypass inject: cannot read {config_path}: {e}")
        return None

    # Normalize suffixes: ".ru" -> "ru", "vk.com" -> "vk.com"
    normalized = [s.lstrip(".").rstrip(".") for s in suffixes if s.strip()]
    if not normalized:
        return None

    # Build bypass rule
    bypass_rule = {
        "domain_suffix": normalized,
        "outbound": "direct",
    }

    # Inject as first route rule (highest priority)
    route = data.setdefault("route", {})
    rules = route.setdefault("rules", [])
    rules.insert(0, bypass_rule)

    # Write patched config to temp file
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix="sb_bypass_",
            suffix=".json",
            dir=cfg.paths.temp_dir,
        )
        os.write(fd, json.dumps(data, indent=2).encode())
        os.close(fd)
    except OSError as e:
        log.log("WARN", f"bypass inject: cannot write temp config: {e}")
        return None

    log.log(
        "INFO",
        f"bypass inject: {len(normalized)} domain suffixes -> direct ({tmp_path})",
    )
    return tmp_path


def _show_error(sb_proc, log_path: Path, log: Logger) -> None:
    """Display sing-box error details."""
    ui.fail(t("vpn.sb.not_connected", timeout=cfg.timeouts.singbox_iface))
    log.log("ERROR", f"sing-box did not start within {cfg.timeouts.singbox_iface}s")

    pid = sb_proc.pid
    if proc.is_alive(pid):
        details = [("", t("vpn.sb.alive_no_iface", pid=pid))]
        log.log("WARN", f"sing-box PID={pid} alive but interface not found")
    else:
        rc = sb_proc.poll()
        rc_display = rc if rc is not None else "?"
        details = [("", t("vpn.sb.exited", rc=rc_display))]
        log.log("ERROR", f"sing-box process exited with code {rc}")

    details.append(("", t("vpn.sb.log_hint", path=log_path)))
    ui.error_tree(details)
