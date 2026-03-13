"""Read-modify-write config.toml preserving comments and formatting."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import tomlkit

from tv.app_config import cfg


def save_tunnel_data(
    tunnels_data: dict[str, dict],
    script_dir: Path,
) -> None:
    """Merge wizard-resolved values into config.toml.

    tunnels_data: structured per-tunnel data:
        {tunnel_name: {
            "auth": {key: value},
            "extra": {key: value},
            "config_file": str,
            "routes": {"targets": [...]},
            "dns": {"nameservers": [...]},
        }}
    """
    path = script_dir / cfg.paths.defaults_file
    if not path.exists():
        return

    doc = tomlkit.parse(path.read_text())

    tunnels_section = doc.get("tunnels")
    if not isinstance(tunnels_section, dict):
        return

    for name, data in tunnels_data.items():
        tunnel = tunnels_section.get(name)
        if not isinstance(tunnel, dict):
            continue

        # Auth params -> [tunnels.NAME.auth]
        if data.get("auth"):
            if "auth" not in tunnel:
                tunnel["auth"] = tomlkit.table()
            for k, v in data["auth"].items():
                tunnel["auth"][k] = v

        # Extra params -> top-level [tunnels.NAME] keys
        if data.get("extra"):
            for k, v in data["extra"].items():
                tunnel[k] = v

        # config_file -> [tunnels.NAME].config_file
        if "config_file" in data:
            tunnel["config_file"] = data["config_file"]

        # Routes targets -> [tunnels.NAME.routes].targets
        routes = data.get("routes", {})
        if "targets" in routes:
            if "routes" not in tunnel:
                tunnel["routes"] = tomlkit.table()
            tunnel["routes"]["targets"] = routes["targets"]

        # DNS nameservers -> [tunnels.NAME.dns].nameservers
        dns = data.get("dns", {})
        if "nameservers" in dns:
            if "dns" not in tunnel:
                tunnel["dns"] = tomlkit.table()
            tunnel["dns"]["nameservers"] = dns["nameservers"]

    _atomic_write(path, tomlkit.dumps(doc))


def _atomic_write(path: Path, content: str) -> None:
    """Write file atomically with 0o600 permissions."""
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)
    try:
        os.chmod(tmp_path, 0o600)
        _chown_to_real_user(tmp_path)
        os.rename(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _chown_to_real_user(path: str) -> None:
    """Chown file to real user when running under sudo."""
    uid_s = os.environ.get("SUDO_UID", "")
    gid_s = os.environ.get("SUDO_GID", "")
    if uid_s and gid_s:
        try:
            os.chown(path, int(uid_s), int(gid_s))
        except OSError:
            pass
