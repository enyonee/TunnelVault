"""tunnelvault - multi-VPN connection manager."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("tunnelvault")
except PackageNotFoundError:
    # Fallback: read from pyproject.toml
    try:
        from pathlib import Path
        import re as _re

        _pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        _match = _re.search(r'version\s*=\s*"([^"]+)"', _pyproject.read_text())
        __version__ = _match.group(1) if _match else "dev"
    except Exception:
        __version__ = "dev"
