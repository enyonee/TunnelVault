"""VPN tunnel plugins."""

from tv.vpn import registry  # noqa: F401 — ensure registry is importable
from tv.vpn import openconnect  # noqa: F401 — register openconnect plugin
