"""VPN tunnel plugins."""

from tv.vpn import registry  # noqa: F401 — ensure registry is importable
from tv.vpn import openconnect  # noqa: F401 — register plugins
from tv.vpn import openvpn  # noqa: F401
from tv.vpn import fortivpn  # noqa: F401
from tv.vpn import singbox  # noqa: F401
from tv.vpn import wireguard  # noqa: F401
from tv.vpn import ipsec  # noqa: F401
from tv.vpn import tailscale  # noqa: F401
from tv.vpn import sshtunnel  # noqa: F401
