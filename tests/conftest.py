"""Shared fixtures for tunnelvault tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tv.logger import Logger
from tv.net import NetManager


@pytest.fixture(autouse=True)
def _pin_locale_and_reset():
    from tv import i18n

    i18n.init("en")
    yield
    from tv.app_config import reset

    reset()
    i18n.reset()


@pytest.fixture(autouse=True)
def _assume_binaries_installed(monkeypatch):
    """Default: all VPN binaries available. Override in specific tests."""
    from tv.vpn.base import TunnelPlugin

    monkeypatch.setattr(TunnelPlugin, "check_binary", classmethod(lambda cls: True))


# Ensure all VPN plugins are registered for the entire test suite.
import tv.vpn.openvpn as _ovpn  # noqa: F401,E402
import tv.vpn.fortivpn as _forti  # noqa: F401,E402
import tv.vpn.singbox as _sb  # noqa: F401,E402


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Temp directory with required config files."""
    (tmp_path / "client.ovpn").write_text("[openvpn config]")
    (tmp_path / "singbox.json").write_text('{"log":{"level":"info"}}')
    return tmp_path


@pytest.fixture
def logger(tmp_path: Path) -> Logger:
    return Logger(tmp_path / "test.log")


@pytest.fixture
def mock_net() -> MagicMock:
    """Mock NetManager with sensible defaults."""
    net = MagicMock(spec=NetManager)
    net.default_gateway.return_value = "192.168.1.1"
    net.interfaces.return_value = {"en0": "192.168.1.7", "lo0": "127.0.0.1"}
    net.check_interface.return_value = True
    net.add_host_route.return_value = True
    net.add_net_route.return_value = True
    net.add_iface_route.return_value = True
    net.setup_dns_resolver.return_value = {"alpha.local": True, "bravo.local": True}
    net.disable_ipv6.return_value = True
    net.restore_ipv6.return_value = True
    net.delete_host_route.return_value = True
    net.delete_net_route.return_value = True
    net.route_table.return_value = "default via 192.168.1.1 dev en0"
    net.iface_info.return_value = ""
    net.ppp_peer.return_value = ""
    net.resolve_host.return_value = ["1.2.3.4"]
    net.cleanup_dns_resolver.return_value = None
    net.cleanup_local_dns_resolvers.return_value = []
    return net
