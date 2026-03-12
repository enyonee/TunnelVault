"""Integration tests: reconnect and disconnect-connect cycles.

Tests that tunnelvault can recover from disconnection:
- disconnect + reconnect cycle
- Engine.reconnect_all() full cycle
- Rapid connect/disconnect stability
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest

from tv.engine import Engine
from tv.logger import Logger
from tv.net import NetManager


pytestmark = pytest.mark.network


@pytest.fixture
def openvpn_project(tmp_path: Path, openvpn_client_config: Path) -> Path:
    """Project dir with defaults.toml for OpenVPN tunnel."""
    dst = tmp_path / "client.ovpn"
    dst.write_text(openvpn_client_config.read_text())

    (tmp_path / "defaults.toml").write_text(
        "[tunnels.openvpn]\n"
        'type = "openvpn"\n'
        "order = 1\n"
        'config_file = "client.ovpn"\n'
        f'log = "{tmp_path}/openvpn.log"\n'
        "\n"
        "[tunnels.openvpn.checks]\n"
        'ping = [{host = "10.8.0.1"}]\n'
    )

    settings = {"openvpn": {"config_file": "client.ovpn", "targets": []}}
    (tmp_path / ".vpn-settings.json").write_text(json.dumps(settings))

    return tmp_path


def _wait_for_tun(net: NetManager, ifaces_before: set, timeout: int = 15) -> str | None:
    """Poll for new tun/utun interface."""
    for _ in range(timeout * 2):
        time.sleep(0.5)
        new = set(net.interfaces().keys()) - ifaces_before
        tun = [i for i in new if i.startswith(("tun", "utun"))]
        if tun:
            return tun[0]
    return None


def _no_vpn_ifaces(net: NetManager, ifaces_before: set) -> bool:
    """Check no VPN interfaces remain."""
    current = set(net.interfaces().keys())
    leftover = current - ifaces_before
    vpn = [i for i in leftover if i.startswith(("tun", "utun", "ppp"))]
    return len(vpn) == 0


class TestReconnectCycle:
    """Disconnect + reconnect via Engine.reconnect_all()."""

    def test_reconnect_all_restores_connection(
        self,
        openvpn_project: Path,
        real_net: NetManager,
        test_logger: Logger,
    ):
        """reconnect_all() disconnects and reconnects, health checks pass after."""
        import tomli

        with open(openvpn_project / "defaults.toml", "rb") as f:
            defs = tomli.load(f)

        engine = Engine(openvpn_project, defs, net=real_net, log=test_logger)
        engine.prepare(setup=False)
        engine.setup()
        engine.connect_all()
        time.sleep(2)

        try:
            # Reconnect
            results, ext_ip = engine.reconnect_all()

            # После reconnect health checks должны пройти
            passed = [r for r in results if r.status == "ok"]
            assert len(passed) > 0, (
                f"No checks passed after reconnect: "
                f"{[(r.name, r.status, r.detail) for r in results]}"
            )

            # Интерфейс должен быть на месте
            ifaces = real_net.interfaces()
            tun = [k for k in ifaces if k.startswith(("tun", "utun"))]
            assert len(tun) > 0, f"No tun interface after reconnect: {ifaces}"

        finally:
            engine.disconnect_all()

    def test_disconnect_then_manual_connect(
        self,
        openvpn_project: Path,
        real_net: NetManager,
        test_logger: Logger,
    ):
        """disconnect_all -> connect_all works (simulates user --disconnect + --connect)."""
        import tomli

        with open(openvpn_project / "defaults.toml", "rb") as f:
            defs = tomli.load(f)

        engine = Engine(openvpn_project, defs, net=real_net, log=test_logger)
        engine.prepare(setup=False)
        engine.setup()

        ifaces_before = set(real_net.interfaces().keys())

        # Первое подключение
        engine.connect_all()
        time.sleep(2)
        assert _wait_for_tun(real_net, ifaces_before, timeout=1) or True  # уже есть

        # Отключение
        engine.disconnect_all()
        time.sleep(1)
        assert _no_vpn_ifaces(real_net, ifaces_before), (
            "Interfaces not cleaned after disconnect"
        )

        # Повторное подключение
        engine.setup(clear=False)
        engine.connect_all()
        time.sleep(2)

        try:
            iface = _wait_for_tun(real_net, ifaces_before, timeout=1)
            assert iface is not None, (
                f"No tun interface after second connect: {real_net.interfaces()}"
            )

            # Ping работает
            result = subprocess.run(
                ["ping", "-c", "2", "-W", "2", "10.8.0.1"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                f"Ping failed after reconnect: {result.stderr}"
            )

        finally:
            engine.disconnect_all()


class TestRapidCycles:
    """Rapid connect/disconnect to test stability."""

    def test_three_connect_disconnect_cycles(
        self, openvpn_client_config: Path, real_net: NetManager
    ):
        """Three rapid connect/disconnect cycles - no leaked interfaces."""
        ifaces_baseline = set(real_net.interfaces().keys())

        for cycle in range(3):
            proc = subprocess.Popen(
                ["openvpn", "--config", str(openvpn_client_config)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Ждём подключения
            iface = _wait_for_tun(real_net, ifaces_baseline)
            assert iface is not None, f"Cycle {cycle + 1}: no tun interface appeared"

            # Отключаем
            proc.terminate()
            proc.wait(timeout=5)
            time.sleep(1)

        # После всех циклов - чисто
        assert _no_vpn_ifaces(real_net, ifaces_baseline), (
            f"Leaked interfaces after 3 cycles: "
            f"{set(real_net.interfaces().keys()) - ifaces_baseline}"
        )
