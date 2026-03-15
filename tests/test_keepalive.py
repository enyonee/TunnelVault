"""Tests for keepalive mode: check_alive, reconnect_all, _keepalive_loop."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tv.engine import Engine
from tv.vpn.base import TunnelConfig, TunnelPlugin, VPNResult
from tv.checks import CheckResult


# =========================================================================
# Engine.check_alive
# =========================================================================


class TestCheckAlive:
    def test_all_alive_returns_empty(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 100
        tcfg = TunnelConfig(name="vpn1", type="openvpn")
        result = VPNResult(ok=True, pid=100)

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [result]

        with patch("tv.engine.proc.is_alive", return_value=True):
            dead = engine.check_alive()

        assert dead == []

    def test_dead_process_detected(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 200
        tcfg = TunnelConfig(name="vpn1", type="openvpn")
        result = VPNResult(ok=True, pid=200)

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [result]

        with patch("tv.engine.proc.is_alive", return_value=False):
            dead = engine.check_alive()

        assert len(dead) == 1
        assert dead[0][0].name == "vpn1"
        assert dead[0][1] == 200

    def test_failed_result_not_checked(self, tmp_dir, mock_net, logger):
        """Tunnel that failed to connect is not checked."""
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 300
        tcfg = TunnelConfig(name="vpn1", type="openvpn")
        result = VPNResult(ok=False, pid=300)

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [result]

        with patch("tv.engine.proc.is_alive") as mock_alive:
            dead = engine.check_alive()

        mock_alive.assert_not_called()
        assert dead == []

    def test_no_pid_not_checked(self, tmp_dir, mock_net, logger):
        """Tunnel without PID (e.g. Tunnelblick) is not checked."""
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = None
        tcfg = TunnelConfig(name="vpn1", type="openvpn")
        result = VPNResult(ok=True, pid=None)

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [result]

        with patch("tv.engine.proc.is_alive") as mock_alive:
            dead = engine.check_alive()

        mock_alive.assert_not_called()
        assert dead == []

    def test_mixed_alive_and_dead(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin1 = MagicMock(spec=TunnelPlugin)
        plugin1._pid = 100
        plugin2 = MagicMock(spec=TunnelPlugin)
        plugin2._pid = 200

        tcfg1 = TunnelConfig(name="alive", type="openvpn")
        tcfg2 = TunnelConfig(name="dead", type="singbox")

        engine.plugins = [plugin1, plugin2]
        engine.tunnels = [tcfg1, tcfg2]
        engine.results = [VPNResult(ok=True, pid=100), VPNResult(ok=True, pid=200)]

        def alive_check(pid):
            return pid == 100

        with patch("tv.engine.proc.is_alive", side_effect=alive_check):
            dead = engine.check_alive()

        assert len(dead) == 1
        assert dead[0][0].name == "dead"


# =========================================================================
# Engine.reconnect_all
# =========================================================================


class TestReconnectAll:
    def test_calls_disconnect_setup_connect_check(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        engine.tunnels = [TunnelConfig(name="t", type="openvpn")]
        engine.results = [VPNResult(ok=True)]

        with (
            patch.object(engine, "disconnect_all") as mock_disc,
            patch.object(engine, "wait_for_network", return_value=True),
            patch.object(engine, "setup") as mock_setup,
            patch.object(engine, "connect_all") as mock_conn,
            patch.object(engine, "check_all", return_value=([], "")) as mock_check,
            patch("tv.engine.time.sleep"),
        ):
            engine.reconnect_all()

        mock_disc.assert_called_once()
        mock_setup.assert_called_once_with(clear=False, quiet=True)
        mock_conn.assert_called_once_with(quiet=True)
        mock_check.assert_called_once_with(quiet=True)

    def test_returns_check_results(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)

        fake_results = [CheckResult("test", "ok", "ok")]
        with (
            patch.object(engine, "disconnect_all"),
            patch.object(engine, "wait_for_network", return_value=True),
            patch.object(engine, "setup"),
            patch.object(engine, "connect_all"),
            patch.object(engine, "check_all", return_value=(fake_results, "1.2.3.4")),
            patch("tv.engine.time.sleep"),
        ):
            results, ext_ip = engine.reconnect_all()

        assert results == fake_results
        assert ext_ip == "1.2.3.4"

    def test_pause_between_disconnect_and_setup(self, tmp_dir, mock_net, logger):
        """There's a pause between disconnect and setup for cleanup."""
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        call_order = []

        with (
            patch.object(
                engine, "disconnect_all", side_effect=lambda: call_order.append("disc")
            ),
            patch.object(
                engine,
                "wait_for_network",
                side_effect=lambda: (call_order.append("net_wait"), True)[-1],
            ),
            patch.object(
                engine, "setup", side_effect=lambda **kw: call_order.append("setup")
            ),
            patch.object(
                engine,
                "connect_all",
                side_effect=lambda **kw: call_order.append("conn"),
            ),
            patch.object(engine, "check_all", return_value=([], "")),
            patch(
                "tv.engine.time.sleep",
                side_effect=lambda s: call_order.append(f"sleep:{s}"),
            ),
        ):
            engine.reconnect_all()

        assert call_order[0] == "disc"
        assert call_order[1].startswith("sleep:")
        assert call_order[2] == "net_wait"
        assert call_order[3] == "setup"
        assert call_order[4] == "conn"

    def test_raises_when_network_unavailable(self, tmp_dir, mock_net, logger):
        """reconnect_all raises RuntimeError if network doesn't come back."""
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)

        with (
            patch.object(engine, "disconnect_all"),
            patch.object(engine, "wait_for_network", return_value=False),
            patch("tv.engine.time.sleep"),
            pytest.raises(RuntimeError, match="Network not available"),
        ):
            engine.reconnect_all()


class TestWaitForNetwork:
    def test_returns_true_when_gateway_available(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        mock_net.default_gateway.return_value = "192.168.1.1"

        result = engine.wait_for_network()

        assert result is True
        mock_net.default_gateway.assert_called_once()

    def test_waits_until_gateway_appears(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        mock_net.default_gateway.side_effect = [None, None, "10.0.0.1"]

        with (
            patch("tv.engine.time.sleep"),
            patch("tv.engine.time.monotonic") as mock_mono,
        ):
            mock_mono.side_effect = [0.0, 2.0, 4.0, 6.0]
            result = engine.wait_for_network()

        assert result is True
        assert mock_net.default_gateway.call_count == 3

    def test_returns_false_on_timeout(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        mock_net.default_gateway.return_value = None

        with (
            patch("tv.engine.time.sleep"),
            patch("tv.engine.time.monotonic") as mock_mono,
        ):
            # Сразу за пределами deadline
            mock_mono.side_effect = [0.0, 31.0]
            result = engine.wait_for_network()

        assert result is False


# =========================================================================
# _keepalive_loop
# =========================================================================


class TestKeepaliveLoop:
    def test_reconnects_on_dead_process(self, tmp_dir, mock_net, logger):
        """Dead process triggers reconnect."""
        from tunnelvault import _keepalive_loop

        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 100
        tcfg = TunnelConfig(name="vpn1", type="openvpn")

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [VPNResult(ok=True, pid=100)]

        call_count = 0

        def fake_sleep(interval):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                raise KeyboardInterrupt  # exit loop after one iteration

        with (
            patch("tunnelvault.time.sleep", side_effect=fake_sleep),
            patch("tv.engine.proc.is_alive", return_value=False),
            patch("tunnelvault.time.monotonic", side_effect=[0.0, 30.0, 30.0]),
            patch.object(engine, "reconnect_all", return_value=([], "")) as mock_recon,
            pytest.raises(KeyboardInterrupt),
        ):
            _keepalive_loop(engine)

        mock_recon.assert_called_once()

    def test_no_reconnect_when_all_alive(self, tmp_dir, mock_net, logger):
        """All alive - no reconnect."""
        from tunnelvault import _keepalive_loop

        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 100
        tcfg = TunnelConfig(name="vpn1", type="openvpn")

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [VPNResult(ok=True, pid=100)]

        call_count = 0

        def fake_sleep(interval):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                raise KeyboardInterrupt

        with (
            patch("tunnelvault.time.sleep", side_effect=fake_sleep),
            patch("tv.engine.proc.is_alive", return_value=True),
            patch("tunnelvault.time.monotonic", side_effect=[0.0, 30.0, 30.0]),
            patch.object(engine, "reconnect_all") as mock_recon,
            pytest.raises(KeyboardInterrupt),
        ):
            _keepalive_loop(engine)

        mock_recon.assert_not_called()

    def test_reconnects_on_sleep_detected(self, tmp_dir, mock_net, logger):
        """Time gap > 2x interval triggers reconnect (sleep detection)."""
        from tunnelvault import _keepalive_loop

        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 100
        tcfg = TunnelConfig(name="vpn1", type="openvpn")

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [VPNResult(ok=True, pid=100)]

        call_count = 0

        def fake_sleep(interval):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                raise KeyboardInterrupt

        # monotonic: 0, then 300 (5 min gap = system slept)
        with (
            patch("tunnelvault.time.sleep", side_effect=fake_sleep),
            patch("tv.engine.proc.is_alive", return_value=True),
            patch("tunnelvault.time.monotonic", side_effect=[0.0, 300.0, 300.0]),
            patch.object(engine, "reconnect_all", return_value=([], "")) as mock_recon,
            pytest.raises(KeyboardInterrupt),
        ):
            _keepalive_loop(engine)

        mock_recon.assert_called_once()

    def test_reconnect_failure_continues_loop(self, tmp_dir, mock_net, logger):
        """Reconnect failure logs error, updates cooldown, and continues loop."""
        from tunnelvault import _keepalive_loop

        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 100
        tcfg = TunnelConfig(name="vpn1", type="openvpn")

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [VPNResult(ok=True, pid=100)]

        sleep_count = 0

        def fake_sleep(interval):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count > 2:
                raise KeyboardInterrupt

        # monotonic: dead detected → reconnect fails → continue loop (cooldown active) → exit
        # First iteration: 0→30 (dead, reconnect fail)
        # Second iteration: 30→32 (dead, but cooldown: 5s - 2s = 3s remaining)
        # Third sleep → exit
        mono_values = [0.0, 30.0, 30.0, 32.0, 32.0]
        with (
            patch("tunnelvault.time.sleep", side_effect=fake_sleep),
            patch("tv.engine.proc.is_alive", return_value=False),
            patch("tunnelvault.time.monotonic", side_effect=mono_values),
            patch.object(
                engine, "reconnect_all", side_effect=RuntimeError("network down")
            ) as mock_recon,
            pytest.raises(KeyboardInterrupt),
        ):
            _keepalive_loop(engine)

        # Reconnect attempted once, then blocked by cooldown even after failure
        assert mock_recon.call_count == 1

    def test_reconnect_debounce(self, tmp_dir, mock_net, logger):
        """Multiple wake events within cooldown window trigger only one reconnect."""
        from tunnelvault import _keepalive_loop

        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 100
        tcfg = TunnelConfig(name="vpn1", type="openvpn")

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [VPNResult(ok=True, pid=100)]

        sleep_count = 0

        def fake_sleep(interval):
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count > 3:
                raise KeyboardInterrupt

        # First sleep gap → reconnect
        # Second sleep gap 2s later (within 5s cooldown) → skip
        # Third iteration → exit
        mono_values = [
            0.0,
            300.0,  # first wake (elapsed=300s)
            300.0,  # after reconnect
            302.0,  # second wake (elapsed=2s, but gap detected)
            302.0,  # cooldown skip
            362.0,  # normal tick
        ]
        with (
            patch("tunnelvault.time.sleep", side_effect=fake_sleep),
            patch("tv.engine.proc.is_alive", return_value=True),
            patch("tunnelvault.time.monotonic", side_effect=mono_values),
            patch.object(engine, "reconnect_all", return_value=([], "")) as mock_recon,
            pytest.raises(KeyboardInterrupt),
        ):
            _keepalive_loop(engine)

        # Only first reconnect executed, second skipped due to cooldown
        assert mock_recon.call_count == 1
