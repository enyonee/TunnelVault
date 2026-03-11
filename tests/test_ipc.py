"""Tests for IPC protocol, server, and client."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tv import ipc_protocol as proto
from tv.ipc_server import start_server_thread
from tv.ipc_client import IPCClient, try_ipc
from tv.engine import Engine
from tv.vpn.base import TunnelConfig, TunnelPlugin, VPNResult


# =========================================================================
# Protocol
# =========================================================================


class TestProtocol:
    def test_encode_decode_roundtrip(self):
        obj = {"cmd": "status", "v": 1}
        encoded = proto.encode(obj)
        assert encoded.endswith(b"\n")
        decoded = proto.decode(encoded)
        assert decoded == obj

    def test_make_request(self):
        req = proto.make_request("reconnect", name="vpn1")
        assert req["cmd"] == "reconnect"
        assert req["v"] == proto.PROTOCOL_VERSION
        assert req["name"] == "vpn1"

    def test_make_response(self):
        resp = proto.make_response(True, data={"tunnels": []})
        assert resp["ok"] is True
        assert resp["data"] == {"tunnels": []}

    def test_make_error(self):
        err = proto.make_error("boom")
        assert err["ok"] is False
        assert err["error"] == "boom"

    def test_socket_path(self, tmp_dir):
        from tv.app_config import cfg
        path = proto.socket_path(tmp_dir)
        assert path.name == cfg.paths.socket_file
        assert path.parent.name == cfg.paths.log_dir


# =========================================================================
# Engine per-tunnel operations
# =========================================================================


class TestEnginePerTunnel:
    def test_disconnect_one(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 100
        tcfg = TunnelConfig(name="vpn1", type="openvpn")

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [VPNResult(ok=True, pid=100)]

        result = engine.disconnect_one("vpn1")

        assert result is True
        plugin.disconnect.assert_called_once()
        plugin.delete_routes.assert_called_once()
        plugin.cleanup_dns.assert_called_once()
        assert engine.results[0].ok is False

    def test_disconnect_one_not_found(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        engine.plugins = []
        engine.tunnels = []
        engine.results = []

        assert engine.disconnect_one("nope") is False

    def test_reconnect_one(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        plugin = MagicMock(spec=TunnelPlugin)
        plugin._pid = 100
        tcfg = TunnelConfig(name="vpn1", type="openvpn")

        engine.plugins = [plugin]
        engine.tunnels = [tcfg]
        engine.results = [VPNResult(ok=True, pid=100)]

        from unittest.mock import patch

        mock_new_plugin = MagicMock(spec=TunnelPlugin)
        mock_new_plugin.connect.return_value = VPNResult(ok=True, pid=200)

        with (
            patch("tv.engine.get_plugin") as mock_get,
            patch("tv.engine.time.sleep"),
        ):
            mock_get.return_value.return_value = mock_new_plugin
            result = engine.reconnect_one("vpn1")

        assert result is True
        plugin.disconnect.assert_called_once()
        mock_new_plugin.connect.assert_called_once()
        assert engine.results[0].ok is True
        assert engine.plugins[0] is mock_new_plugin

    def test_reconnect_one_not_found(self, tmp_dir, mock_net, logger):
        engine = Engine(tmp_dir, {}, net=mock_net, log=logger)
        engine.plugins = []
        engine.tunnels = []
        engine.results = []

        assert engine.reconnect_one("nope") is False


# =========================================================================
# Server + Client integration
# =========================================================================


@pytest.fixture
def ipc_setup(tmp_dir, mock_net, logger):
    """Start IPC server with a mock engine, yield client, cleanup."""
    engine = Engine(tmp_dir, {}, net=mock_net, log=logger)

    plugin = MagicMock(spec=TunnelPlugin)
    plugin._pid = 100
    tcfg = TunnelConfig(name="vpn1", type="openvpn", interface="utun3")

    engine.plugins = [plugin]
    engine.tunnels = [tcfg]
    engine.results = [VPNResult(ok=True, pid=100, detail="connected")]

    # Unix socket path limit 104 bytes on macOS - use /tmp
    import tempfile
    sock_path = Path(tempfile.mktemp(suffix=".sock", prefix="tv_test_"))
    lock = threading.Lock()

    server, thread = start_server_thread(engine, sock_path, logger, lock)
    # Дать серверу стартовать
    time.sleep(0.1)

    client = IPCClient(sock_path)
    yield engine, client, server, lock

    server.shutdown()
    thread.join(timeout=3)
    if sock_path.exists():
        sock_path.unlink()


class TestIPCIntegration:
    def test_client_detects_running_daemon(self, ipc_setup):
        _, client, *_ = ipc_setup
        assert client.is_daemon_running() is True

    def test_client_detects_no_daemon(self, tmp_dir):
        client = IPCClient(tmp_dir / "nonexistent.sock")
        assert client.is_daemon_running() is False

    def test_status_command(self, ipc_setup):
        _, client, *_ = ipc_setup
        resp = client.send("status")

        assert resp["ok"] is True
        data = resp["data"]
        assert "pid" in data
        assert "uptime" in data
        assert len(data["tunnels"]) == 1

        tunnel = data["tunnels"][0]
        assert tunnel["name"] == "vpn1"
        assert tunnel["type"] == "openvpn"
        assert tunnel["connected"] is True
        assert tunnel["pid"] == 100
        assert tunnel["interface"] == "utun3"

    def test_check_command(self, ipc_setup):
        engine, client, *_ = ipc_setup

        from unittest.mock import patch
        with patch("tv.engine.proc.is_alive", return_value=True):
            resp = client.send("check")

        assert resp["ok"] is True
        tunnels = resp["data"]["tunnels"]
        assert tunnels[0]["alive"] is True

    def test_check_detects_dead(self, ipc_setup):
        engine, client, *_ = ipc_setup

        from unittest.mock import patch
        with patch("tv.engine.proc.is_alive", return_value=False):
            resp = client.send("check")

        assert resp["ok"] is True
        tunnels = resp["data"]["tunnels"]
        assert tunnels[0]["alive"] is False

    def test_unknown_command(self, ipc_setup):
        _, client, *_ = ipc_setup
        resp = client.send("foobar")

        assert resp["ok"] is False
        assert "unknown" in resp["error"]

    def test_reconnect_command(self, ipc_setup):
        engine, client, *_ = ipc_setup

        from unittest.mock import patch
        with (
            patch.object(engine, "disconnect_all"),
            patch.object(engine, "setup"),
            patch.object(engine, "connect_all"),
            patch.object(engine, "check_all", return_value=([], "")),
            patch("tv.engine.time.sleep"),
        ):
            resp = client.send("reconnect")

        assert resp["ok"] is True
        assert "reconnected" in resp["data"]

    def test_disconnect_command(self, ipc_setup):
        engine, client, *_ = ipc_setup

        from unittest.mock import patch
        with patch.object(engine, "disconnect_all"):
            resp = client.send("disconnect")

        assert resp["ok"] is True

    def test_reconnect_one_tunnel(self, ipc_setup):
        engine, client, *_ = ipc_setup

        from unittest.mock import patch
        with patch.object(engine, "reconnect_one", return_value=True) as mock_recon:
            resp = client.send("reconnect", name="vpn1")

        assert resp["ok"] is True
        assert resp["data"]["reconnected"] == ["vpn1"]
        mock_recon.assert_called_once_with("vpn1", quiet=True)

    def test_reconnect_unknown_tunnel(self, ipc_setup):
        engine, client, *_ = ipc_setup

        from unittest.mock import patch
        with patch.object(engine, "reconnect_one", return_value=False):
            resp = client.send("reconnect", name="nonexistent")

        assert resp["ok"] is False
        assert "not found" in resp["error"]

    def test_disconnect_one_tunnel(self, ipc_setup):
        engine, client, *_ = ipc_setup

        from unittest.mock import patch
        with patch.object(engine, "disconnect_one", return_value=True) as mock_disc:
            resp = client.send("disconnect", name="vpn1")

        assert resp["ok"] is True
        assert resp["data"]["disconnected"] == "vpn1"
        mock_disc.assert_called_once_with("vpn1")

    def test_disconnect_unknown_tunnel(self, ipc_setup):
        engine, client, *_ = ipc_setup

        from unittest.mock import patch
        with patch.object(engine, "disconnect_one", return_value=False):
            resp = client.send("disconnect", name="nope")

        assert resp["ok"] is False
        assert "not found" in resp["error"]

    def test_try_ipc_returns_none_when_no_daemon(self, tmp_dir):
        resp = try_ipc(tmp_dir / "nope.sock", "status")
        assert resp is None

    def test_try_ipc_returns_response(self, ipc_setup):
        engine, client, server, _ = ipc_setup
        sock_path = server._socket_path
        resp = try_ipc(sock_path, "status")
        assert resp is not None
        assert resp["ok"] is True

    def test_multiple_sequential_commands(self, ipc_setup):
        """Server handles multiple sequential connections."""
        _, client, *_ = ipc_setup

        for _ in range(5):
            resp = client.send("status")
            assert resp["ok"] is True

    def test_reconnect_blocks_on_lock(self, ipc_setup):
        """Reconnect waits if lock is held."""
        engine, client, _, lock = ipc_setup

        # Захватим лок - reconnect должен подождать
        lock.acquire()

        def release_later():
            time.sleep(0.3)
            lock.release()

        threading.Thread(target=release_later, daemon=True).start()

        from unittest.mock import patch
        with (
            patch.object(engine, "disconnect_all"),
            patch.object(engine, "setup"),
            patch.object(engine, "connect_all"),
            patch.object(engine, "check_all", return_value=([], "")),
            patch("tv.engine.time.sleep"),
        ):
            resp = client.send("reconnect")

        assert resp["ok"] is True


# =========================================================================
# TCP fallback (Windows mode)
# =========================================================================


@pytest.fixture
def tcp_ipc_setup(tmp_dir, mock_net, logger):
    """Start IPC server in TCP mode (simulating Windows), yield client, cleanup."""
    engine = Engine(tmp_dir, {}, net=mock_net, log=logger)

    plugin = MagicMock(spec=TunnelPlugin)
    plugin._pid = 100
    tcfg = TunnelConfig(name="vpn1", type="openvpn", interface="utun3")

    engine.plugins = [plugin]
    engine.tunnels = [tcfg]
    engine.results = [VPNResult(ok=True, pid=100, detail="connected")]

    logs_dir = tmp_dir / "logs"
    logs_dir.mkdir(exist_ok=True)
    sock_path = logs_dir / "tunnelvault.sock"
    lock = threading.Lock()

    from unittest.mock import patch

    # Force TCP mode
    with patch("tv.ipc_protocol.use_unix_socket", return_value=False):
        server, thread = start_server_thread(engine, sock_path, logger, lock)
        time.sleep(0.5)

        client = IPCClient(sock_path)
        client._use_unix = False
        yield engine, client, server, lock

    server.shutdown()
    thread.join(timeout=3)


class TestIPCTcpFallback:
    def test_status_via_tcp(self, tcp_ipc_setup):
        _, client, *_ = tcp_ipc_setup
        resp = client.send("status")

        assert resp["ok"] is True
        assert len(resp["data"]["tunnels"]) == 1

    def test_check_via_tcp(self, tcp_ipc_setup):
        _, client, *_ = tcp_ipc_setup

        from unittest.mock import patch
        with patch("tv.engine.proc.is_alive", return_value=True):
            resp = client.send("check")

        assert resp["ok"] is True

    def test_tcp_port_file_created(self, tcp_ipc_setup):
        _, _, server, _ = tcp_ipc_setup
        assert server._tcp_port > 0

    def test_tcp_client_detects_no_daemon(self, tmp_dir):
        """Client returns False when no port file exists."""
        client = IPCClient(tmp_dir / "logs" / "tunnelvault.sock")
        client._use_unix = False
        assert client.is_daemon_running() is False
