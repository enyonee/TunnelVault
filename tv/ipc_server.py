"""IPC server: unix socket listener, dispatches commands to Engine."""

from __future__ import annotations

import os
import select
import socket
import threading
import time
from pathlib import Path
from typing import Optional

from tv import ipc_protocol as proto
from tv.engine import Engine
from tv.logger import Logger


class IPCServer:
    """Unix socket server that exposes Engine state via JSON-line protocol.

    Runs in a daemon thread alongside the keepalive loop.
    Read-only commands (status, check) don't need a lock.
    Mutating commands (reconnect, disconnect) acquire reconnect_lock.
    """

    def __init__(
        self,
        engine: Engine,
        socket_path: Path,
        log: Logger,
        reconnect_lock: Optional[threading.Lock] = None,
    ):
        self._engine = engine
        self._socket_path = socket_path
        self._log = log
        self._reconnect_lock = reconnect_lock
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._started = time.monotonic()

    def serve_forever(self) -> None:
        """Bind unix socket and accept connections until shutdown()."""
        self._cleanup_stale_socket()

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setblocking(False)

        try:
            self._sock.bind(str(self._socket_path))
            # Доступ для обычного юзера (status без sudo)
            os.chmod(str(self._socket_path), 0o666)
            self._sock.listen(5)
            self._log.log("INFO", f"IPC server listening on {self._socket_path}")
        except OSError as e:
            self._log.log("ERROR", f"IPC server bind failed: {e}")
            return

        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([self._sock], [], [], 1.0)
            except (OSError, ValueError):
                break

            if not ready:
                continue

            try:
                conn, _ = self._sock.accept()
            except OSError:
                break

            try:
                self._handle_client(conn)
            except Exception as e:
                self._log.log("WARN", f"IPC client error: {e}")
            finally:
                conn.close()

        self._cleanup()

    def shutdown(self) -> None:
        """Signal the server to stop."""
        self._stop.set()

    def _cleanup_stale_socket(self) -> None:
        """Remove leftover socket file from previous crash."""
        if self._socket_path.exists():
            try:
                self._socket_path.unlink()
                self._log.log("INFO", f"Removed stale socket: {self._socket_path}")
            except OSError:
                pass

    def _cleanup(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._socket_path.exists():
            try:
                self._socket_path.unlink()
            except OSError:
                pass

    def _handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(proto.SERVER_CLIENT_TIMEOUT)

        try:
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
                if len(data) > 65536:
                    conn.sendall(proto.encode(proto.make_error("request too large")))
                    return
        except socket.timeout:
            conn.sendall(proto.encode(proto.make_error("timeout")))
            return

        try:
            request = proto.decode(data)
        except (ValueError, KeyError):
            conn.sendall(proto.encode(proto.make_error("invalid JSON")))
            return

        response = self._dispatch(request)
        conn.sendall(proto.encode(response))

    def _dispatch(self, request: dict) -> dict:
        cmd = request.get("cmd")
        if cmd not in proto.COMMANDS:
            return proto.make_error(f"unknown command: {cmd}")

        handlers = {
            "status": self._cmd_status,
            "check": self._cmd_check,
            "reconnect": self._cmd_reconnect,
            "disconnect": self._cmd_disconnect,
        }

        try:
            return handlers[cmd](request)
        except Exception as e:
            self._log.log("ERROR", f"IPC command '{cmd}' failed: {e}")
            return proto.make_error(str(e))

    def _cmd_status(self, _request: dict) -> dict:
        engine = self._engine
        tunnels = []
        for tcfg, plugin, result in zip(
            engine.tunnels, engine.plugins, engine.results
        ):
            tunnels.append({
                "name": tcfg.name,
                "type": tcfg.type,
                "connected": result.ok,
                "pid": plugin._pid,
                "interface": tcfg.interface or "",
                "detail": result.detail or "",
            })

        return proto.make_response(True, data={
            "pid": os.getpid(),
            "uptime": int(time.monotonic() - self._started),
            "tunnels": tunnels,
        })

    def _cmd_check(self, _request: dict) -> dict:
        engine = self._engine
        dead = engine.check_alive()
        tunnels = []
        for tcfg, plugin, result in zip(
            engine.tunnels, engine.plugins, engine.results
        ):
            is_dead = any(tc.name == tcfg.name for tc, _ in dead)
            tunnels.append({
                "name": tcfg.name,
                "alive": result.ok and not is_dead,
                "pid": plugin._pid,
            })

        return proto.make_response(True, data={"tunnels": tunnels})

    def _cmd_reconnect(self, request: dict) -> dict:
        name = request.get("name")
        lock = self._reconnect_lock

        if lock and not lock.acquire(timeout=30):
            return proto.make_error("reconnect in progress, try later")

        try:
            if name:
                ok = self._engine.reconnect_one(name, quiet=True)
                if not ok:
                    return proto.make_error(f"tunnel not found: {name}")
                return proto.make_response(True, data={"reconnected": [name]})

            self._engine.reconnect_all(quiet=True)
            names = [tc.name for tc, r in zip(
                self._engine.tunnels, self._engine.results
            ) if r.ok]
            return proto.make_response(True, data={"reconnected": names})
        except Exception as e:
            return proto.make_error(f"reconnect failed: {e}")
        finally:
            if lock and lock.locked():
                lock.release()

    def _cmd_disconnect(self, request: dict) -> dict:
        name = request.get("name")
        lock = self._reconnect_lock

        if lock and not lock.acquire(timeout=30):
            return proto.make_error("operation in progress, try later")

        try:
            if name:
                ok = self._engine.disconnect_one(name)
                if not ok:
                    return proto.make_error(f"tunnel not found: {name}")
                return proto.make_response(True, data={"disconnected": name})

            self._engine.disconnect_all()
            return proto.make_response(True, data={"disconnected": "all"})
        except Exception as e:
            return proto.make_error(f"disconnect failed: {e}")
        finally:
            if lock and lock.locked():
                lock.release()


def start_server_thread(
    engine: Engine,
    socket_path: Path,
    log: Logger,
    reconnect_lock: Optional[threading.Lock] = None,
) -> tuple[IPCServer, threading.Thread]:
    """Start IPC server in a daemon thread. Returns (server, thread)."""
    server = IPCServer(engine, socket_path, log, reconnect_lock)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="ipc-server")
    thread.start()
    return server, thread
