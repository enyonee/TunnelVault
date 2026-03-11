"""IPC client: connect to daemon socket, send commands, get responses."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Optional

from tv import ipc_protocol as proto


class IPCClient:
    """Client for communicating with tunnelvault daemon via unix socket."""

    def __init__(self, socket_path: Path):
        self._socket_path = socket_path

    def is_daemon_running(self) -> bool:
        """Check if daemon is listening on socket."""
        if not self._socket_path.exists():
            return False
        try:
            with self._connect():
                return True
        except (OSError, ConnectionRefusedError):
            return False

    def send(self, cmd: str, **kwargs: Any) -> dict[str, Any]:
        """Send a command and return the response dict.

        Raises ConnectionError if daemon is not running.
        Raises TimeoutError on response timeout.
        """
        request = proto.make_request(cmd, **kwargs)
        with self._connect() as sock:
            sock.sendall(proto.encode(request))

            data = b""
            while b"\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("daemon closed connection")
                data += chunk

            return proto.decode(data)

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(proto.CLIENT_TIMEOUT)
        sock.connect(str(self._socket_path))
        return sock


def try_ipc(socket_path: Path, cmd: str, **kwargs: Any) -> Optional[dict]:
    """Try to send command via IPC. Returns response or None if daemon not running."""
    client = IPCClient(socket_path)
    if not client.is_daemon_running():
        return None
    try:
        return client.send(cmd, **kwargs)
    except (OSError, TimeoutError):
        return None
