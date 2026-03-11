"""UDP DNS proxy with host route injection for bypass domains.

Intercepts DNS queries for configured domain suffixes, forwards them to
upstream DNS, extracts A-record IPs, and injects host routes through the
default gateway so traffic bypasses VPN.
"""

from __future__ import annotations

import socket
import threading
from typing import TYPE_CHECKING, Optional

from dnslib import DNSRecord, QTYPE

if TYPE_CHECKING:
    from tv.logger import Logger
    from tv.net import NetManager


_DNS_BUF_SIZE = 4096  # Standard EDNS0 UDP buffer


class BypassDNSProxy:
    """UDP DNS proxy that injects host routes for bypass domain suffixes."""

    def __init__(
        self,
        suffixes: list[str],
        upstream_dns: str,
        net: NetManager,
        logger: Logger,
        gateway: str,
        *,
        bind: str = "127.0.0.1",
        port: int = 53,
    ) -> None:
        self._suffixes = [s.lower().rstrip(".") for s in suffixes]
        self._upstream = upstream_dns
        self._net = net
        self._log = logger
        self._gw = gateway
        self._bind = bind
        self._port = port

        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._injected: set[str] = set()
        self._lock = threading.Lock()

    def start(self) -> None:
        """Bind UDP socket and start serving in a daemon thread."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind((self._bind, self._port))

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve,
            name="dns-bypass-proxy",
            daemon=True,
        )
        self._thread.start()
        self._log.log("INFO", f"DNS bypass proxy started on {self._bind}:{self._port}")

    def stop(self) -> None:
        """Signal shutdown, close socket, wait for thread."""
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None
        self._log.log("INFO", "DNS bypass proxy stopped")

    def restart_thread(self) -> None:
        """Restart serving thread on existing socket (e.g. after fork).

        The socket survives fork but the thread does not.
        Safe to call only when the old thread is dead (e.g. post-fork).
        """
        if self._sock is None:
            return
        if self._thread is not None and self._thread.is_alive():
            self._log.log(
                "WARN", "DNS proxy restart_thread: thread still alive, skipping"
            )
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve,
            name="dns-bypass-proxy",
            daemon=True,
        )
        self._thread.start()
        self._log.log("INFO", "DNS bypass proxy thread restarted (post-fork)")

    def injected_routes(self) -> set[str]:
        """Return copy of all IPs that got host routes injected."""
        with self._lock:
            return set(self._injected)

    def _matches(self, qname: str) -> bool:
        """Check if query name matches any configured suffix."""
        name = qname.lower().rstrip(".")
        for suffix in self._suffixes:
            bare = suffix.lstrip(".")
            if name == bare or name.endswith("." + bare):
                return True
        return False

    def _serve(self) -> None:
        """Main recv loop - runs in daemon thread."""
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(_DNS_BUF_SIZE)
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                continue

            try:
                self._handle(data, addr)
            except Exception as exc:
                self._log.log("WARN", f"DNS proxy handle error: {exc}")

    def _handle(self, data: bytes, addr: tuple) -> None:
        """Parse query, forward to upstream, inject routes, reply."""
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)

        # Forward to upstream regardless of match
        reply_data = self._forward(data)
        if reply_data is None:
            return

        # If query matches a bypass suffix, extract IPs and inject routes
        if self._matches(qname):
            try:
                reply = DNSRecord.parse(reply_data)
                for rr in reply.rr:
                    if rr.rtype == QTYPE.A:
                        ip = str(rr.rdata)
                        self._inject_route(ip, qname)
            except Exception as exc:
                self._log.log("WARN", f"DNS proxy parse reply error: {exc}")

        # Send reply back to client
        sock = self._sock
        if sock and not self._stop_event.is_set():
            try:
                sock.sendto(reply_data, addr)
            except OSError:
                pass  # socket closed by stop() between check and send

    def _forward(self, data: bytes) -> Optional[bytes]:
        """Forward raw DNS packet to upstream and return response."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3.0)
                s.sendto(data, (self._upstream, 53))
                reply, _ = s.recvfrom(_DNS_BUF_SIZE)
                return reply
        except (socket.timeout, OSError) as exc:
            self._log.log("WARN", f"DNS upstream {self._upstream} timeout: {exc}")
            return None

    def _inject_route(self, ip: str, qname: str) -> None:
        """Add host route for IP if not already injected."""
        with self._lock:
            if ip in self._injected:
                return
            ok = self._net.add_host_route(ip, self._gw)
            if ok:
                self._injected.add(ip)
            self._log.log(
                "INFO" if ok else "WARN",
                f"DNS bypass route {ip} ({qname}) -> {self._gw} {'OK' if ok else 'FAIL'}",
            )
