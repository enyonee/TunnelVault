"""Watch: real-time VPN traffic monitoring.

Displays per-tunnel bandwidth and TCP connections using platform tools:
- macOS: ifconfig, netstat -ib, netstat -an
- Linux: ip -br addr, /proc/net/dev, ss -tn
"""

from __future__ import annotations

import platform
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

if platform.system() != "Windows":
    import termios
    import tty

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from tv.i18n import t


# --- Data types ---

@dataclass
class Connection:
    local: str
    remote: str
    state: str


@dataclass
class TunnelSnapshot:
    name: str
    interface: str
    ip: str
    bytes_in: int = 0
    bytes_out: int = 0
    rate_in: float = 0.0
    rate_out: float = 0.0
    connections: list[Connection] = field(default_factory=list)


# --- Constants ---

_VPN_PREFIXES = ("tun", "utun", "ppp")
_IS_DARWIN = platform.system() == "Darwin"
_IS_WINDOWS = platform.system() == "Windows"
_MAX_CONNECTIONS = 30

_PORT_LABELS = {
    22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5432: "PG", 5672: "AMQP",
    6379: "Redis", 8080: "HTTP", 8443: "HTTPS",
}


# --- Formatting ---

def _fmt_rate(bps: float) -> str:
    """Format bytes/sec to human-readable."""
    if bps < 1024:
        return f"{bps:.0f} B/s"
    if bps < 1048576:
        return f"{bps / 1024:.1f} KB/s"
    return f"{bps / 1048576:.1f} MB/s"


def _fmt_total(b: int) -> str:
    """Format total bytes to human-readable."""
    if b < 1024:
        return f"{b} B"
    if b < 1048576:
        return f"{b / 1024:.1f} KB"
    if b < 1073741824:
        return f"{b / 1048576:.1f} MB"
    return f"{b / 1073741824:.1f} GB"


def _port_label(addr: str) -> str:
    """Return human label for well-known port."""
    _, _, port_s = addr.rpartition(":")
    try:
        return _PORT_LABELS.get(int(port_s), "")
    except ValueError:
        return ""


class _DNSCache:
    """Non-blocking reverse DNS cache with background resolution."""

    def __init__(self, max_workers: int = 4) -> None:
        self._cache: dict[str, str | None] = {}  # ip -> hostname | None (pending)
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rdns")

    def get(self, ip: str) -> str:
        """Get hostname for IP. Returns IP immediately if not yet resolved."""
        with self._lock:
            if ip in self._cache:
                val = self._cache[ip]
                return val if val is not None else ip
            self._cache[ip] = None  # mark as pending

        self._pool.submit(self._resolve, ip)
        return ip

    def _resolve(self, ip: str) -> None:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            if len(host) > 40:
                host = host[:37] + "..."
        except (socket.herror, socket.gaierror, OSError):
            host = ip
        with self._lock:
            self._cache[ip] = host

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)


_dns_cache = _DNSCache()


def _fmt_remote(addr: str) -> str:
    """Format remote address: resolve IP to hostname if possible."""
    ip, _, port = addr.rpartition(":")
    host = _dns_cache.get(ip)
    if host != ip:
        return f"{host}:{port}"
    return addr


def _is_vpn_iface(name: str) -> bool:
    if _IS_WINDOWS:
        # On Windows, VPN adapters have names like "VPN Connection", "PPP adapter"
        # Rely on config-based matching via _resolve_names(); accept all here.
        return True
    return any(name.startswith(p) for p in _VPN_PREFIXES)


def _cmd(args: list[str], timeout: int = 5) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return subprocess.CompletedProcess(args=args, returncode=-1, stdout="", stderr="")


# --- macOS data collection ---

def _darwin_vpn_ifaces() -> dict[str, str]:
    """Get VPN interface -> IP via single ifconfig call."""
    r = _cmd(["ifconfig"])
    if r.returncode != 0:
        return {}
    result = {}
    current: Optional[str] = None
    for line in r.stdout.splitlines():
        if line and not line[0].isspace() and ":" in line:
            name = line.split(":")[0]
            current = name if _is_vpn_iface(name) else None
        elif current and "\tinet " in line:
            parts = line.strip().split()
            try:
                result[current] = parts[parts.index("inet") + 1]
            except (ValueError, IndexError):
                pass
            current = None
    return result


def _darwin_iface_bytes() -> dict[str, tuple[int, int]]:
    """Get (bytes_in, bytes_out) for VPN interfaces via netstat -ib."""
    r = _cmd(["netstat", "-ib"])
    if r.returncode != 0:
        return {}
    result = {}
    for line in r.stdout.splitlines():
        if "<Link#" not in line:
            continue
        parts = line.split()
        # Link line: Name Mtu <Link#N> Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
        # Find the <Link#> column to anchor the offsets
        name = parts[0] if parts else ""
        if not _is_vpn_iface(name):
            continue
        try:
            link_idx = next(i for i, p in enumerate(parts) if "<Link#" in p)
            # Ibytes = link_idx + 3, Obytes = link_idx + 6
            result[name] = (int(parts[link_idx + 3]), int(parts[link_idx + 6]))
        except (ValueError, IndexError, StopIteration):
            pass
    return result


def _darwin_connections(local_ips: set[str]) -> list[Connection]:
    """Get TCP connections filtered by VPN local IPs."""
    r = _cmd(["netstat", "-an", "-f", "inet", "-p", "tcp"])
    if r.returncode != 0:
        return []
    conns = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] != "tcp4":
            continue
        state = parts[5]
        if state in ("LISTEN", "CLOSED"):
            continue
        # macOS format: 10.8.0.22.54108 (IP.port, last dot separates port)
        local_raw = parts[3]
        lip, _, lport = local_raw.rpartition(".")
        if lip not in local_ips:
            continue
        remote_raw = parts[4]
        rip, _, rport = remote_raw.rpartition(".")
        conns.append(Connection(
            local=f"{lip}:{lport}",
            remote=f"{rip}:{rport}",
            state=state[:5],
        ))
    return conns


# --- Linux data collection ---

def _linux_vpn_ifaces() -> dict[str, str]:
    """Get VPN interface -> IP via ip command."""
    r = _cmd(["ip", "-br", "addr"])
    if r.returncode != 0:
        return {}
    result = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            name = parts[0]
            if _is_vpn_iface(name):
                addr = parts[2].split("/")[0] if "/" in parts[2] else parts[2]
                result[name] = addr
    return result


def _linux_iface_bytes() -> dict[str, tuple[int, int]]:
    """Get (bytes_in, bytes_out) for VPN interfaces from /proc/net/dev."""
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()
    except OSError:
        return {}
    result = {}
    for line in lines:
        stripped = line.strip()
        idx = stripped.find(":")
        if idx < 0:
            continue
        name = stripped[:idx].strip()
        if not _is_vpn_iface(name):
            continue
        nums = stripped[idx + 1:].split()
        # rx_bytes(0) ... tx_bytes(8)
        if len(nums) >= 9:
            try:
                result[name] = (int(nums[0]), int(nums[8]))
            except (ValueError, IndexError):
                pass
    return result


def _linux_connections(local_ips: set[str]) -> list[Connection]:
    """Get TCP connections filtered by VPN local IPs."""
    r = _cmd(["ss", "-tn"])
    if r.returncode != 0:
        return []
    conns = []
    for line in r.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        local_raw = parts[3]
        remote_raw = parts[4]
        lip = local_raw.rsplit(":", 1)[0]
        if lip not in local_ips:
            continue
        conns.append(Connection(
            local=local_raw,
            remote=remote_raw,
            state=state[:5],
        ))
    return conns


# --- Windows data collection ---

def _windows_vpn_ifaces() -> dict[str, str]:
    """Get interface -> IP via PowerShell Get-NetIPAddress (locale-safe)."""
    r = _cmd(["powershell", "-Command",
              "Get-NetIPAddress -AddressFamily IPv4 | "
              "Select-Object InterfaceAlias, IPAddress | "
              "Format-Table -HideTableHeaders"])
    if r.returncode != 0:
        return {}
    result = {}
    for line in r.stdout.splitlines():
        parts = line.strip().rsplit(None, 1)
        if len(parts) == 2:
            name, ip = parts
            name = name.strip()
            if name and ip and not ip.startswith("127."):
                result[name] = ip
    return result


def _windows_iface_bytes() -> dict[str, tuple[int, int]]:
    """Get (bytes_in, bytes_out) via PowerShell Get-NetAdapterStatistics."""
    r = _cmd(["powershell", "-Command",
              "Get-NetAdapterStatistics | "
              "Select-Object Name, ReceivedBytes, SentBytes | "
              "Format-Table -HideTableHeaders"])
    if r.returncode != 0:
        return {}
    result = {}
    for line in r.stdout.splitlines():
        parts = line.strip().rsplit(None, 2)
        if len(parts) == 3:
            name, rx, tx = parts
            try:
                result[name.strip()] = (int(rx), int(tx))
            except ValueError:
                pass
    return result


def _windows_connections(local_ips: set[str]) -> list[Connection]:
    """Get TCP connections via netstat -an (locale-safe)."""
    r = _cmd(["netstat", "-an", "-p", "TCP"])
    if r.returncode != 0:
        return []
    conns = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "TCP":
            continue
        state = parts[3] if len(parts) > 3 else ""
        if state in ("LISTENING", "LISTEN", "CLOSED"):
            continue
        local_raw = parts[1]
        remote_raw = parts[2]
        lip = local_raw.rsplit(":", 1)[0]
        if lip not in local_ips:
            continue
        conns.append(Connection(
            local=local_raw,
            remote=remote_raw,
            state=state[:5],
        ))
    return conns


# --- Display ---

def _build_display(
    snapshots: list[TunnelSnapshot],
    ts: datetime,
    poll_ms: float = 0,
) -> Panel:
    """Build the full watch display panel."""
    renderables: list = []

    # Bandwidth table
    bw = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
        expand=True,
    )
    bw.add_column("Tunnel", style="bold white", ratio=2)
    bw.add_column("Iface", style="dim", ratio=1)
    bw.add_column("↓ In", style="green", justify="right", ratio=1)
    bw.add_column("↑ Out", style="cyan", justify="right", ratio=1)
    bw.add_column("Total", style="dim", justify="right", ratio=1)

    if snapshots:
        for s in snapshots:
            bw.add_row(
                s.name, s.interface,
                _fmt_rate(s.rate_in), _fmt_rate(s.rate_out),
                _fmt_total(s.bytes_in + s.bytes_out),
            )
    else:
        bw.add_row(f"[dim italic]{t('watch.no_active_vpn')}", "", "", "", "")

    renderables.append(
        Panel(bw, title=f"[bold]{t('watch.traffic')}[/bold]", border_style="blue")
    )

    # Connections per tunnel
    for s in snapshots:
        ct = Table(box=None, show_header=False, padding=(0, 1), expand=True)
        ct.add_column("Local", min_width=21)
        ct.add_column("", width=1, style="dim")
        ct.add_column("Remote", min_width=21)
        ct.add_column("State", width=5)
        ct.add_column("Proto", style="dim", width=6)

        shown = s.connections[:_MAX_CONNECTIONS]
        if shown:
            for c in shown:
                st = "green" if "ESTAB" in c.state else "yellow"
                remote_display = _fmt_remote(c.remote)
                ct.add_row(
                    c.local, "→",
                    f"[yellow]{remote_display}[/yellow]",
                    f"[{st}]{c.state}[/{st}]",
                    _port_label(c.remote),
                )
            if len(s.connections) > _MAX_CONNECTIONS:
                ct.add_row(
                    f"[dim]{t('watch.more_connections', count=len(s.connections) - _MAX_CONNECTIONS)}",
                    "", "", "", "",
                )
        else:
            ct.add_row(f"[dim italic]{t('watch.no_connections')}", "", "", "", "")

        title = f"[bold]{s.name}[/bold] [dim]({s.interface} {s.ip})[/dim]"
        n = len(s.connections)
        sub = f"[dim]{n}[/dim]" if n else None
        renderables.append(
            Panel(ct, title=title, subtitle=sub, border_style="dim")
        )

    n_tunnels = len(snapshots)
    n_conns = sum(len(s.connections) for s in snapshots)
    title = (
        f"[bold bright_blue]tunnelvault watch[/bold bright_blue]"
        f"  [dim]{ts.strftime('%H:%M:%S')} │ {n_tunnels} tunnels │ {n_conns} conn │ {poll_ms:.0f}ms │ {t('watch.exit_hint')}[/dim]"
    )

    panel = Panel(
        Group(*renderables),
        title=title,
        border_style="bright_blue",
        padding=(0, 1),
    )

    return panel


# --- Main loop ---

def _resolve_names(
    vpn_ifaces: dict[str, str],
    exact: dict[str, str],
    prefix: dict[str, str],
    show_all: bool,
) -> dict[str, str]:
    """Map interface -> tunnel name. One profile = one interface.

    Returns {interface: display_name} for interfaces to show.
    """
    result: dict[str, str] = {}
    assigned_names: set[str] = set()

    # 1. Exact matches (configured interface, e.g. singbox -> utun99)
    for iface in vpn_ifaces:
        if iface in exact:
            result[iface] = exact[iface]
            assigned_names.add(exact[iface])

    # 2. Prefix matches: first unmatched interface wins per profile
    remaining = sorted(set(vpn_ifaces) - set(result))
    for iface in remaining:
        for pfx, name in prefix.items():
            if iface.startswith(pfx) and name not in assigned_names:
                result[iface] = name
                assigned_names.add(name)
                break

    # 3. --all: show remaining as raw interface names
    if show_all:
        for iface in vpn_ifaces:
            if iface not in result:
                result[iface] = iface

    return result


def run(
    exact_names: Optional[dict[str, str]] = None,
    prefix_names: Optional[dict[str, str]] = None,
    show_all: bool = False,
) -> None:
    """Run real-time VPN traffic monitor.

    Args:
        exact_names: {interface: tunnel_name} for tunnels with configured interface.
        prefix_names: {prefix: tunnel_name} for tunnels with dynamic interface.
        show_all: Show all VPN interfaces, not just configured ones.
    """
    if exact_names is None:
        exact_names = {}
    if prefix_names is None:
        prefix_names = {}
    has_config = bool(exact_names or prefix_names)

    if _IS_WINDOWS:
        get_ifaces = _windows_vpn_ifaces
        get_bytes = _windows_iface_bytes
        get_conns = _windows_connections
    elif _IS_DARWIN:
        get_ifaces = _darwin_vpn_ifaces
        get_bytes = _darwin_iface_bytes
        get_conns = _darwin_connections
    else:
        get_ifaces = _linux_vpn_ifaces
        get_bytes = _linux_iface_bytes
        get_conns = _linux_connections

    console = Console()
    prev_bytes: dict[str, tuple[int, int]] = {}
    prev_time: Optional[float] = None

    data_pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="watch")

    # Suppress mouse scroll escape sequences in alternate screen
    _old_termios = None
    fd = None
    if not _IS_WINDOWS:
        try:
            fd = sys.stdin.fileno()
            _old_termios = termios.tcgetattr(fd)
            tty.setcbreak(fd)
        except (ValueError, termios.error, OSError):
            pass

    try:
        loading = Panel(
            Text(f"  {t('watch.loading')}...", style="dim italic", justify="center"),
            title=f"[bold bright_blue]tunnelvault watch[/bold bright_blue]  [dim]{t('watch.exit_hint')}[/dim]",
            border_style="bright_blue",
            padding=(1, 2),
        )
        with Live(loading, console=console, refresh_per_second=1, screen=True) as live:
            while True:
                now = time.monotonic()
                ts = datetime.now()

                # Run data collection in parallel
                t0 = time.monotonic()
                f_ifaces = data_pool.submit(get_ifaces)
                f_bytes = data_pool.submit(get_bytes)
                vpn_ifaces = f_ifaces.result(timeout=5)
                all_bytes = f_bytes.result(timeout=5)
                vpn_ips = set(vpn_ifaces.values())
                all_conns = get_conns(vpn_ips)
                poll_ms = (time.monotonic() - t0) * 1000

                named = _resolve_names(vpn_ifaces, exact_names, prefix_names, show_all or not has_config)

                snapshots = []
                for iface, ip in sorted(vpn_ifaces.items()):
                    if iface not in named:
                        continue
                    name = named[iface]
                    b_in, b_out = all_bytes.get(iface, (0, 0))

                    rate_in = rate_out = 0.0
                    if prev_time is not None and iface in prev_bytes:
                        dt = now - prev_time
                        if dt > 0:
                            p_in, p_out = prev_bytes[iface]
                            rate_in = max(0.0, (b_in - p_in) / dt)
                            rate_out = max(0.0, (b_out - p_out) / dt)
                    prev_bytes[iface] = (b_in, b_out)

                    iface_conns = [
                        c for c in all_conns
                        if c.local.rsplit(":", 1)[0] == ip
                    ]

                    snapshots.append(TunnelSnapshot(
                        name=name, interface=iface, ip=ip,
                        bytes_in=b_in, bytes_out=b_out,
                        rate_in=rate_in, rate_out=rate_out,
                        connections=iface_conns,
                    ))

                prev_time = now
                live.update(_build_display(snapshots, ts, poll_ms=poll_ms))
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        data_pool.shutdown(wait=False)
        _dns_cache.shutdown()
        if _old_termios is not None and fd is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, _old_termios)
            except (termios.error, OSError):
                pass
