"""Platform-aware networking: routes, interfaces, DNS, gateway."""

from __future__ import annotations

import platform
import re
import shutil
import socket
import subprocess
from abc import ABC, abstractmethod
from typing import Optional

from tv.app_config import cfg

IS_WINDOWS = platform.system() == "Windows"


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run with default timeout."""
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", cfg.timeouts.net_command)
    try:
        return subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args=cmd, returncode=-1, stdout="", stderr="timeout"
        )


# macOS ignores 0.0.0.0/1 and 128.0.0.0/1 routes for normal app traffic.
# Split into specific subnets like sing-box auto_route does.
_CATCHALL_SPLIT: dict[str, list[str]] = {
    "0.0.0.0/1": [
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
    ],
    "128.0.0.0/1": ["128.0.0.0/1"],
}


def _split_catchall(network: str) -> list[str] | None:
    """Split 0.0.0.0/1 into specific subnets. Returns None if no split needed."""
    return _CATCHALL_SPLIT.get(network)


class NetManager(ABC):
    """Abstract network manager. Implementations for Darwin/Linux."""

    @abstractmethod
    def default_gateway(self) -> Optional[str]: ...

    @abstractmethod
    def interfaces(self) -> dict[str, str]: ...

    @abstractmethod
    def check_interface(self, name: str) -> bool: ...

    @abstractmethod
    def add_host_route(self, ip: str, gateway: str) -> bool: ...

    @abstractmethod
    def add_net_route(self, network: str, gateway: str) -> bool: ...

    @abstractmethod
    def add_iface_route(self, target: str, iface: str, host: bool = True) -> bool: ...

    # ---- IPv6 primitives (PR#2 IPv6 foundation) ----
    # Default: no-op для backward compat. Реализации Darwin/Linux/Windows переопределяют.
    # На Darwin add_iface_route6 НЕ использует ppp_peer (IPv4-only) - сразу
    # -interface <utun*> для TUN интерфейсов. На Linux используется
    # 'ip -6 route replace' (не add) - безопаснее для ::/0 при наличии RA.

    def add_host_route6(self, ip: str, gateway: str) -> bool:
        return False

    def add_net_route6(self, network: str, gateway: str) -> bool:
        return False

    def add_iface_route6(self, target: str, iface: str, host: bool = True) -> bool:
        return False

    def delete_host_route6(self, ip: str) -> bool:
        return False

    def delete_net_route6(self, network: str) -> bool:
        return False

    def set_dns6(
        self,
        domains: list[str],
        nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]:
        """Set IPv6-nameservers для доменов. Пустой nameservers - no-op (не сбрасывает)."""
        return {d: False for d in domains}

    @abstractmethod
    def setup_dns_resolver(
        self,
        domains: list[str],
        nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]: ...

    @abstractmethod
    def cleanup_dns_resolver(self, domains: list[str], interface: str = "") -> None: ...

    def cleanup_local_dns_resolvers(self) -> list[str]:
        """Scan and remove resolver files pointing to localhost (safety net).

        Returns list of cleaned zone names. Default: no-op (Linux).
        """
        return []

    @abstractmethod
    def disable_ipv6(self) -> bool: ...

    @abstractmethod
    def restore_ipv6(self) -> bool: ...

    @abstractmethod
    def delete_host_route(self, ip: str) -> bool: ...

    @abstractmethod
    def delete_net_route(self, network: str) -> bool: ...

    @abstractmethod
    def route_table(self, lines: int | None = None) -> str: ...

    @abstractmethod
    def iface_info(self, name: str) -> str: ...

    @abstractmethod
    def ppp_peer(self, name: str) -> str:
        """Get PPP peer (gateway) address for a point-to-point interface."""
        ...

    def setup_system_proxy(self, port: int) -> bool:
        """Set system-wide HTTP/SOCKS proxy. Default no-op (Linux)."""
        return False

    def cleanup_system_proxy(self) -> bool:
        """Remove system-wide proxy settings. Default no-op (Linux)."""
        return True

    def reset_system_dns(self) -> bool:
        """Reset system DNS to DHCP defaults. Default no-op (Linux)."""
        return True

    def resolve_host(self, hostname: str, timeout: int | None = None) -> list[str]:
        """Resolve hostname to IPs (dig -> host -> getent -> nslookup -> socket fallback).

        Весь fallback-цикл выполняется в отдельном потоке с общим таймаутом `t`,
        чтобы зависание одного инструмента не блокировало весь процесс.
        """
        import threading

        t = timeout if timeout is not None else cfg.timeouts.net_command
        result: list[list[str]] = []

        def _try_dig(args: list[str], per: int) -> list[str]:
            r = _run(args, timeout=per + 1)
            if r.returncode == 0 and r.stdout.strip():
                return [
                    ln.strip()
                    for ln in r.stdout.strip().splitlines()
                    if re.match(r"\d+\.\d+\.\d+\.\d+$", ln.strip())
                ]
            return []

        def _do_resolve() -> None:
            # Короткий per_tool чтобы успеть попробовать несколько методов
            per_tool = max(1, t // 3)

            if shutil.which("dig"):
                # Запускаем системный DNS и публичный 1.1.1.1 параллельно —
                # системный DNS может быть сломан (остатки VPN-конфига)
                import concurrent.futures as _cf

                with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                    f_sys = ex.submit(
                        _try_dig,
                        ["dig", "+short", f"+time={per_tool}", "+tries=1", hostname],
                        per_tool,
                    )
                    f_pub = ex.submit(
                        _try_dig,
                        [
                            "dig",
                            "@1.1.1.1",
                            "+short",
                            f"+time={per_tool}",
                            "+tries=1",
                            hostname,
                        ],
                        per_tool,
                    )
                    done, _ = _cf.wait(
                        [f_sys, f_pub],
                        timeout=per_tool + 1,
                        return_when=_cf.FIRST_COMPLETED,
                    )
                    for f in done:
                        ips = f.result()
                        if ips:
                            result.append(ips)
                            return
                    # Ждём второй если первый не дал результата
                    for f in [f_sys, f_pub]:
                        try:
                            ips = f.result(timeout=per_tool + 1)
                            if ips:
                                result.append(ips)
                                return
                        except Exception:
                            pass

            if shutil.which("host"):
                r = _run(["host", "-W", str(per_tool), hostname], timeout=per_tool + 1)
                if r.returncode == 0:
                    ips = [
                        ln.split()[-1]
                        for ln in r.stdout.splitlines()
                        if "has address" in ln
                    ]
                    if ips:
                        result.append(ips)
                        return

            if shutil.which("getent"):
                r = _run(["getent", "ahosts", hostname], timeout=per_tool)
                if r.returncode == 0:
                    for ln in r.stdout.splitlines():
                        if "STREAM" in ln:
                            result.append([ln.split()[0]])
                            return

            if shutil.which("nslookup"):
                r = _run(["nslookup", hostname], timeout=per_tool)
                if r.returncode == 0:
                    ips = []
                    in_answer = False
                    for ln in r.stdout.splitlines():
                        if "Name:" in ln:
                            in_answer = True
                        elif in_answer and "Address:" in ln:
                            addr = ln.split("Address:")[-1].strip()
                            if re.match(r"\d+\.\d+\.\d+\.\d+$", addr):
                                ips.append(addr)
                    if ips:
                        result.append(ips)
                        return

            # socket.getaddrinfo - last resort, no configurable timeout on macOS
            try:
                infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
                seen: set[str] = set()
                ips = []
                for info in infos:
                    addr = info[4][0]
                    if addr not in seen:
                        seen.add(addr)
                        ips.append(addr)
                if ips:
                    result.append(ips)
            except socket.gaierror:
                pass

        thread = threading.Thread(target=_do_resolve, daemon=True)
        thread.start()
        thread.join(timeout=t)
        return result[0] if result else []


# ---------------------------------------------------------------------------
# Darwin (macOS)
# ---------------------------------------------------------------------------


class DarwinNet(NetManager):
    def default_gateway(self) -> Optional[str]:
        r = _run(["route", "-n", "get", "default"])
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if "gateway:" in line:
                    return line.split("gateway:")[-1].strip()
        return None

    def interfaces(self) -> dict[str, str]:
        result: dict[str, str] = {}
        r = _run(["ifconfig", "-a"])
        if r.returncode != 0:
            return result
        current: str | None = None
        for line in r.stdout.splitlines():
            # Interface header: "en0: flags=8863<...> mtu 1500"
            if line and not line[0].isspace() and ":" in line:
                current = line.split(":")[0]
            elif current and current not in result and "inet " in line:
                parts = line.strip().split()
                try:
                    idx = parts.index("inet")
                    result[current] = parts[idx + 1]
                except (ValueError, IndexError):
                    pass
        return result

    def check_interface(self, name: str) -> bool:
        r = _run(["ifconfig", name])
        return r.returncode == 0

    def add_host_route(self, ip: str, gateway: str) -> bool:
        r = _run(["sudo", "route", "add", "-host", ip, gateway])
        return r.returncode == 0

    def add_net_route(self, network: str, gateway: str) -> bool:
        r = _run(["sudo", "route", "add", "-net", network, gateway])
        return r.returncode == 0

    def add_iface_route(self, target: str, iface: str, host: bool = True) -> bool:
        flag = "-host" if host else "-net"
        # For TUN interfaces, use gateway (peer IP) instead of -interface.
        # macOS ignores -interface routes for normal app traffic (no G flag).
        if iface.startswith("utun"):
            gw = self.ppp_peer(iface)
            if gw:
                # macOS ignores 0.0.0.0/1 even with gateway. Split into
                # specific subnets like sing-box auto_route does.
                if not host:
                    subnets = _split_catchall(target)
                    if subnets:
                        return all(
                            _run(["sudo", "route", "add", "-net", s, gw]).returncode
                            == 0
                            for s in subnets
                        )
                r = _run(["sudo", "route", "add", flag, target, gw])
                return r.returncode == 0
        r = _run(["sudo", "route", "add", flag, target, "-interface", iface])
        return r.returncode == 0

    def setup_dns_resolver(
        self,
        domains: list[str],
        nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]:
        # macOS uses /etc/resolver/ files - interface is not needed
        resolver_dir = cfg.paths.resolver_dir
        _run(["sudo", "mkdir", "-p", resolver_dir])
        content = (
            "# tunnelvault\n"
            + "\n".join(f"nameserver {ns}" for ns in nameservers)
            + "\n"
        )
        results: dict[str, bool] = {}
        for domain in domains:
            r = _run(
                ["sudo", "tee", f"{resolver_dir}/{domain}"],
                input=content,
            )
            results[domain] = r.returncode == 0
        return results

    def cleanup_dns_resolver(self, domains: list[str], interface: str = "") -> None:
        resolver_dir = cfg.paths.resolver_dir
        files = [f"{resolver_dir}/{d}" for d in domains]
        _run(["sudo", "rm", "-f"] + files)

    def cleanup_local_dns_resolvers(self) -> list[str]:
        """Remove /etc/resolver/ files created by tunnelvault (identified by marker)."""
        import os

        resolver_dir = cfg.paths.resolver_dir
        if not os.path.isdir(resolver_dir):
            return []

        cleaned = []
        try:
            entries = os.listdir(resolver_dir)
        except OSError:
            return []

        for name in entries:
            path = os.path.join(resolver_dir, name)
            try:
                with open(path) as f:
                    content = f.read()
            except OSError:
                continue
            if "# tunnelvault" in content:
                _run(["sudo", "rm", "-f", path])
                cleaned.append(name)

        return cleaned

    def _active_network_services(self) -> list[str]:
        """Discover active network services (Wi-Fi, Ethernet, etc.)."""
        r = _run(["networksetup", "-listallnetworkservices"])
        if r.returncode != 0:
            return [cfg.defaults.network_service]
        services = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("*") or not line or line.startswith("An asterisk"):
                continue
            services.append(line)
        return services or [cfg.defaults.network_service]

    def disable_ipv6(self) -> bool:
        ok = True
        for svc in self._active_network_services():
            r = _run(["sudo", "networksetup", "-setv6off", svc])
            if r.returncode != 0:
                ok = False
        return ok

    def restore_ipv6(self) -> bool:
        ok = True
        for svc in self._active_network_services():
            r = _run(["sudo", "networksetup", "-setv6automatic", svc])
            if r.returncode != 0:
                ok = False
        return ok

    def reset_system_dns(self) -> bool:
        """Сбрасывает system DNS на DHCP-defaults для всех сетевых сервисов.

        VPN-клиенты (openconnect, fortivpn) выставляют DNS через networksetup.
        После disconnect без сброса DNS остаётся указывать на VPN-внутренние серверы,
        что ломает разрешение имён до следующего реконнекта.
        """
        ok = True
        for svc in self._active_network_services():
            r = _run(["sudo", "networksetup", "-setdnsservers", svc, "Empty"])
            if r.returncode != 0:
                ok = False
        return ok

    def delete_host_route(self, ip: str) -> bool:
        r = _run(["sudo", "route", "delete", "-host", ip])
        return r.returncode == 0

    def delete_net_route(self, network: str) -> bool:
        subnets = _split_catchall(network)
        if subnets:
            return all(
                _run(["sudo", "route", "delete", "-net", s]).returncode == 0
                for s in subnets
            )
        r = _run(["sudo", "route", "delete", "-net", network])
        return r.returncode == 0

    # ---- IPv6 primitives ----

    def add_host_route6(self, ip: str, gateway: str) -> bool:
        r = _run(["sudo", "route", "add", "-inet6", "-host", ip, gateway])
        return r.returncode == 0

    def add_net_route6(self, network: str, gateway: str) -> bool:
        r = _run(["sudo", "route", "add", "-inet6", "-net", network, gateway])
        return r.returncode == 0

    def add_iface_route6(self, target: str, iface: str, host: bool = True) -> bool:
        """На Darwin IPv6 route через TUN: -inet6 -host/-net <target> -interface <iface>.

        НЕ использует ppp_peer (IPv4-only: парсит 'inet X --> Y'). Для IPv6
        на утилитах macOS 'route add -inet6 <cidr> -interface utunN' работает
        без gateway - ядро автоматически находит next-hop через interface.
        """
        flag = "-host" if host else "-net"
        r = _run(["sudo", "route", "add", "-inet6", flag, target, "-interface", iface])
        return r.returncode == 0

    def delete_host_route6(self, ip: str) -> bool:
        r = _run(["sudo", "route", "delete", "-inet6", "-host", ip])
        return r.returncode == 0

    def delete_net_route6(self, network: str) -> bool:
        r = _run(["sudo", "route", "delete", "-inet6", "-net", network])
        return r.returncode == 0

    def set_dns6(
        self,
        domains: list[str],
        nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]:
        """Пишет IPv6 nameserver в /etc/resolver/<domain>.

        macOS BIND resolver формат: 'nameserver 2001:db8::1' без скобок.
        Пустой nameservers - no-op (не сбрасывает существующий файл).
        """
        if not nameservers:
            return {d: False for d in domains}
        resolver_dir = cfg.paths.resolver_dir
        _run(["sudo", "mkdir", "-p", resolver_dir])
        content = (
            "# tunnelvault\n"
            + "\n".join(f"nameserver {ns}" for ns in nameservers)
            + "\n"
        )
        results: dict[str, bool] = {}
        for domain in domains:
            r = _run(
                ["sudo", "tee", f"{resolver_dir}/{domain}"],
                input=content,
            )
            results[domain] = r.returncode == 0
        return results

    def route_table(self, lines: int | None = None) -> str:
        if lines is None:
            lines = cfg.display.route_table_lines
        r = _run(["netstat", "-rn"])
        if r.returncode == 0:
            return "\n".join(r.stdout.splitlines()[:lines])
        return ""

    def iface_info(self, name: str) -> str:
        r = _run(["ifconfig", name])
        return r.stdout if r.returncode == 0 else ""

    def ppp_peer(self, name: str) -> str:
        r = _run(["ifconfig", name])
        if r.returncode != 0:
            return ""
        for line in r.stdout.splitlines():
            if "inet " in line:
                parts = line.split()
                # macOS: inet X.X.X.X --> Y.Y.Y.Y
                if "-->" in parts:
                    idx = parts.index("-->")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        return ""

    def setup_system_proxy(self, port: int) -> bool:
        """Set macOS system HTTP/HTTPS/SOCKS proxy on all active network services."""
        ok = True
        for svc in self._active_network_services():
            for cmd in [
                ["networksetup", "-setwebproxy", svc, "127.0.0.1", str(port)],
                ["networksetup", "-setsecurewebproxy", svc, "127.0.0.1", str(port)],
                ["networksetup", "-setsocksfirewallproxy", svc, "127.0.0.1", str(port)],
            ]:
                r = _run(cmd)
                if r.returncode != 0:
                    ok = False
        return ok

    def cleanup_system_proxy(self) -> bool:
        """Disable macOS system HTTP/HTTPS/SOCKS proxy on all active network services."""
        ok = True
        for svc in self._active_network_services():
            for cmd in [
                ["networksetup", "-setwebproxystate", svc, "off"],
                ["networksetup", "-setsecurewebproxystate", svc, "off"],
                ["networksetup", "-setsocksfirewallproxystate", svc, "off"],
            ]:
                r = _run(cmd)
                if r.returncode != 0:
                    ok = False
        return ok


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------


class LinuxNet(NetManager):
    def default_gateway(self) -> Optional[str]:
        r = _run(["ip", "route", "show", "default"])
        if r.returncode == 0:
            parts = r.stdout.strip().split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
        return None

    def interfaces(self) -> dict[str, str]:
        result: dict[str, str] = {}
        r = _run(["ip", "-br", "addr"])
        if r.returncode != 0:
            return result
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                iface = parts[0]
                addr = parts[2].split("/")[0] if "/" in parts[2] else parts[2]
                result[iface] = addr
        return result

    def check_interface(self, name: str) -> bool:
        r = _run(["ip", "link", "show", name])
        return r.returncode == 0

    def add_host_route(self, ip: str, gateway: str) -> bool:
        r = _run(["sudo", "ip", "route", "add", f"{ip}/32", "via", gateway])
        return r.returncode == 0

    def add_net_route(self, network: str, gateway: str) -> bool:
        r = _run(["sudo", "ip", "route", "add", network, "via", gateway])
        return r.returncode == 0

    def add_iface_route(self, target: str, iface: str, host: bool = True) -> bool:
        t = f"{target}/32" if host else target
        r = _run(["sudo", "ip", "route", "add", t, "dev", iface])
        return r.returncode == 0

    def setup_dns_resolver(
        self,
        domains: list[str],
        nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]:
        results: dict[str, bool] = {}
        iface = interface
        if not iface:
            for domain in domains:
                results[domain] = False
            return results
        if shutil.which("resolvectl"):
            r = _run(["ip", "link", "show", iface])
            if r.returncode == 0:
                _run(["sudo", "resolvectl", "dns", iface] + nameservers)
                for domain in domains:
                    r3 = _run(["sudo", "resolvectl", "domain", iface, domain])
                    results[domain] = r3.returncode == 0
                return results
        for domain in domains:
            results[domain] = False
        return results

    def cleanup_dns_resolver(self, domains: list[str], interface: str = "") -> None:
        iface = interface
        if not iface:
            return
        if shutil.which("resolvectl"):
            _run(["sudo", "resolvectl", "revert", iface])

    def disable_ipv6(self) -> bool:
        r = _run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
        return r.returncode == 0

    def restore_ipv6(self) -> bool:
        r = _run(["sudo", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"])
        return r.returncode == 0

    def delete_host_route(self, ip: str) -> bool:
        r = _run(["sudo", "ip", "route", "del", f"{ip}/32"])
        return r.returncode == 0

    def delete_net_route(self, network: str) -> bool:
        r = _run(["sudo", "ip", "route", "del", network])
        return r.returncode == 0

    # ---- IPv6 primitives ----

    def add_host_route6(self, ip: str, gateway: str) -> bool:
        # replace вместо add: безопаснее при существующем маршруте (напр. RA ::/0).
        r = _run(["sudo", "ip", "-6", "route", "replace", f"{ip}/128", "via", gateway])
        return r.returncode == 0

    def add_net_route6(self, network: str, gateway: str) -> bool:
        r = _run(["sudo", "ip", "-6", "route", "replace", network, "via", gateway])
        return r.returncode == 0

    def add_iface_route6(self, target: str, iface: str, host: bool = True) -> bool:
        t = f"{target}/128" if host else target
        r = _run(["sudo", "ip", "-6", "route", "replace", t, "dev", iface])
        return r.returncode == 0

    def delete_host_route6(self, ip: str) -> bool:
        r = _run(["sudo", "ip", "-6", "route", "del", f"{ip}/128"])
        return r.returncode == 0

    def delete_net_route6(self, network: str) -> bool:
        r = _run(["sudo", "ip", "-6", "route", "del", network])
        return r.returncode == 0

    def set_dns6(
        self,
        domains: list[str],
        nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]:
        """resolvectl принимает IPv6 nameservers без кавычек.

        Пустой nameservers - no-op (иначе resolvectl dns iface без аргументов
        СБРОСИТ существующие DNS для интерфейса, это не no-op).
        """
        results: dict[str, bool] = {d: False for d in domains}
        if not nameservers:
            return results
        iface = interface
        if not iface:
            return results
        if not shutil.which("resolvectl"):
            return results
        r = _run(["ip", "link", "show", iface])
        if r.returncode != 0:
            return results
        _run(["sudo", "resolvectl", "dns", iface] + nameservers)
        for domain in domains:
            r3 = _run(["sudo", "resolvectl", "domain", iface, domain])
            results[domain] = r3.returncode == 0
        return results

    def route_table(self, lines: int | None = None) -> str:
        if lines is None:
            lines = cfg.display.route_table_lines
        r = _run(["ip", "route"])
        if r.returncode == 0:
            return "\n".join(r.stdout.splitlines()[:lines])
        r = _run(["netstat", "-rn"])
        if r.returncode == 0:
            return "\n".join(r.stdout.splitlines()[:lines])
        return ""

    def iface_info(self, name: str) -> str:
        r = _run(["ip", "addr", "show", name])
        if r.returncode == 0:
            return r.stdout
        r = _run(["ifconfig", name])
        return r.stdout if r.returncode == 0 else ""

    def ppp_peer(self, name: str) -> str:
        # ip addr: "inet 10.0.0.2 peer 10.0.0.1/32 scope global ppp0"
        r = _run(["ip", "addr", "show", name])
        if r.returncode == 0:
            m = re.search(r"peer (\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                return m.group(1)
        # Fallback: ifconfig "P-t-P:X.X.X.X"
        r = _run(["ifconfig", name])
        if r.returncode == 0:
            m = re.search(r"P-t-P:(\d+\.\d+\.\d+\.\d+)", r.stdout)
            if m:
                return m.group(1)
        return ""

    def setup_system_proxy(self, port: int) -> bool:
        """Set Linux system proxy via gsettings (GNOME) or env file fallback."""
        proxy = f"127.0.0.1:{port}"
        # Try GNOME gsettings first
        if shutil.which("gsettings"):
            ok = True
            for cmd in [
                ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
                [
                    "gsettings",
                    "set",
                    "org.gnome.system.proxy.http",
                    "host",
                    "127.0.0.1",
                ],
                ["gsettings", "set", "org.gnome.system.proxy.http", "port", str(port)],
                [
                    "gsettings",
                    "set",
                    "org.gnome.system.proxy.https",
                    "host",
                    "127.0.0.1",
                ],
                ["gsettings", "set", "org.gnome.system.proxy.https", "port", str(port)],
                [
                    "gsettings",
                    "set",
                    "org.gnome.system.proxy.socks",
                    "host",
                    "127.0.0.1",
                ],
                ["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(port)],
            ]:
                r = _run(cmd)
                if r.returncode != 0:
                    ok = False
            if ok:
                return True
        # Fallback: write env vars to /etc/environment
        env_lines = [
            f'http_proxy="http://{proxy}/"',
            f'https_proxy="http://{proxy}/"',
            f'all_proxy="socks5://{proxy}/"',
            f'HTTP_PROXY="http://{proxy}/"',
            f'HTTPS_PROXY="http://{proxy}/"',
            f'ALL_PROXY="socks5://{proxy}/"',
        ]
        return _write_env_proxy(env_lines)

    def cleanup_system_proxy(self) -> bool:
        """Remove Linux system proxy settings."""
        if shutil.which("gsettings"):
            r = _run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"])
            if r.returncode == 0:
                return True
        return _remove_env_proxy()


def _write_env_proxy(lines: list[str]) -> bool:
    """Append proxy env vars to /etc/environment (with marker for cleanup)."""
    marker = "# tunnelvault-proxy"
    content = f"\n{marker}\n" + "\n".join(lines) + f"\n{marker}-end\n"
    r = _run(
        ["sudo", "tee", "-a", "/etc/environment"],
        input=content,
        capture_output=True,
    )
    return r.returncode == 0


def _remove_env_proxy() -> bool:
    """Remove tunnelvault proxy lines from /etc/environment."""
    env_path = "/etc/environment"
    try:
        with open(env_path) as f:
            original = f.read()
    except OSError:
        return True  # file doesn't exist = nothing to clean
    marker = "# tunnelvault-proxy"
    if marker not in original:
        return True
    cleaned_lines = []
    skipping = False
    for line in original.splitlines():
        if line.strip() == marker:
            skipping = True
            continue
        if line.strip() == f"{marker}-end":
            skipping = False
            continue
        if not skipping:
            cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines).rstrip() + "\n" if cleaned_lines else ""
    r = _run(["sudo", "tee", env_path], input=cleaned, capture_output=True)
    return r.returncode == 0


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------


def _cidr_to_mask(prefix_len: int) -> str:
    """Convert CIDR prefix length to dotted subnet mask (e.g. 24 -> 255.255.255.0)."""
    bits = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return f"{(bits >> 24) & 0xFF}.{(bits >> 16) & 0xFF}.{(bits >> 8) & 0xFF}.{bits & 0xFF}"


class WindowsNet(NetManager):
    """Windows networking via route.exe, netsh, and PowerShell."""

    def default_gateway(self) -> Optional[str]:
        r = _run(["route", "PRINT", "0.0.0.0"])
        if r.returncode == 0:
            in_routes = False
            for line in r.stdout.splitlines():
                stripped = line.strip()
                if "Active Routes:" in line:
                    in_routes = True
                    continue
                if in_routes and stripped.startswith("0.0.0.0"):
                    parts = stripped.split()
                    # Network Destination | Netmask | Gateway | Interface | Metric
                    if len(parts) >= 3:
                        gw = parts[2]
                        if re.match(r"\d+\.\d+\.\d+\.\d+$", gw):
                            return gw
        return None

    def interfaces(self) -> dict[str, str]:
        result: dict[str, str] = {}
        r = _run(["ipconfig"])
        if r.returncode != 0:
            return result
        current: str | None = None
        for line in r.stdout.splitlines():
            # Adapter header: "Ethernet adapter Local Area Connection:" or
            # "PPP adapter VPN Connection:"
            if "adapter" in line and line.rstrip().endswith(":"):
                # Extract adapter name after "adapter "
                idx = line.find("adapter ")
                if idx >= 0:
                    current = line[idx + 8 :].rstrip(": \t")
            elif current and current not in result:
                # "   IPv4 Address. . . . . . . . . . . : 192.168.1.5"
                if "IPv4 Address" in line and ":" in line:
                    addr = line.split(":")[-1].strip()
                    if re.match(r"\d+\.\d+\.\d+\.\d+$", addr):
                        result[current] = addr
        return result

    def check_interface(self, name: str) -> bool:
        r = _run(["netsh", "interface", "show", "interface", f"name={name}"])
        if r.returncode == 0 and "Connected" in r.stdout:
            return True
        # Fallback: check via ipconfig
        ifaces = self.interfaces()
        return name in ifaces

    def add_host_route(self, ip: str, gateway: str) -> bool:
        r = _run(["route", "ADD", ip, "MASK", "255.255.255.255", gateway])
        return r.returncode == 0

    def add_net_route(self, network: str, gateway: str) -> bool:
        if "/" not in network:
            return False
        net_addr, prefix = network.rsplit("/", 1)
        try:
            mask = _cidr_to_mask(int(prefix))
        except (ValueError, OverflowError):
            return False
        r = _run(["route", "ADD", net_addr, "MASK", mask, gateway])
        return r.returncode == 0

    def add_iface_route(self, target: str, iface: str, host: bool = True) -> bool:
        if host:
            prefix = f"{target}/32"
        else:
            prefix = target if "/" in target else f"{target}/32"
        # netsh takes interface name directly (no index lookup needed)
        r = _run(
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                prefix,
                f"interface={iface}",
            ]
        )
        return r.returncode == 0

    def setup_dns_resolver(
        self,
        domains: list[str],
        nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]:
        results: dict[str, bool] = {}
        ns_list = ",".join(f"'{ns}'" for ns in nameservers)
        for domain in domains:
            # NRPT rule with tunnelvault marker comment
            ps_cmd = (
                f"Add-DnsClientNrptRule -Namespace '.{domain}' "
                f"-NameServers {ns_list} -Comment 'tunnelvault'"
            )
            r = _run(["powershell", "-Command", ps_cmd])
            results[domain] = r.returncode == 0
        return results

    def cleanup_dns_resolver(self, domains: list[str], interface: str = "") -> None:
        # Remove NRPT rules created by tunnelvault
        for domain in domains:
            ps_cmd = (
                "Get-DnsClientNrptRule | "
                f"Where-Object {{ $_.Comment -eq 'tunnelvault' -and $_.Namespace -eq '.{domain}' }} | "
                "Remove-DnsClientNrptRule -Force"
            )
            _run(["powershell", "-Command", ps_cmd])

    def cleanup_local_dns_resolvers(self) -> list[str]:
        """Remove all NRPT rules created by tunnelvault."""
        r = _run(
            [
                "powershell",
                "-Command",
                "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'tunnelvault' } | "
                "ForEach-Object { $_.Namespace }",
            ]
        )
        if r.returncode != 0 or not r.stdout.strip():
            return []
        zones = [z.lstrip(".") for z in r.stdout.strip().splitlines() if z.strip()]
        if zones:
            _run(
                [
                    "powershell",
                    "-Command",
                    "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'tunnelvault' } | "
                    "Remove-DnsClientNrptRule -Force",
                ]
            )
        return zones

    def disable_ipv6(self) -> bool:
        r = _run(
            [
                "powershell",
                "-Command",
                "Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | "
                "Disable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false",
            ]
        )
        return r.returncode == 0

    def restore_ipv6(self) -> bool:
        r = _run(
            [
                "powershell",
                "-Command",
                "Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | "
                "Enable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false",
            ]
        )
        return r.returncode == 0

    def delete_host_route(self, ip: str) -> bool:
        r = _run(["route", "DELETE", ip])
        return r.returncode == 0

    def delete_net_route(self, network: str) -> bool:
        net_addr = network.split("/")[0] if "/" in network else network
        r = _run(["route", "DELETE", net_addr])
        return r.returncode == 0

    # ---- IPv6 primitives ----

    def add_host_route6(self, ip: str, gateway: str) -> bool:
        r = _run(
            [
                "netsh",
                "interface",
                "ipv6",
                "add",
                "route",
                f"{ip}/128",
                f"nexthop={gateway}",
            ]
        )
        return r.returncode == 0

    def add_net_route6(self, network: str, gateway: str) -> bool:
        if "/" not in network:
            return False
        r = _run(
            [
                "netsh",
                "interface",
                "ipv6",
                "add",
                "route",
                network,
                f"nexthop={gateway}",
            ]
        )
        return r.returncode == 0

    def add_iface_route6(self, target: str, iface: str, host: bool = True) -> bool:
        prefix = (
            f"{target}/128" if host else (target if "/" in target else f"{target}/128")
        )
        r = _run(
            [
                "netsh",
                "interface",
                "ipv6",
                "add",
                "route",
                prefix,
                f"interface={iface}",
            ]
        )
        return r.returncode == 0

    def delete_host_route6(self, ip: str) -> bool:
        r = _run(["netsh", "interface", "ipv6", "delete", "route", f"{ip}/128"])
        return r.returncode == 0

    def delete_net_route6(self, network: str) -> bool:
        if "/" not in network:
            return False
        r = _run(["netsh", "interface", "ipv6", "delete", "route", network])
        return r.returncode == 0

    def set_dns6(
        self,
        domains: list[str],
        nameservers: list[str],
        interface: str = "",
    ) -> dict[str, bool]:
        """Windows NRPT принимает IPv6 nameservers. Пустой nameservers - no-op."""
        results: dict[str, bool] = {d: False for d in domains}
        if not nameservers:
            return results
        ns_list = ",".join(f"'{ns}'" for ns in nameservers)
        for domain in domains:
            ps_cmd = (
                f"Add-DnsClientNrptRule -Namespace '.{domain}' "
                f"-NameServers {ns_list} -Comment 'tunnelvault'"
            )
            r = _run(["powershell", "-Command", ps_cmd])
            results[domain] = r.returncode == 0
        return results

    def route_table(self, lines: int | None = None) -> str:
        if lines is None:
            lines = cfg.display.route_table_lines
        r = _run(["route", "PRINT"])
        if r.returncode == 0:
            return "\n".join(r.stdout.splitlines()[:lines])
        return ""

    def iface_info(self, name: str) -> str:
        r = _run(["netsh", "interface", "ip", "show", "config", f"name={name}"])
        return r.stdout if r.returncode == 0 else ""

    def ppp_peer(self, name: str) -> str:
        # Try ipconfig - look for Default Gateway under the named adapter
        r = _run(["ipconfig"])
        if r.returncode != 0:
            return ""
        in_adapter = False
        for line in r.stdout.splitlines():
            if "adapter" in line and name in line and line.rstrip().endswith(":"):
                in_adapter = True
            elif in_adapter and "adapter" in line and line.rstrip().endswith(":"):
                break  # next adapter
            elif in_adapter and "Default Gateway" in line and ":" in line:
                gw = line.split(":")[-1].strip()
                if re.match(r"\d+\.\d+\.\d+\.\d+$", gw):
                    return gw
        return ""

    def setup_system_proxy(self, port: int) -> bool:
        """Set Windows system proxy via netsh and registry."""
        proxy = f"127.0.0.1:{port}"
        # netsh winhttp (system-level, used by many Windows services)
        r = _run(["netsh", "winhttp", "set", "proxy", proxy])
        # Registry (user-level, used by browsers and most apps)
        ps_cmd = (
            "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
            f"-Name ProxyServer -Value '{proxy}'; "
            "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
            "-Name ProxyEnable -Value 1"
        )
        r2 = _run(["powershell", "-Command", ps_cmd])
        return r.returncode == 0 or r2.returncode == 0

    def cleanup_system_proxy(self) -> bool:
        """Remove Windows system proxy settings."""
        r = _run(["netsh", "winhttp", "reset", "proxy"])
        ps_cmd = (
            "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
            "-Name ProxyEnable -Value 0; "
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
            "-Name ProxyServer -ErrorAction SilentlyContinue"
        )
        r2 = _run(["powershell", "-Command", ps_cmd])
        return r.returncode == 0 or r2.returncode == 0


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create() -> NetManager:
    system = platform.system()
    if system == "Darwin":
        return DarwinNet()
    if system == "Windows":
        return WindowsNet()
    if system != "Linux":
        import warnings

        warnings.warn(
            f"Unsupported OS '{system}', using Linux networking as fallback",
            stacklevel=2,
        )
    return LinuxNet()
