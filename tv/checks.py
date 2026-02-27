"""Health checks: ports, ping, DNS, HTTP."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

from tv import ui
from tv.app_config import cfg
from tv.i18n import t
from tv.logger import Logger

IS_WINDOWS = platform.system() == "Windows"


@dataclass
class CheckResult:
    label: str
    status: str   # "ok" | "fail" | "skip"
    detail: str


# --- Check primitives (each returns True on success) ---

def _run_check(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    """subprocess.run with timeout protection for check commands."""
    if timeout is None:
        timeout = cfg.timeouts.check_subprocess
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args=cmd, returncode=-1, stdout="", stderr="timeout")


def _check_port(host: str, port: int, timeout: int | None = None) -> bool:
    if timeout is None:
        timeout = cfg.timeouts.check_port
    if IS_WINDOWS or not shutil.which("nc"):
        # Pure Python socket connect (works everywhere)
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False
    r = _run_check(["nc", "-z", "-w", str(timeout), host, str(port)], timeout + 2)
    return r.returncode == 0


def _check_ping(host: str, timeout: int | None = None) -> bool:
    if timeout is None:
        timeout = cfg.timeouts.check_ping
    system = platform.system()
    if system == "Windows":
        # Windows: -n count, -w timeout in milliseconds
        args = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    elif system == "Darwin":
        # macOS: -W is in milliseconds, -t is total timeout in seconds
        args = ["ping", "-c", "1", "-t", str(timeout), host]
    else:
        # Linux: -W is in seconds
        args = ["ping", "-c", "1", "-W", str(timeout), host]
    r = _run_check(args, timeout + 2)
    return r.returncode == 0


def _check_dns(name: str, server: str, timeout: int | None = None) -> bool:
    if timeout is None:
        timeout = cfg.timeouts.check_dns
    r = _run_check(["nslookup", name, server], timeout)
    return r.returncode == 0


def _urllib_get(url: str, timeout: int) -> tuple[int, str]:
    """HTTP GET via urllib (fallback when curl is unavailable). Returns (status_code, body)."""
    import ssl
    import urllib.request
    import urllib.error
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tunnelvault"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def _check_http(url: str, timeout: int | None = None) -> bool:
    if timeout is None:
        timeout = cfg.timeouts.check_http
    if shutil.which("curl"):
        r = _run_check(
            ["curl", "-4", "-sk", "--max-time", str(timeout),
             "-o", os.devnull, "-w", "%{http_code}", url],
            timeout + 2,
        )
        if r.returncode != 0:
            return False
        code = r.stdout.strip()
        return code != "000" and code.startswith(("2", "3"))
    # Fallback: urllib
    status, _ = _urllib_get(url, timeout)
    return 200 <= status < 400


def _check_http_any(url: str, timeout: int | None = None) -> bool:
    """Returns True if HTTP response is not a timeout (000)."""
    if timeout is None:
        timeout = cfg.timeouts.check_http
    if shutil.which("curl"):
        r = _run_check(
            ["curl", "-4", "-sk", "--max-time", str(timeout),
             "-o", os.devnull, "-w", "%{http_code}", url],
            timeout + 2,
        )
        return r.returncode == 0 and r.stdout.strip() != "000"
    # Fallback: urllib
    status, _ = _urllib_get(url, timeout)
    return status != 0


def get_external_ip(url: str, timeout: int | None = None) -> Optional[str]:
    if timeout is None:
        timeout = cfg.timeouts.check_external_ip
    if shutil.which("curl"):
        r = _run_check(["curl", "-4", "-s", "--max-time", str(timeout), url], timeout + 2)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
        return None
    # Fallback: urllib
    status, body = _urllib_get(url, timeout)
    if status == 200 and body.strip():
        return body.strip()
    return None


# --- Check runner ---

def _run_one(
    idx: int,
    guard: bool,
    label: str,
    fn: Callable[[], bool],
    ok_msg: str,
    fail_msg: str,
    logger: Optional[Logger],
    cmd_hint: str = "",
) -> CheckResult:
    """Run a single check with terminal output."""
    hint = f" {ui.DIM}{cmd_hint}{ui.NC}" if cmd_hint else ""
    print(f"   {ui.DIM}[{idx}]{ui.NC} {label}{hint} ... ", end="", flush=True)

    if not guard:
        print(f"{ui.YELLOW}⏭{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {label} -> SKIP")
        return CheckResult(label, "skip", t("check.skip"))

    try:
        ok = fn()
    except Exception:
        ok = False

    if ok:
        print(f"{ui.GREEN}✅{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {label} ({cmd_hint}) -> OK ({ok_msg})" if cmd_hint else f"[{idx}] {label} -> OK ({ok_msg})")
        return CheckResult(label, "ok", ok_msg)
    else:
        print(f"{ui.RED}❌{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {label} ({cmd_hint}) -> FAIL ({fail_msg})" if cmd_hint else f"[{idx}] {label} -> FAIL ({fail_msg})")
        return CheckResult(label, "fail", fail_msg)


# --- Command hints ---

def _ping_hint(host: str) -> str:
    system = platform.system()
    if system == "Windows":
        return f"ping -n 1 -w 3000 {host}"
    if system == "Darwin":
        return f"ping -c1 -t3 {host}"
    return f"ping -c1 -W3 {host}"


def _fallback_hint(fallback: str, host: str) -> str:
    if not fallback or ":" not in fallback:
        return ""
    fb_type, fb_arg = fallback.split(":", 1)
    if fb_type == "port":
        return f"nc -z {host} {fb_arg}"
    if fb_type == "dns":
        return f"nslookup {fb_arg} {host}"
    return ""


# --- Ping with fallback ---

def _parse_fallback(fallback: str, host: str) -> tuple[Callable[[], bool], str] | None:
    """Parse fallback spec like 'port:53' or 'dns:some.host'. Returns (fn, label)."""
    if not fallback or ":" not in fallback:
        return None
    fb_type, fb_arg = fallback.split(":", 1)
    if fb_type == "port":
        try:
            port = int(fb_arg)
        except ValueError:
            return None
        return (lambda h=host, p=port: _check_port(h, p)), f"port:{fb_arg}"
    if fb_type == "dns":
        return (lambda n=fb_arg, s=host: _check_dns(n, s)), f"dns:{fb_arg}"
    return None


def _run_ping_check(
    idx: int,
    guard: bool,
    host: str,
    label: str,
    fallback: str,
    logger: Optional[Logger],
) -> CheckResult:
    """Run ping check with optional fallback strategy."""
    check_label = f"{host} ({label})"
    fb = _parse_fallback(fallback, host)
    has_fb = fb is not None

    # Build command hints
    p_hint = _ping_hint(host)
    fb_cmd_hint = _fallback_hint(fallback, host) if has_fb else ""
    hint_parts = [p_hint]
    if fb_cmd_hint:
        hint_parts.append(f"-> {fb_cmd_hint}")
    cmd_display = " ".join(hint_parts)

    print(f"   {ui.DIM}[{idx}]{ui.NC} {check_label} {ui.DIM}{cmd_display}{ui.NC} ... ", end="", flush=True)

    if not guard:
        print(f"{ui.YELLOW}⏭{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {check_label} ({cmd_display}) -> SKIP")
        return CheckResult(check_label, "skip", t("check.skip"))

    # Primary: ping
    try:
        ping_ok = _check_ping(host)
    except Exception:
        ping_ok = False

    if ping_ok:
        print(f"{ui.GREEN}✅{ui.NC}")
        if logger:
            logger.log("CHECK", f"[{idx}] {check_label} ({p_hint}) -> OK (ping)")
        return CheckResult(check_label, "ok", t("check.ping_ok"))

    # Fallback
    if has_fb:
        fb_fn, fb_label = fb
        try:
            fb_ok = fb_fn()
        except Exception:
            fb_ok = False

        if fb_ok:
            print(f"{ui.YELLOW}⚠{ui.NC}{ui.GREEN}✅{ui.NC} {ui.DIM}(fallback: {fb_cmd_hint}){ui.NC}")
            detail = f"fallback: {fb_label}"
            if logger:
                logger.log("CHECK", f"[{idx}] {check_label} ({p_hint} fail -> {fb_cmd_hint}) -> OK")
            return CheckResult(check_label, "ok", detail)
        else:
            print(f"{ui.RED}❌{ui.NC} {ui.DIM}({p_hint} + {fb_cmd_hint}){ui.NC}")
            detail = f"ping + {fb_label} fail"
            if logger:
                logger.log("CHECK", f"[{idx}] {check_label} ({p_hint} fail, {fb_cmd_hint} fail) -> FAIL")
            return CheckResult(check_label, "fail", detail)

    # No fallback, plain fail
    print(f"{ui.RED}❌{ui.NC}")
    if logger:
        logger.log("CHECK", f"[{idx}] {check_label} ({p_hint}) -> FAIL ({t('check.no_ping')})")
    return CheckResult(check_label, "fail", t("check.no_ping"))


# --- Per-tunnel checks ---

def run_all_from_tunnels(
    tunnel_checks: list[tuple[str, bool, dict]],
    logger: Optional[Logger] = None,
) -> tuple[list[CheckResult], str]:
    """Run health checks from per-tunnel check configs.

    Args:
        tunnel_checks: list of (tunnel_name, is_ok, checks_dict)
            checks_dict keys: ports, ping, dns, http, external_ip_url
        logger: optional Logger

    Returns:
        (list[CheckResult], external_ip)
    """
    results: list[CheckResult] = []
    idx = 0
    ext_ip = ""

    if logger:
        logger.log("INFO", "=== Checks ===")

    print()
    print(f"  {ui.BOLD}🧪 {t('check.checks_title')}{ui.NC}")
    print()

    for tunnel_name, is_ok, checks_cfg in tunnel_checks:
        if not checks_cfg:
            continue

        print(f"   {ui.DIM}── {tunnel_name} ──{ui.NC}")

        # Ports
        for entry in checks_cfg.get("ports", []):
            host = entry.get("host", "")
            port = entry.get("port", 0)
            if not host or not port:
                continue
            idx += 1
            results.append(_run_one(
                idx, is_ok, f"{host}:{port}",
                lambda h=host, p=port: _check_port(h, p),
                t("check.port_open"), t("check.port_closed"), logger,
                cmd_hint=f"nc -z {host} {port}",
            ))

        # Ping (with optional fallback)
        for entry in checks_cfg.get("ping", []):
            host = entry.get("host", "")
            if not host:
                continue
            label = entry.get("label", host)
            fallback = entry.get("fallback", "")
            idx += 1
            results.append(_run_ping_check(
                idx, is_ok, host, label, fallback, logger,
            ))

        # DNS
        for entry in checks_cfg.get("dns", []):
            name = entry.get("name", "")
            server = entry.get("server", "")
            if not name or not server:
                continue
            idx += 1
            results.append(_run_one(
                idx, is_ok, f"{name} @{server}",
                lambda n=name, s=server: _check_dns(n, s),
                t("check.resolves"), t("check.no_resolve"), logger,
                cmd_hint=f"nslookup {name} {server}",
            ))

        # HTTP
        for url in checks_cfg.get("http", []):
            label = url.replace("https://", "").replace("http://", "").rstrip("/")
            idx += 1
            results.append(_run_one(
                idx, is_ok, label,
                lambda u=url: _check_http_any(u),
                "ok", t("check.timeout"), logger,
                cmd_hint=f"curl -s {url}",
            ))

        # External IP (special case)
        ext_ip_url = checks_cfg.get("external_ip_url", "")
        if ext_ip_url:
            idx += 1
            ext_hint = f"curl -s {ext_ip_url}"
            ext_label = t("check.external_ip")
            print(f"   {ui.DIM}[{idx}]{ui.NC} {ext_label} {ui.DIM}{ext_hint}{ui.NC} ... ", end="", flush=True)
            if is_ok:
                ext_ip = get_external_ip(ext_ip_url) or ""
                if ext_ip:
                    print(f"{ui.GREEN}✅{ui.NC} {ui.DIM}({ext_ip}){ui.NC}")
                    results.append(CheckResult(ext_label, "ok", ext_ip))
                    if logger:
                        logger.log("CHECK", f"[{idx}] External IP -> OK ({ext_ip})")
                else:
                    print(f"{ui.RED}❌{ui.NC}")
                    results.append(CheckResult(ext_label, "fail", t("check.timeout")))
                    if logger:
                        logger.log("CHECK", f"[{idx}] External IP -> FAIL (timeout)")
            else:
                print(f"{ui.YELLOW}⏭{ui.NC}")
                results.append(CheckResult(ext_label, "skip", t("check.skip")))
                if logger:
                    logger.log("CHECK", f"[{idx}] External IP -> SKIP")

    if logger:
        passed = sum(1 for r in results if r.status == "ok")
        failed = sum(1 for r in results if r.status == "fail")
        skipped = sum(1 for r in results if r.status == "skip")
        logger.log("INFO", f"Checks: passed={passed} failed={failed} skipped={skipped} total={len(results)}")

    return results, ext_ip


# --- Quiet mode (single animated line) ---

def _collect_check_tasks(
    tunnel_checks: list[tuple[str, bool, dict]],
) -> list[tuple[str, bool, str, Callable[[], bool | str | None]]]:
    """Collect all checks as (label, guard, type, fn) without running them."""
    tasks: list[tuple[str, bool, str, Callable[[], bool | str | None]]] = []

    for tunnel_name, is_ok, checks_cfg in tunnel_checks:
        if not checks_cfg:
            continue

        for entry in checks_cfg.get("ports", []):
            host = entry.get("host", "")
            port = entry.get("port", 0)
            if host and port:
                tasks.append((
                    f"{host}:{port}",
                    is_ok, "port",
                    lambda h=host, p=port: _check_port(h, p),
                ))

        for entry in checks_cfg.get("ping", []):
            host = entry.get("host", "")
            if not host:
                continue
            label = entry.get("label", host)
            fallback = entry.get("fallback", "")
            fb = _parse_fallback(fallback, host)

            def _ping_with_fb(h=host, f=fb):
                try:
                    if _check_ping(h):
                        return True
                except Exception:
                    pass
                if f:
                    fb_fn, _ = f
                    try:
                        return fb_fn()
                    except Exception:
                        pass
                return False

            tasks.append((f"{host} ({label})", is_ok, "ping", _ping_with_fb))

        for entry in checks_cfg.get("dns", []):
            name = entry.get("name", "")
            server = entry.get("server", "")
            if name and server:
                tasks.append((
                    f"{name} @{server}",
                    is_ok, "dns",
                    lambda n=name, s=server: _check_dns(n, s),
                ))

        for url in checks_cfg.get("http", []):
            label = url.replace("https://", "").replace("http://", "").rstrip("/")
            tasks.append((label, is_ok, "http", lambda u=url: _check_http_any(u)))

        ext_ip_url = checks_cfg.get("external_ip_url", "")
        if ext_ip_url:
            tasks.append((
                "external-ip", is_ok, "ext_ip",
                lambda u=ext_ip_url: get_external_ip(u),
            ))

    return tasks


def run_all_quiet(
    tunnel_checks: list[tuple[str, bool, dict]],
    logger: Optional[Logger] = None,
) -> tuple[list[CheckResult], str]:
    """Run checks with single-line animated output."""
    import shutil
    import sys

    tasks = _collect_check_tasks(tunnel_checks)
    if not tasks:
        return [], ""

    results: list[CheckResult] = []
    ext_ip = ""
    total = len(tasks)
    cols = shutil.get_terminal_size().columns

    for i, (label, guard, ctype, fn) in enumerate(tasks, 1):
        # Animated progress line
        line = f"  \033[0;36m⟳\033[0m {i}/{total} {label}"
        # Truncate and pad to terminal width
        vis_len = len(line) - 8  # subtract ANSI codes length
        pad = max(0, cols - vis_len)
        sys.stderr.write(f"\r{line}{' ' * pad}")
        sys.stderr.flush()

        if not guard:
            results.append(CheckResult(label, "skip", t("check.skip")))
            if logger:
                logger.log("CHECK", f"[{i}] {label} -> SKIP")
            continue

        try:
            result = fn()
        except Exception:
            result = False

        if ctype == "ext_ip":
            if result:
                ext_ip = str(result)
                results.append(CheckResult(label, "ok", ext_ip))
                if logger:
                    logger.log("CHECK", f"[{i}] {label} -> OK ({ext_ip})")
            else:
                results.append(CheckResult(label, "fail", t("check.timeout")))
                if logger:
                    logger.log("CHECK", f"[{i}] {label} -> FAIL")
        elif result:
            results.append(CheckResult(label, "ok", "ok"))
            if logger:
                logger.log("CHECK", f"[{i}] {label} -> OK")
        else:
            results.append(CheckResult(label, "fail", "fail"))
            if logger:
                logger.log("CHECK", f"[{i}] {label} -> FAIL")

    # Final summary line
    passed = sum(1 for r in results if r.status == "ok")
    failed = sum(1 for r in results if r.status == "fail")

    if failed == 0:
        summary = f"  \033[0;32m✅ {passed}/{total} checks passed\033[0m"
    else:
        summary = f"  \033[0;31m❌ {failed} failed\033[0m, \033[0;32m{passed} passed\033[0m / {total}"

    if ext_ip:
        summary += f"  \033[2mIP: {ext_ip}\033[0m"

    pad = max(0, cols - len(summary) + 16)  # account for ANSI
    sys.stderr.write(f"\r{summary}{' ' * pad}\n")
    sys.stderr.flush()

    if logger:
        logger.log("INFO", f"Checks: passed={passed} failed={failed} total={total}")

    return results, ext_ip
