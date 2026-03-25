"""Daemon management: daemonize, PID file, autostart (launchd/systemd)."""

from __future__ import annotations

import os
import platform
import subprocess

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]

try:
    import plistlib
except ImportError:
    plistlib = None  # type: ignore[assignment]
import sys
from pathlib import Path

from tv import ui
from tv.app_config import cfg
from tv.i18n import t

PLIST_LABEL = "com.tunnelvault.keepalive"
PLIST_PATH = Path(f"/Library/LaunchDaemons/{PLIST_LABEL}.plist")

SYSTEMD_UNIT = "tunnelvault.service"
SYSTEMD_PATH = Path(f"/etc/systemd/system/{SYSTEMD_UNIT}")

# Module-level fd for PID file lock (kept open while daemon is alive)
_pid_fd: int | None = None


# =========================================================================
# PID file
# =========================================================================


def pid_file_path(script_dir: Path) -> Path:
    """Absolute path to PID file (inside log_dir)."""
    log_dir = Path(cfg.paths.log_dir)
    if not log_dir.is_absolute():
        log_dir = script_dir / log_dir
    return log_dir / cfg.paths.pid_file


def write_pid(script_dir: Path, pid: int | None = None) -> Path:
    """Write current (or given) PID to file with flock. Returns path.

    The file descriptor is kept open (module-level _pid_fd) so the lock
    persists for the lifetime of the process.

    If the lock is held by a stale (dead or non-tunnelvault) process,
    the lock file is removed and re-created. If held by a live tunnelvault
    process, it is terminated first.
    """
    global _pid_fd
    path = pid_file_path(script_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    actual_pid = os.getpid() if pid is None else pid
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        # Lock held by another process - attempt recovery
        fd = _recover_stale_lock(path, actual_pid)

    try:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        pass  # fd from mock or already truncated by O_TRUNC
    os.write(fd, str(actual_pid).encode())

    # Close previous fd if any
    if _pid_fd is not None:
        try:
            os.close(_pid_fd)
        except OSError:
            pass
    _pid_fd = fd
    return path


def _recover_stale_lock(path: Path, new_pid: int) -> int:
    """Attempt to recover a stale PID lock. Returns new locked fd.

    Raises BlockingIOError if recovery fails (live tunnelvault process
    that won't die).
    """
    import signal
    import time

    old_pid = read_pid_from_path(path)
    if old_pid is None:
        # Can't read PID - just nuke the file
        return _force_relock(path)

    if not is_pid_alive(old_pid):
        ui.warn(f"Stale PID lock from dead process {old_pid}, taking over")
        return _force_relock(path)

    if not is_tunnelvault_process(old_pid):
        ui.warn(f"PID {old_pid} is not tunnelvault, removing stale lock")
        return _force_relock(path)

    # Live tunnelvault process - terminate it
    ui.warn(f"Killing stale tunnelvault process {old_pid}")
    try:
        os.kill(old_pid, signal.SIGTERM)
    except OSError:
        return _force_relock(path)

    for _ in range(20):  # 10 seconds
        if not is_pid_alive(old_pid):
            break
        time.sleep(0.5)
    else:
        try:
            os.kill(old_pid, signal.SIGKILL)
            time.sleep(0.5)
        except OSError:
            pass

    return _force_relock(path)


def _force_relock(path: Path) -> int:
    """Remove and re-create PID file with a fresh lock. Returns locked fd."""
    path.unlink(missing_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise BlockingIOError("Failed to acquire PID lock after recovery")
    return fd


def read_pid_from_path(path: Path) -> int | None:
    """Read PID from a specific path. Returns None if missing or invalid."""
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def read_pid(script_dir: Path) -> int | None:
    """Read PID from file. Returns None if missing or invalid."""
    path = pid_file_path(script_dir)
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def remove_pid(script_dir: Path) -> None:
    """Remove PID file and release lock."""
    global _pid_fd
    if _pid_fd is not None:
        try:
            fcntl.flock(_pid_fd, fcntl.LOCK_UN)
            os.close(_pid_fd)
        except OSError:
            pass
        _pid_fd = None
    pid_file_path(script_dir).unlink(missing_ok=True)


def is_pid_alive(pid: int) -> bool:
    """Check if process with given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def is_pid_file_locked(script_dir: Path) -> bool:
    """Check if PID file is locked by another process (daemon alive)."""
    path = pid_file_path(script_dir)
    if not path.exists():
        return False
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Got the lock -> no one holds it -> daemon is dead
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        except OSError:
            # Can't get lock -> daemon holds it -> alive
            return True
        finally:
            os.close(fd)
    except OSError:
        return False


def is_tunnelvault_process(pid: int) -> bool:
    """Verify that PID belongs to a tunnelvault process."""
    try:
        system = platform.system()
        if system == "Linux":
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace")
            return "tunnelvault" in cmdline
        else:
            r = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "tunnelvault" in r.stdout
    except Exception:
        return False


# =========================================================================
# Daemonize (double fork + setsid)
# =========================================================================


def daemonize(script_dir: Path) -> int:
    """Double-fork into background. Returns child PID to parent, 0 to grandchild.

    Parent should print PID and sys.exit(0).
    Grandchild: setsid, second fork, redirect stdio to daemon.log, write PID file.

    Uses a pipe to synchronize: grandchild writes its PID to the pipe after
    writing the PID file, so the parent always gets the correct PID.
    """
    # Create pipe for grandchild -> parent PID communication
    pipe_r, pipe_w = os.pipe()

    # First fork - detach from terminal
    first_pid = os.fork()
    if first_pid > 0:
        # Parent: close write end, read grandchild PID from pipe
        os.close(pipe_w)
        _, status = os.waitpid(first_pid, 0)
        try:
            data = b""
            while True:
                chunk = os.read(pipe_r, 64)
                if not chunk:
                    break
                data += chunk
            grandchild_pid = int(data.strip()) if data.strip() else None
        except (ValueError, OSError):
            grandchild_pid = None
        finally:
            os.close(pipe_r)
        return grandchild_pid or first_pid

    # --- Intermediate child ---
    os.close(pipe_r)  # close read end in child
    os.setsid()

    # Second fork - prevent acquiring controlling terminal
    second_pid = os.fork()
    if second_pid > 0:
        # Intermediate child: close pipe write end and exit
        os.close(pipe_w)
        os._exit(0)

    # --- Grandchild (actual daemon) ---
    # Redirect stdio to daemon.log
    log_path = daemon_log_path(script_dir)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(fd, 1)  # stdout
    os.dup2(fd, 2)  # stderr
    os.close(fd)

    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)  # stdin
    os.close(devnull)

    # Write PID file (with flock)
    write_pid(script_dir)

    # Signal parent with our PID via pipe
    try:
        os.write(pipe_w, str(os.getpid()).encode())
    except OSError:
        pass
    finally:
        os.close(pipe_w)

    return 0


# =========================================================================
# Autostart: enable / disable
# =========================================================================


def enable(script_dir: Path, *, only: str | None = None) -> None:
    """Enable autostart for current platform."""
    system = platform.system()
    if system == "Darwin":
        _enable_launchd(script_dir, only=only)
    elif system == "Linux":
        _enable_systemd(script_dir, only=only)
    else:
        ui.fail(f"Autostart not supported on {system}")
        sys.exit(1)


def disable(script_dir: Path | None = None) -> None:
    """Disable autostart for current platform.

    If script_dir is provided, also stops a running daemon.
    """
    # Stop running daemon first
    if script_dir is not None:
        _stop_running_daemon(script_dir)

    system = platform.system()
    if system == "Darwin":
        _disable_launchd()
    elif system == "Linux":
        _disable_systemd()
    else:
        ui.fail(f"Autostart not supported on {system}")
        sys.exit(1)


def _stop_running_daemon(script_dir: Path) -> None:
    """Stop a running daemon if PID file exists."""
    import signal
    import time

    daemon_pid = read_pid(script_dir)
    if not daemon_pid or not is_pid_alive(daemon_pid):
        return

    if not is_tunnelvault_process(daemon_pid):
        ui.warn(f"PID {daemon_pid} is not a tunnelvault process, skipping")
        remove_pid(script_dir)
        return

    os.kill(daemon_pid, signal.SIGTERM)
    for _ in range(30):
        if not is_pid_alive(daemon_pid):
            break
        time.sleep(0.5)
    else:
        os.kill(daemon_pid, signal.SIGKILL)
    remove_pid(script_dir)


# =========================================================================
# Launchd (macOS)
# =========================================================================


def _enable_launchd(script_dir: Path, *, only: str | None = None) -> None:
    """Install and load launchd plist."""
    if PLIST_PATH.exists():
        subprocess.run(
            ["launchctl", "unload", str(PLIST_PATH)],
            capture_output=True,
        )

    plist = _build_plist(script_dir, only=only)
    PLIST_PATH.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML))

    r = subprocess.run(
        ["launchctl", "load", "-w", str(PLIST_PATH)],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        ui.ok(t("daemon.enabled"))
        ui.info(f"  {ui.DIM}{PLIST_PATH}{ui.NC}")
        log_path = daemon_log_path(script_dir)
        ui.info(f"  {ui.DIM}{t('daemon.log_hint', path=log_path)}{ui.NC}")
    else:
        ui.fail(t("daemon.enable_failed", error=r.stderr.strip()))


def _disable_launchd() -> None:
    """Unload and remove launchd plist."""
    if not PLIST_PATH.exists():
        ui.warn(t("daemon.already_disabled"))
        return

    subprocess.run(
        ["launchctl", "unload", str(PLIST_PATH)],
        capture_output=True,
    )
    PLIST_PATH.unlink(missing_ok=True)
    ui.ok(t("daemon.disabled"))


# =========================================================================
# Systemd (Linux)
# =========================================================================


def _enable_systemd(script_dir: Path, *, only: str | None = None) -> None:
    """Generate and enable systemd unit."""
    unit = _build_systemd_unit(script_dir, only=only)
    SYSTEMD_PATH.write_text(unit)
    ui.info(t("daemon.systemd_unit_written", path=str(SYSTEMD_PATH)))

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    r = subprocess.run(
        ["systemctl", "enable", "--now", SYSTEMD_UNIT],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        ui.ok(t("daemon.enabled"))
    else:
        ui.fail(t("daemon.enable_failed", error=r.stderr.strip()))


def _disable_systemd() -> None:
    """Disable and remove systemd unit."""
    if not SYSTEMD_PATH.exists():
        ui.warn(t("daemon.already_disabled"))
        return

    subprocess.run(
        ["systemctl", "disable", "--now", SYSTEMD_UNIT],
        capture_output=True,
    )
    SYSTEMD_PATH.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    ui.ok(t("daemon.disabled"))


def _build_systemd_unit(script_dir: Path, *, only: str | None = None) -> str:
    """Build systemd unit file content with hardening directives."""
    script = str((script_dir / "tunnelvault.py").resolve())
    python = sys.executable
    args = f"{python} {script} --foreground"
    if only:
        args += f" --only {only}"

    # Resolve log_dir for ReadWritePaths
    log_dir = Path(cfg.paths.log_dir)
    if not log_dir.is_absolute():
        log_dir = script_dir / log_dir
    log_dir_resolved = str(log_dir.resolve())

    return f"""\
[Unit]
Description=TunnelVault VPN keepalive
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={args}
Restart=on-failure
RestartSec=10
WorkingDirectory={script_dir.resolve()}
ProtectSystem=strict
ProtectHome=read-only
NoNewPrivileges=yes
ReadWritePaths=/etc/resolv.conf /etc/resolver /var/log {log_dir_resolved}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


# =========================================================================
# Public helpers
# =========================================================================


def daemon_log_path(script_dir: Path) -> Path:
    """Path to daemon.log file."""
    log_dir = Path(cfg.paths.log_dir)
    if not log_dir.is_absolute():
        log_dir = script_dir / log_dir
    return log_dir / "daemon.log"


def _build_plist(script_dir: Path, *, only: str | None = None) -> dict:
    """Build launchd plist dictionary."""
    script = str((script_dir / "tunnelvault.py").resolve())
    python = sys.executable

    # launchd manages the process - use --foreground so tunnelvault
    # doesn't fork (launchd needs the PID it launched to stay alive)
    args = [python, script, "--foreground"]
    if only:
        args.extend(["--only", only])

    log_dir = Path(cfg.paths.log_dir)
    if not log_dir.is_absolute():
        log_dir = script_dir / log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    daemon_log = str(log_dir / "daemon.log")

    return {
        "Label": PLIST_LABEL,
        "ProgramArguments": args,
        "WorkingDirectory": str(script_dir.resolve()),
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": daemon_log,
        "StandardErrorPath": daemon_log,
    }
