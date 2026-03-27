#!/usr/bin/env bash
# tunnelvault setup — all platforms (macOS, Linux, Windows/MSYS2)
# Usage: ./setup.sh [--no-tests]
set -euo pipefail
cd "$(dirname "$0")"

G='\033[0;32m' R='\033[0;31m' Y='\033[1;33m' D='\033[2m' N='\033[0m'
ok()   { echo -e "  ${G}+${N} $1"; }
fail() { echo -e "  ${R}x${N} $1"; }
warn() { echo -e "  ${Y}!${N} $1"; }
MISSING=0

echo
echo -e "  ${G}tunnelvault setup${N}"
echo -e "  ${D}─────────────────${N}"
echo

# ── Detect OS ────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
    Darwin*)  PLATFORM=macos  ;;
    Linux*)   PLATFORM=linux  ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM=windows ;;
    *)        PLATFORM=linux  ;;
esac
ok "Platform: $PLATFORM"

# ── Python 3.10+ ─────────────────────────────────────────────
PY=""
for c in python3 python; do
    command -v "$c" &>/dev/null || continue
    v=$("$c" -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}') if v >= (3,10) else exit(1)" 2>/dev/null) && PY="$c" && break
done
if [ -z "$PY" ]; then
    # Try auto-install on Linux
    if [ "$PLATFORM" = "linux" ] && command -v apt-get &>/dev/null; then
        warn "Python 3.10+ not found — installing via apt..."
        sudo apt-get update -qq 2>/dev/null
        sudo apt-get install -y -qq python3 python3-venv curl 2>/dev/null
        for c in python3 python; do
            command -v "$c" &>/dev/null || continue
            v=$("$c" -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}') if v >= (3,10) else exit(1)" 2>/dev/null) && PY="$c" && break
        done
    fi
    if [ -z "$PY" ]; then
        fail "Python 3.10+ not found"
        case "$PLATFORM" in
            macos)   echo -e "    ${D}brew install python@3.12${N}" ;;
            linux)   echo -e "    ${D}sudo apt install python3 python3-venv${N}" ;;
            windows) echo -e "    ${D}winget install Python.Python.3.12${N}" ;;
        esac
        exit 1
    fi
fi
ok "Python $v ($PY)"

# ── venv ──────────────────────────────────────────────────────
VENV_PY=".venv/bin/python"
[ "$PLATFORM" = "windows" ] && VENV_PY=".venv/Scripts/python.exe"

NEED_VENV=0
if [ ! -d .venv ]; then
    NEED_VENV=1
elif [ ! -f "$VENV_PY" ]; then
    rm -rf .venv
    NEED_VENV=1
fi
if [ "$NEED_VENV" -eq 1 ]; then
    "$PY" -m venv .venv
    ok "venv created"
else
    ok "venv"
fi

# ── pip ───────────────────────────────────────────────────────
PIP=".venv/bin/pip"
[ "$PLATFORM" = "windows" ] && PIP=".venv/Scripts/pip.exe"

if [ ! -f "$PIP" ]; then
    "$VENV_PY" -m ensurepip -q 2>/dev/null || true
fi
if [ ! -f "$PIP" ]; then
    curl -sS https://bootstrap.pypa.io/get-pip.py | "$VENV_PY" - -q 2>/dev/null
fi

# ── Python deps ───────────────────────────────────────────────
"$PIP" install -q rich "dnslib>=0.9" "tomlkit>=0.13" pytest pytest-xdist 2>/dev/null
"$VENV_PY" -c "import tomllib" 2>/dev/null || "$PIP" install -q tomli 2>/dev/null
ok "Python deps (rich, dnslib, tomlkit, pytest)"

# ── System tools ──────────────────────────────────────────────
echo
echo -e "  ${D}System tools:${N}"

install_tool() {
    local name="$1"
    if command -v "$name" &>/dev/null; then
        ok "$name $(command -v "$name" | xargs basename)"
        return 0
    fi
    return 1
}

install_or_hint() {
    local name="$1" mac="${2:-}" linux_apt="${3:-}" linux_dnf="${4:-}" win="${5:-}"
    if install_tool "$name"; then return; fi

    # Try auto-install
    if [ "$PLATFORM" = "macos" ] && [ -n "$mac" ] && command -v brew &>/dev/null; then
        warn "$name not found — installing via brew..."
        brew install $mac 2>/dev/null && install_tool "$name" && return
    fi
    if [ "$PLATFORM" = "linux" ] && [ -n "$linux_apt" ]; then
        if command -v apt-get &>/dev/null; then
            warn "$name not found — installing via apt..."
            sudo apt-get install -y -qq $linux_apt 2>/dev/null && install_tool "$name" && return
        elif command -v dnf &>/dev/null && [ -n "$linux_dnf" ]; then
            warn "$name not found — installing via dnf..."
            sudo dnf install -y -q $linux_dnf 2>/dev/null && install_tool "$name" && return
        fi
    fi

    # Manual hint
    fail "$name not found"
    case "$PLATFORM" in
        macos)   [ -n "$mac" ]       && echo -e "    ${D}brew install $mac${N}" ;;
        linux)   [ -n "$linux_apt" ]  && echo -e "    ${D}sudo apt install $linux_apt  # or: dnf install ${linux_dnf:-$linux_apt}${N}" ;;
        windows) [ -n "$win" ]        && echo -e "    ${D}$win${N}" ;;
    esac
    MISSING=$((MISSING + 1))
}

#               binary          brew                apt                     dnf                     windows hint
install_or_hint openvpn         "openvpn"           "openvpn"               "openvpn"               "choco install openvpn"
install_or_hint openfortivpn    "openfortivpn"      "openfortivpn"          "openfortivpn"          "https://github.com/adrienverge/openfortivpn#windows"
install_or_hint curl            "curl"              "curl"                  "curl"                  "(built-in on Windows 10+)"
install_or_hint openssl         "openssl"           "openssl"               "openssl"               "choco install openssl"
install_or_hint wg              "wireguard-tools"   "wireguard-tools"       "wireguard-tools"       "https://www.wireguard.com/install/"

# nc: different package names
if ! command -v nc &>/dev/null; then
    if [ "$PLATFORM" = "macos" ]; then
        ok "nc (built-in on macOS)"
    else
        install_or_hint nc "" "netcat-openbsd" "nmap-ncat" "(optional)"
    fi
else
    ok "nc"
fi

# ── Bundled sing-box ──────────────────────────────────────────
if [ -f bin/sing-box ]; then
    chmod +x bin/sing-box 2>/dev/null
    SB_VER=$(bin/sing-box version 2>/dev/null | head -1 | awk '{print $NF}')
    ok "sing-box $SB_VER (bundled)"
else
    warn "bin/sing-box not found"
    MISSING=$((MISSING + 1))
fi

# ── Config ────────────────────────────────────────────────────
echo
if [ ! -f config.toml ] && [ -f config.toml.example ]; then
    cp config.toml.example config.toml
    ok "config.toml copied from example (edit it with your settings)"
elif [ -f config.toml ]; then
    ok "config.toml"
else
    warn "config.toml.example not found"
fi

chmod +x tvpn 2>/dev/null || true

# ── Summary ───────────────────────────────────────────────────
echo
if [ "$MISSING" -eq 0 ]; then
    echo -e "  ${G}Ready!${N}"
else
    warn "$MISSING tool(s) missing. Install them and re-run ./setup.sh"
fi
echo -e "  ${D}sudo ./tvpn${N}              # connect"
echo -e "  ${D}sudo ./tvpn --status${N}     # check"
echo -e "  ${D}sudo ./tvpn --disconnect${N} # disconnect"
echo -e "  ${D}./tvpn --watch${N}           # live traffic"
echo
