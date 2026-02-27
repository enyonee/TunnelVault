#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

G='\033[0;32m' R='\033[0;31m' D='\033[2m' N='\033[0m'

# Python 3.10+
PY=""
for c in python3 python; do
    command -v "$c" &>/dev/null || continue
    v=$("$c" -c "import sys; v=sys.version_info; print(f'{v.major}.{v.minor}') if v >= (3,10) else exit(1)" 2>/dev/null) && PY="$c" && break
done
[ -z "$PY" ] && echo -e "${R}Python 3.10+ not found${N}" && exit 1
echo -e "${G}+${N} Python $v"

# venv (recreate if broken - no python or no install method)
NEED_VENV=0
if [ ! -d .venv ]; then
    NEED_VENV=1
elif [ ! -f .venv/bin/python ]; then
    rm -rf .venv
    NEED_VENV=1
fi
if [ "$NEED_VENV" -eq 1 ]; then
    "$PY" -m venv .venv
    echo -e "${G}+${N} venv created"
else
    echo -e "${G}+${N} venv"
fi

# install tool: pip inside venv (ensurepip if missing)
if [ ! -f .venv/bin/pip ]; then
    .venv/bin/python -m ensurepip -q 2>/dev/null || true
fi
if [ ! -f .venv/bin/pip ]; then
    # ensurepip failed (some distros strip it) - bootstrap from get-pip
    curl -sS https://bootstrap.pypa.io/get-pip.py | .venv/bin/python - -q 2>/dev/null
fi
INST=".venv/bin/pip install -q"

# deps
$INST rich "dnslib>=0.9" pytest pytest-xdist 2>/dev/null
.venv/bin/python -c "import tomllib" 2>/dev/null || $INST tomli 2>/dev/null
echo -e "${G}+${N} deps"

# config
[ ! -f defaults.toml ] && [ -f defaults.toml.example ] && cp defaults.toml.example defaults.toml && echo -e "${G}+${N} defaults.toml from example"
chmod +x tvpn 2>/dev/null || true

# tests
echo -e "\n${D}Running tests...${N}\n"
.venv/bin/python -m pytest tests/ -x -q
