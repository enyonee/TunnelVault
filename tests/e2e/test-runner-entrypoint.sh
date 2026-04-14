#!/bin/bash
# Ensure TUN device exists
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

# Start tailscaled with real TUN (container needs NET_ADMIN + /dev/net/tun)
if command -v tailscaled &>/dev/null; then
    mkdir -p /var/lib/tailscale /var/run/tailscale
    # Disable telemetry - without this tailscaled hangs trying to reach log.tailscale.io
    TS_NO_LOGS_NO_SUPPORT=true \
    tailscaled \
        --state=/var/lib/tailscale/tailscaled.state \
        --socket=/var/run/tailscale/tailscaled.sock \
        >/var/log/tailscaled.log 2>&1 &
fi

exec "$@"
