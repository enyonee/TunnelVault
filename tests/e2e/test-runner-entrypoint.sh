#!/bin/bash
# Start tailscaled if available (needed for Tailscale integration tests)
if command -v tailscaled &>/dev/null; then
    mkdir -p /var/lib/tailscale /var/run/tailscale
    tailscaled \
        --state=/var/lib/tailscale/tailscaled.state \
        --tun=userspace-networking \
        --socket=/var/run/tailscale/tailscaled.sock \
        >/var/log/tailscaled.log 2>&1 &
fi

exec "$@"
