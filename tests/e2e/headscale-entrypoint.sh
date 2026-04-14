#!/bin/sh
set -e

mkdir -p /etc/headscale /var/lib/headscale

# Minimal headscale config
cat > /etc/headscale/config.yaml <<EOF
server_url: http://172.28.0.17:8080
listen_addr: 0.0.0.0:8080
private_key_path: /var/lib/headscale/private.key
noise:
  private_key_path: /var/lib/headscale/noise_private.key
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
ip_prefixes:
  - 100.64.0.0/10
  - fd7a:115c:a1e0::/48
dns:
  base_domain: test.local
  magic_dns: false
derp:
  server:
    enabled: true
    region_id: 999
    region_code: test
    region_name: Test
    stun_listen_addr: 0.0.0.0:3478
    private_key_path: /var/lib/headscale/derp_server_private.key
  urls: []
  paths: []
  auto_update_enabled: false
EOF

# Start headscale in background
headscale serve &
sleep 3

# Create user and auth key
headscale users create testuser 2>/dev/null || true
AUTH_KEY=$(headscale preauthkeys create --user testuser --reusable --expiration 24h 2>/dev/null | tail -1)

# Write auth key to shared volume
mkdir -p /shared
echo "$AUTH_KEY" > /shared/ts-auth-key

echo "Headscale ready. Auth key: $AUTH_KEY"

# Keep running
wait
