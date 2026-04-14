#!/bin/sh
set -e

# TUN device
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

# Generate server keys
SERVER_PRIVATE=$(wg genkey)
SERVER_PUBLIC=$(echo "$SERVER_PRIVATE" | wg pubkey)

# Generate client keys
CLIENT_PRIVATE=$(wg genkey)
CLIENT_PUBLIC=$(echo "$CLIENT_PRIVATE" | wg pubkey)

# Server config
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE
Address = 10.30.0.1/24
ListenPort = 51820

[Peer]
PublicKey = $CLIENT_PUBLIC
AllowedIPs = 10.30.0.2/32
EOF

# Write client config to shared volume (test-runner picks it up)
mkdir -p /shared
cat > /shared/wg-client.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE
Address = 10.30.0.2/24

[Peer]
PublicKey = $SERVER_PUBLIC
AllowedIPs = 10.30.0.0/24
Endpoint = 172.28.0.14:51820
PersistentKeepalive = 25
EOF

chmod 600 /shared/wg-client.conf

echo "WireGuard server starting..."
echo "Server public key: $SERVER_PUBLIC"

wg-quick up wg0

# Keep alive
exec sleep infinity
