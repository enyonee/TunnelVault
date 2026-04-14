#!/bin/sh
set -e

mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

# Generate self-signed cert for server
ipsec pki --gen --outform pem > /etc/ipsec.d/private/server-key.pem
ipsec pki --self --in /etc/ipsec.d/private/server-key.pem \
    --dn "CN=vpn-server" --ca --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem
ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --outform pem > /tmp/server-pub.pem
ipsec pki --issue --in /tmp/server-pub.pem \
    --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
    --cakey /etc/ipsec.d/private/server-key.pem \
    --dn "CN=vpn-server" --san vpn-server --san 172.28.0.16 \
    --outform pem > /etc/ipsec.d/certs/server-cert.pem

# Create swanctl config with PSK auth (simplest for testing)
mkdir -p /etc/swanctl/conf.d
cat > /etc/swanctl/conf.d/test.conf <<SWANEOF
connections {
    test-vpn {
        version = 2
        local_addrs = 172.28.0.16

        local {
            auth = psk
            id = vpn-server
        }
        remote {
            auth = psk
        }

        children {
            test-child {
                local_ts = 10.40.0.0/24
                start_action = none
            }
        }
    }
}

secrets {
    ike-test {
        secret = "test-psk-secret-12345"
    }
}
SWANEOF

# Write client swanctl.conf to shared volume
mkdir -p /shared
cat > /shared/ipsec-client.conf <<CLIENTEOF
connections {
    test-vpn {
        version = 2
        remote_addrs = 172.28.0.16

        local {
            auth = psk
        }
        remote {
            auth = psk
            id = vpn-server
        }

        children {
            test-child {
                remote_ts = 10.40.0.0/24
                start_action = none
            }
        }
    }
}

secrets {
    ike-test {
        secret = "test-psk-secret-12345"
    }
}
CLIENTEOF

echo "Starting strongSwan (charon)..."
# Start charon directly (no systemd in container)
ipsec start
sleep 2
swanctl --load-all

echo "strongSwan ready."
exec sleep infinity
