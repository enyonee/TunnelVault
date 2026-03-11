#!/usr/bin/env bash
# Ephemeral integration test runner
# Creates namespace, deploys VPN servers, runs tests, cleans up
# Usage: ./run-tests.sh [--keep]  (--keep to not delete namespace after)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_ID=$(date +%s)
NS="test-vpn-${RUN_ID}"
KEEP=false

[[ "${1:-}" == "--keep" ]] && KEEP=true

echo "=== Creating ephemeral namespace: $NS ==="
kubectl create namespace "$NS"
kubectl label namespace "$NS" env=test app=tunnelvault --overwrite

# Apply policies and quotas (replace namespace in manifests)
for f in network-policy.yaml resource-quota.yaml; do
    sed "s/namespace: test-vpn/namespace: $NS/g" "$SCRIPT_DIR/$f" | kubectl apply -f -
done

# Deploy VPN servers (replace namespace)
for f in openvpn-server.yaml ocserv.yaml singbox-server.yaml; do
    sed "s/namespace: test-vpn/namespace: $NS/g" "$SCRIPT_DIR/$f" | kubectl apply -f -
done

echo "=== Waiting for VPN servers ==="
kubectl wait --for=condition=Available deploy --all -n "$NS" --timeout=120s 2>/dev/null || true
sleep 5

echo "=== Running tests ==="
# Create and run test Job
sed -e "s/namespace: test-vpn/namespace: $NS/g" \
    -e "s/openvpn-server\.test-vpn/openvpn-server.$NS/g" \
    -e "s/ocserv\.test-vpn/ocserv.$NS/g" \
    -e "s/singbox-server\.test-vpn/singbox-server.$NS/g" \
    "$SCRIPT_DIR/test-runner-job.yaml" | kubectl apply -f -

# Follow logs
kubectl wait --for=condition=Ready pod -l job-name=tunnelvault-integration-test -n "$NS" --timeout=120s 2>/dev/null || true
kubectl logs -f -n "$NS" job/tunnelvault-integration-test 2>/dev/null || true

# Get exit code
EXIT_CODE=$(kubectl get pod -n "$NS" -l job-name=tunnelvault-integration-test \
    -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || echo "1")

echo ""
if [ "$EXIT_CODE" = "0" ]; then
    echo "=== TESTS PASSED ==="
else
    echo "=== TESTS FAILED (exit code: $EXIT_CODE) ==="
fi

# Cleanup
if [ "$KEEP" = false ]; then
    echo "=== Cleaning up namespace $NS ==="
    kubectl delete namespace "$NS" --wait=false
else
    echo "=== Keeping namespace $NS (delete manually: kubectl delete ns $NS) ==="
fi

exit "${EXIT_CODE:-1}"
