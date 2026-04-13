#!/bin/bash
# VM-based e2e test runner for tunnelvault
# Usage:
#   ./scripts/vm-test.sh setup    - create Lima VM + deploy code
#   ./scripts/vm-test.sh test     - run e2e tests inside VM
#   ./scripts/vm-test.sh deploy   - sync code to VM
#   ./scripts/vm-test.sh ssh      - open shell in VM
#   ./scripts/vm-test.sh teardown - destroy VM
#   ./scripts/vm-test.sh smoke    - quick connect/disconnect cycle

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VM_NAME="tv-test"
VM_PROJECT_DIR="/tmp/tv-test/tunnelvault"

_log() { echo "==> $*"; }
_err() { echo "ERR: $*" >&2; exit 1; }

_vm_running() {
    limactl list --json 2>/dev/null | grep -q "\"$VM_NAME\".*\"Running\""
}

_lima() {
    limactl shell "$VM_NAME" -- "$@"
}

cmd_setup() {
    _log "Creating Lima VM '$VM_NAME'..."
    if limactl list --json 2>/dev/null | grep -q "\"$VM_NAME\""; then
        _log "VM exists, starting..."
        limactl start "$VM_NAME" 2>/dev/null || true
    else
        limactl create --name "$VM_NAME" "$SCRIPT_DIR/lima.yaml" --tty=false
        limactl start "$VM_NAME"
    fi

    _log "Waiting for VM..."
    for i in $(seq 1 30); do
        _lima true 2>/dev/null && break
        sleep 2
    done
    _lima true || _err "VM not ready after 60s"

    cmd_deploy

    _log "Building test stack..."
    _lima bash -c "cd $VM_PROJECT_DIR && docker compose -f docker-compose.test.yml build"

    _log "Setup complete. Run: $0 test"
}

cmd_deploy() {
    _log "Syncing code to VM..."
    # Lima mounts ~ read-only, so copy to writable location
    _lima mkdir -p "$VM_PROJECT_DIR"
    # Sync via Lima's SSH config
    LIMA_SSH_CONFIG="$HOME/.lima/$VM_NAME/ssh.config"
    if [ -f "$LIMA_SSH_CONFIG" ]; then
        rsync -az --delete \
            --exclude '.venv' --exclude '__pycache__' --exclude '.git' \
            --exclude 'bin/sing-box' --exclude '.worktrees' --exclude 'logs' \
            -e "ssh -F $LIMA_SSH_CONFIG" \
            "$PROJECT_DIR/" "lima-$VM_NAME:$VM_PROJECT_DIR/"
    else
        # Fallback: tar pipe through lima shell
        tar -C "$PROJECT_DIR" \
            --exclude='.venv' --exclude='__pycache__' --exclude='.git' \
            --exclude='bin/sing-box' --exclude='.worktrees' --exclude='logs' \
            -cf - . | _lima bash -c "mkdir -p $VM_PROJECT_DIR && tar -C $VM_PROJECT_DIR -xf -"
    fi
    _log "Code synced to $VM_PROJECT_DIR"
}

cmd_test() {
    _vm_running || _err "VM not running. Run: $0 setup"

    _log "Starting test stack..."
    _lima bash -c "cd $VM_PROJECT_DIR && docker compose -f docker-compose.test.yml up -d"

    _log "Waiting for services..."
    _lima bash -c "cd $VM_PROJECT_DIR && docker compose -f docker-compose.test.yml ps --format '{{.Name}} {{.Status}}'"

    # Wait for healthy
    for i in $(seq 1 30); do
        HEALTHY=$(_lima bash -c "cd $VM_PROJECT_DIR && docker compose -f docker-compose.test.yml ps --format '{{.Status}}' | grep -c healthy" || echo 0)
        [ "$HEALTHY" -ge 3 ] && break
        sleep 2
    done

    _log "Running integration tests..."
    _lima bash -c "cd $VM_PROJECT_DIR && TUN_AVAILABLE=1 uv run pytest tests/integration/ -x -q --tb=short"
    EXIT=$?

    _log "Stopping test stack..."
    _lima bash -c "cd $VM_PROJECT_DIR && docker compose -f docker-compose.test.yml down -v"

    return $EXIT
}

cmd_smoke() {
    _vm_running || _err "VM not running. Run: $0 setup"

    cmd_deploy

    _log "Starting test stack..."
    _lima bash -c "cd $VM_PROJECT_DIR && docker compose -f docker-compose.test.yml up -d"

    _log "Waiting for healthy services..."
    sleep 15

    _log "Running smoke test: connect -> check -> disconnect"
    _lima bash -c "
        cd $VM_PROJECT_DIR
        uv sync --group dev 2>/dev/null

        # Connect
        sudo uv run python tunnelvault.py --config config.test.toml 2>&1 | tail -20
        sleep 5

        # Check routes
        echo '--- Routes ---'
        ip route | head -20

        # Check connectivity
        echo '--- Connectivity ---'
        curl -s --max-time 5 https://ifconfig.me || echo 'ifconfig.me unreachable'

        # Disconnect
        sudo uv run python tunnelvault.py --disconnect --config config.test.toml
        echo '--- After disconnect ---'
        ip route | head -10
    "

    _log "Stopping test stack..."
    _lima bash -c "cd $VM_PROJECT_DIR && docker compose -f docker-compose.test.yml down -v"
}

cmd_ssh() {
    limactl shell "$VM_NAME"
}

cmd_teardown() {
    _log "Destroying VM '$VM_NAME'..."
    limactl stop "$VM_NAME" 2>/dev/null || true
    limactl delete "$VM_NAME" --force 2>/dev/null || true
    _log "VM destroyed"
}

case "${1:-help}" in
    setup)    cmd_setup ;;
    deploy)   cmd_deploy ;;
    test)     cmd_test ;;
    smoke)    cmd_smoke ;;
    ssh)      cmd_ssh ;;
    teardown) cmd_teardown ;;
    *)
        echo "Usage: $0 {setup|deploy|test|smoke|ssh|teardown}"
        echo ""
        echo "  setup    - Create Lima VM, install deps, build test stack"
        echo "  deploy   - Sync code to VM"
        echo "  test     - Run integration tests inside VM"
        echo "  smoke    - Quick connect/disconnect cycle"
        echo "  ssh      - Open shell in VM"
        echo "  teardown - Destroy VM"
        ;;
esac
