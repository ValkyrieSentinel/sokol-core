#!/usr/bin/env bash
# XDP smoke test: attach the real orchestrator to a veth pair and check that
# traffic from a --block'ed source is dropped while other traffic passes.
#
# Needs root (netns, XDP attach). Linux only.
#   sudo scripts/xdp-smoke.sh [path/to/orchestrator]
set -euo pipefail

BIN="${1:-target/release/orchestrator}"
NS=sokol-smoke-peer
HOST_IF=sokol-smk0
PEER_IF=sokol-smk1
HOST_IP=10.231.0.1
ALLOWED_IP=10.231.0.2
BLOCKED_IP=10.231.0.3
WORK="$(mktemp -d)"
LOG="$WORK/orchestrator.log"
ORCH_PID=""
FAILED=0

cleanup() {
    [ -n "$ORCH_PID" ] && kill "$ORCH_PID" 2>/dev/null && wait "$ORCH_PID" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

check() {
    local name="$1"; shift
    if "$@"; then
        echo "PASS  $name"
    else
        echo "FAIL  $name"
        FAILED=1
    fi
}

ping_from() {
    ip netns exec "$NS" ping -c 2 -W 1 -I "$1" "$HOST_IP" >/dev/null 2>&1
}

ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$PEER_IF"
ip link set "$PEER_IF" netns "$NS"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add "$ALLOWED_IP/24" dev "$PEER_IF"
ip netns exec "$NS" ip addr add "$BLOCKED_IP/24" dev "$PEER_IF"
ip netns exec "$NS" ip link set "$PEER_IF" up
ip netns exec "$NS" ip link set lo up

RUST_LOG=info "$BIN" \
    --interface "$HOST_IF" \
    --block "$BLOCKED_IP" \
    --db-path "$WORK/events.sntl" \
    --key-file "$WORK/node.key" \
    --p2p-bind "127.0.0.1:0" \
    >"$LOG" 2>&1 &
ORCH_PID=$!

for _ in $(seq 1 50); do
    grep -q "XDP program successfully locked and attached" "$LOG" && break
    kill -0 "$ORCH_PID" 2>/dev/null || break
    sleep 0.2
done

check "orchestrator attaches XDP to $HOST_IF" grep -q "XDP program successfully locked and attached" "$LOG"
check "traffic from $ALLOWED_IP passes" ping_from "$ALLOWED_IP"
check "traffic from blocked $BLOCKED_IP is dropped" bash -c "! ip netns exec $NS ping -c 2 -W 1 -I $BLOCKED_IP $HOST_IP >/dev/null 2>&1"

ipc() {
    printf '%s\n' "$1" | nc -U -q1 /run/sokol.sock
}

check "control socket is root-only (0600)" test "$(stat -c %a /run/sokol.sock)" = 600
check "unprivileged user cannot write to the control socket" \
    bash -c "! su nobody -s /bin/bash -c 'printf \"DROP_IMMEDIATE:$ALLOWED_IP\\n\" | nc -U -q1 /run/sokol.sock' 2>/dev/null"
sleep 0.5
check "traffic from $ALLOWED_IP still passes after the unprivileged attempt" ping_from "$ALLOWED_IP"

ipc "DROP_IMMEDIATE:127.0.0.1"
ipc "DROP_IMMEDIATE:$HOST_IP"
sleep 0.5
check "loopback is never blocked" grep -q "Refusing to block 127.0.0.1 (loopback)" "$LOG"
check "the node's own address is never blocked" grep -q "Refusing to block $HOST_IP (address of this node)" "$LOG"

ipc "DROP_IMMEDIATE:$ALLOWED_IP"
sleep 0.5
check "root IPC DROP_IMMEDIATE blocks $ALLOWED_IP" bash -c "! ip netns exec $NS ping -c 2 -W 1 -I $ALLOWED_IP $HOST_IP >/dev/null 2>&1"

if [ "$FAILED" -ne 0 ]; then
    echo "--- orchestrator log ---"
    cat "$LOG"
    exit 1
fi
