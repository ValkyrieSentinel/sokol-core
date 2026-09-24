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
# Logged after XDP/TC attach, IPC socket and P2P setup all succeeded.
READY="Sokol-Core running with SokolEngine"

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

start_orchestrator() {
    : >"$LOG"
    RUST_LOG=info "$BIN" \
        --interface "$HOST_IF" \
        --block "$BLOCKED_IP" \
        --db-path "$WORK/events.sntl" \
        --key-file "$WORK/node.key" \
        --p2p-bind "127.0.0.1:0" \
        --metrics-bind "127.0.0.1:9469" \
        "$@" \
        >"$LOG" 2>&1 &
    ORCH_PID=$!
    for _ in $(seq 1 50); do
        grep -q "$READY" "$LOG" && break
        kill -0 "$ORCH_PID" 2>/dev/null || break
        sleep 0.2
    done
}

stop_orchestrator() {
    kill -INT "$ORCH_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "$ORCH_PID" 2>/dev/null || break
        sleep 0.2
    done
    kill -9 "$ORCH_PID" 2>/dev/null || true
    wait "$ORCH_PID" 2>/dev/null || true
    ORCH_PID=""
}

ping_fragmented_from() {
    ip netns exec "$NS" ping -c 2 -W 1 -s 3000 -I "$1" "$HOST_IP" >/dev/null 2>&1
}

start_orchestrator

orchestrator_up() {
    grep -q "$READY" "$LOG" && kill -0 "$ORCH_PID" 2>/dev/null
}

check "orchestrator starts on $HOST_IF" orchestrator_up
check "fragmented IPv4 from $ALLOWED_IP passes (issue #5)" ping_fragmented_from "$ALLOWED_IP"
check "traffic from $ALLOWED_IP passes" ping_from "$ALLOWED_IP"
check "traffic from blocked $BLOCKED_IP is dropped" bash -c "! ip netns exec $NS ping -c 2 -W 1 -I $BLOCKED_IP $HOST_IP >/dev/null 2>&1"

metric() {
    curl -s http://127.0.0.1:9469/metrics | awk -v m="$1" '$1 == m { print $2 }'
}
sleep 1.2
check "metrics: blocklist drops are counted" bash -c "test \"\$(curl -s http://127.0.0.1:9469/metrics | awk '\$1 == \"sokol_xdp_dropped_packets_total{reason=\\\"blocklist\\\"}\" { print \$2 }')\" -ge 2"

# SYN flood on the XDP trap port: events must be rate-limited, not one per packet.
FLOOD_START=$SECONDS
ip netns exec "$NS" bash -c "for i in \$(seq 1 3000); do (echo > /dev/tcp/$HOST_IP/44333) 2>/dev/null; done; true"
FLOOD_SECONDS=$((SECONDS - FLOOD_START + 1))
sleep 1.5
TRAP_EVENTS=$( (grep -a -o "KERNEL_DROP_NOTIFY|Reason:6|" "$WORK/events.sntl" || true) | wc -l)
CPUS=$(nproc)
echo "      trap events recorded: $TRAP_EVENTS for 3000 SYNs; suppressed: $(metric sokol_xdp_events_suppressed_total); cpus: $CPUS"
check "trap SYN flood: excess events are suppressed" test "$(metric sokol_xdp_events_suppressed_total)" -gt 0
# 64 events per CPU per started second of flood (+1 window for the boundary).
check "trap SYN flood: recorded events stay within the per-CPU budget" \
    test "$TRAP_EVENTS" -le $((64 * CPUS * (FLOOD_SECONDS + 1)))

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

stop_orchestrator
start_orchestrator --drop-ipv4-fragments
check "orchestrator restarts on the same interface" orchestrator_up
check "audit log from the first run is re-verified on restart" \
    grep -qE "Audit log .* opened: [1-9][0-9]* records verified" "$LOG"
check "strict mode: unfragmented traffic from $ALLOWED_IP passes" ping_from "$ALLOWED_IP"
check "strict mode: fragmented IPv4 is dropped" bash -c "! ip netns exec $NS ping -c 2 -W 1 -s 3000 -I $ALLOWED_IP $HOST_IP >/dev/null 2>&1"

stop_orchestrator
start_orchestrator --block-ttl 2
ipc "DROP_IMMEDIATE:$ALLOWED_IP"
sleep 0.5
check "TTL: dynamic block of $ALLOWED_IP is enforced" bash -c "! ip netns exec $NS ping -c 1 -W 1 -I $ALLOWED_IP $HOST_IP >/dev/null 2>&1"
sleep 3
check "TTL: dynamic block expires after --block-ttl" ping_from "$ALLOWED_IP"
check "TTL: static --block stays in force" bash -c "! ip netns exec $NS ping -c 1 -W 1 -I $BLOCKED_IP $HOST_IP >/dev/null 2>&1"

stop_orchestrator
check "SIGINT/SIGTERM shutdown is graceful" grep -q "terminated gracefully" "$LOG"

# Unprivileged run: only the capabilities the systemd unit grants.
NONROOT="$WORK/nonroot"
mkdir -p "$NONROOT"
chown nobody "$NONROOT"
chmod 755 "$WORK"
run_nonroot() {
    local caps="$1"
    : >"$LOG"
    setpriv --reuid nobody --regid nogroup --clear-groups \
        --inh-caps "$caps" --ambient-caps "$caps" --bounding-set "$caps" \
        "$BIN" --interface "$HOST_IF" \
        --db-path "$NONROOT/events.log" --key-file "$NONROOT/node.key" \
        --p2p-bind "127.0.0.1:0" --ipc-socket "$NONROOT/sokol.sock" \
        >"$LOG" 2>&1 &
    ORCH_PID=$!
    for _ in $(seq 1 50); do
        grep -q "$READY" "$LOG" && break
        kill -0 "$ORCH_PID" 2>/dev/null || break
        sleep 0.2
    done
}
run_nonroot "-all,+net_admin,+bpf"
check "non-root without CAP_PERFMON is refused by the kernel" bash -c "! grep -q '$READY' '$LOG'"
stop_orchestrator
run_nonroot "-all,+net_admin,+bpf,+perfmon"
check "non-root with CAP_NET_ADMIN+CAP_BPF+CAP_PERFMON starts" orchestrator_up
check "non-root: traffic still flows" ping_from "$ALLOWED_IP"
stop_orchestrator

if [ "$FAILED" -ne 0 ]; then
    echo "--- orchestrator log ---"
    cat "$LOG"
    exit 1
fi
