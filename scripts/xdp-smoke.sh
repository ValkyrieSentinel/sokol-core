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
OPERATOR_PID=""
FAILED=0
# Logged after XDP/TC attach, IPC socket and P2P setup all succeeded.
READY="Sokol-Core running with SokolEngine"

cleanup() {
    [ -n "$ORCH_PID" ] && kill "$ORCH_PID" 2>/dev/null && wait "$ORCH_PID" 2>/dev/null || true
    [ -n "$OPERATOR_PID" ] && kill "$OPERATOR_PID" 2>/dev/null || true
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
        --control-socket "$WORK/control.sock" \
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

PEER_KEY_HEX=$("$BIN" --key-file "$WORK/peer2.key" --print-public-key)
PEER3_KEY_HEX=$("$BIN" --key-file "$WORK/peer3.key" --print-public-key)
printf '[{"node_id": 2, "public_key": "%s"}]' "$PEER_KEY_HEX" >"$WORK/peers.json"

start_orchestrator --peers-file "$WORK/peers.json"

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
check "metrics: static block counted in the IPv4 blocklist gauge" \
    test "$(metric 'sokol_blocks_active{family="ipv4"}')" -ge 1
check "metrics: blocklist drops are counted" bash -c "test \"\$(curl -s http://127.0.0.1:9469/metrics | awk '\$1 == \"sokol_xdp_dropped_packets_total{reason=\\\"blocklist\\\"}\" { print \$2 }')\" -ge 2"

# Scanner probes with impossible TCP flag combinations are dropped in XDP.
send_tcp_flags() {
    ip netns exec "$NS" python3 - "$ALLOWED_IP" "$HOST_IP" "$@" <<'PY'
import socket, struct, sys
src, dst, flag_list = sys.argv[1], sys.argv[2], [int(f, 0) for f in sys.argv[3:]]
def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sock.bind((src, 0))
for i, flags in enumerate(flag_list):
    hdr = struct.pack("!HHIIBBHHH", 40000 + i, 9, 1, 0, 5 << 4, flags, 1024, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr))
    hdr = hdr[:16] + struct.pack("!H", csum(pseudo + hdr)) + hdr[18:]
    sock.sendto(hdr, (dst, 0))
PY
}
BEFORE=$(metric 'sokol_xdp_dropped_packets_total{reason="invalid_tcp_flags"}')
# NULL, XMAS (FIN|PSH|URG), SYN|FIN, FIN alone, SYN|RST — five of each
send_tcp_flags $(for _ in 1 2 3 4 5; do printf '0x00 0x29 0x03 0x01 0x06 '; done)
sleep 1.2
AFTER=$(metric 'sokol_xdp_dropped_packets_total{reason="invalid_tcp_flags"}')
check "NULL/XMAS/SYN-FIN/FIN/SYN-RST probes are dropped in XDP ($BEFORE -> $AFTER)" test $((AFTER - BEFORE)) -eq 25
send_tcp_flags 0x02 0x10 0x14
sleep 1.2
check "SYN, ACK and RST|ACK segments are not counted as invalid" \
    test "$(metric 'sokol_xdp_dropped_packets_total{reason="invalid_tcp_flags"}')" -eq "$AFTER"

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

# Operator dashboard -> node control socket -> XDP, end to end.
ctl() {
    printf '%s\n' "$1" | nc -U -q1 "$WORK/control.sock"
}
check "control socket refuses to ban a protected address" bash -c "ctl() { printf '%s\\n' \"\$1\" | nc -U -q1 '$WORK/control.sock'; }; ctl 'BAN_IP:127.0.0.1' | grep -q '^ERR 127.0.0.1 is protected'"
check "startup loads the pinned peers file" grep -q "(1 pinned peers)" "$LOG"
printf '[{"node_id": 2, "public_keys": ["%s", "%s"]}, {"node_id": 3, "public_key": "%s"}]' \
    "$PEER_KEY_HEX" "$PEER3_KEY_HEX" "$PEER3_KEY_HEX" >"$WORK/peers.json"
check "RELOAD_PEERS picks up a rotated key and a new peer" bash -c "printf 'RELOAD_PEERS\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^OK 2 pinned peers'"
printf 'not json' >"$WORK/peers.json"
check "RELOAD_PEERS keeps the current trust when the file is broken" bash -c "printf 'RELOAD_PEERS\\n' | nc -U -q1 '$WORK/control.sock' | grep -q 'previous trust store kept'"
OPERATOR_BIN="$(dirname "$BIN")/sokol-operator"
OP_TOKEN=smoke-operator-token-0123
SOKOL_OPERATOR_TOKEN=$OP_TOKEN SOKOL_OPERATOR_BIND=127.0.0.1:3900 "$OPERATOR_BIN" >"$WORK/operator.log" 2>&1 &
OPERATOR_PID=$!
op() {
    curl -s -X POST -H "Authorization: Bearer $OP_TOKEN" -H 'Content-Type: application/json' -d "$2" "http://127.0.0.1:3900$1"
}
for _ in $(seq 1 30); do
    curl -s -H "Authorization: Bearer $OP_TOKEN" http://127.0.0.1:3900/api/data | grep -q '"id":1' && break
    sleep 0.3
done
check "operator sees the node via its heartbeat" bash -c "curl -s -H 'Authorization: Bearer $OP_TOKEN' http://127.0.0.1:3900/api/data | grep -q '\"id\":1'"
check "operator ban via dashboard API succeeds" bash -c "curl -s -X POST -H 'Authorization: Bearer $OP_TOKEN' -H 'Content-Type: application/json' -d '{\"ip\":\"$ALLOWED_IP\",\"action\":\"add\"}' http://127.0.0.1:3900/api/nodes/1/blacklist | grep -q '\"success\":true'"
sleep 0.3
check "operator ban is enforced in XDP" bash -c "! ip netns exec $NS ping -c 1 -W 1 -I $ALLOWED_IP $HOST_IP >/dev/null 2>&1"
op /api/nodes/1/blacklist "{\"ip\":\"$ALLOWED_IP\",\"action\":\"remove\"}" >/dev/null
sleep 0.3
check "operator unban lifts the block" ping_from "$ALLOWED_IP"
kill "$OPERATOR_PID" 2>/dev/null || true
OPERATOR_PID=""

ipc "DROP_IMMEDIATE:$ALLOWED_IP"
sleep 0.5
check "root IPC DROP_IMMEDIATE blocks $ALLOWED_IP" bash -c "! ip netns exec $NS ping -c 2 -W 1 -I $ALLOWED_IP $HOST_IP >/dev/null 2>&1"

stop_orchestrator
start_orchestrator --drop-ipv4-fragments
check "orchestrator restarts on the same interface" orchestrator_up
MONITOR_BIN="$(dirname "$BIN")/monitor"
check "monitor --verify accepts the audit chain" bash -c "'$MONITOR_BIN' --verify '$WORK/events.sntl' | grep -q '^OK'"
check "audit log from the first run is re-verified on restart" \
    grep -qE "Audit log .* opened: [1-9][0-9]* records verified" "$LOG"
check "strict mode: unfragmented traffic from $ALLOWED_IP passes" ping_from "$ALLOWED_IP"
check "strict mode: fragmented IPv4 is dropped" bash -c "! ip netns exec $NS ping -c 2 -W 1 -s 3000 -I $ALLOWED_IP $HOST_IP >/dev/null 2>&1"

stop_orchestrator
start_orchestrator --xdp-mode generic
check "--xdp-mode generic attaches in SKB mode" bash -c "ip -d link show $HOST_IF | grep -q xdpgeneric"
stop_orchestrator
start_orchestrator --xdp-mode native
check "--xdp-mode native attaches in driver mode (veth supports it)" bash -c "ip -d link show $HOST_IF | grep -qw xdp && ! ip -d link show $HOST_IF | grep -q xdpgeneric"
check "native mode: blocked source is dropped" bash -c "! ip netns exec $NS ping -c 1 -W 1 -I $BLOCKED_IP $HOST_IP >/dev/null 2>&1"

stop_orchestrator
start_orchestrator --block-ttl 2 --audit-max-bytes 600 --audit-keep 50
ipc "DROP_IMMEDIATE:$ALLOWED_IP"
sleep 0.5
check "TTL: dynamic block of $ALLOWED_IP is enforced" bash -c "! ip netns exec $NS ping -c 1 -W 1 -I $ALLOWED_IP $HOST_IP >/dev/null 2>&1"
sleep 3
check "TTL: dynamic block expires after --block-ttl" ping_from "$ALLOWED_IP"
check "audit log rotated into segments" bash -c "ls '$WORK'/events.sntl.0* >/dev/null 2>&1"
check "monitor --verify accepts the chain across rotated segments" bash -c "'$MONITOR_BIN' --verify '$WORK/events.sntl' | grep -q '^OK'"
FIRST_SEGMENT=$(ls "$WORK"/events.sntl.0* | head -1)
cp "$FIRST_SEGMENT" "$WORK/segment.bak"
printf 'X' | dd of="$FIRST_SEGMENT" bs=1 seek=40 conv=notrunc 2>/dev/null
check "monitor --verify detects an edited segment" bash -c "! '$MONITOR_BIN' --verify '$WORK/events.sntl' >/dev/null"
cp "$WORK/segment.bak" "$FIRST_SEGMENT"
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
        --control-socket "$NONROOT/control.sock" \
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
