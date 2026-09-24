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
    [ -n "${SURICATA_PID:-}" ] && kill "$SURICATA_PID" 2>/dev/null || true
    [ -n "${ADAPTER_PID:-}" ] && kill "$ADAPTER_PID" 2>/dev/null || true
    [ -n "${CS_ADAPTER_PID:-}" ] && kill "$CS_ADAPTER_PID" 2>/dev/null || true
    [ -n "${TRAP_PID:-}" ] && kill "$TRAP_PID" 2>/dev/null || true
    [ -n "${CS_BOUNCER:-}" ] && cscli bouncers delete "$CS_BOUNCER" >/dev/null 2>&1 || true
    [ -n "${CROWDSEC_PID:-}" ] && kill "$CROWDSEC_PID" 2>/dev/null || true
    pkill -f "gobgpd -f $WORK" 2>/dev/null || true
    [ -n "${NODE2_PID:-}" ] && kill "$NODE2_PID" 2>/dev/null || true
    ip link del sokol-wg0 2>/dev/null || true
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
        --p2p-bind "${P2P_BIND:-127.0.0.1:0}" \
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

# A blocked IPv6 source is dropped even when its extension headers do not parse: a truncated
# Hop-by-Hop header used to end the program with XDP_PASS before the blocklist hit was acted on.
BLOCKED_V6=2001:db8:bad::66
printf 'BAN_IP:%s\n' "$BLOCKED_V6" | nc -U -q1 "$WORK/control.sock" >/dev/null
send_v6() {   # send_v6 <next header> <count>: bare IPv6 headers from the blocked source
    ip netns exec "$NS" python3 - "$PEER_IF" "$BLOCKED_V6" "$1" "$2" <<'PY'
import socket, struct, sys
ifname, src, nh, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((ifname, 0))
eth = b"\xff" * 6 + s.getsockname()[4][:6] + struct.pack("!H", 0x86DD)
# payload length 0, hop limit 64; with next header 0 (Hop-by-Hop) the extension header is missing
ip6 = struct.pack("!IHBB", 6 << 28, 0, nh, 64) + socket.inet_pton(socket.AF_INET6, src) \
    + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
for _ in range(count):
    s.send(eth + ip6)
PY
}
BEFORE=$(metric 'sokol_xdp_dropped_packets_total{reason="blocklist"}')
send_v6 59 10   # 59 = no next header: parses cleanly
sleep 1.2
MID=$(metric 'sokol_xdp_dropped_packets_total{reason="blocklist"}')
check "blocked IPv6 source is dropped ($BEFORE -> $MID)" test $((MID - BEFORE)) -eq 10
send_v6 0 10
sleep 1.2
AFTER=$(metric 'sokol_xdp_dropped_packets_total{reason="blocklist"}')
check "blocked IPv6 source with a truncated extension header is dropped ($MID -> $AFTER)" \
    test $((AFTER - MID)) -eq 10
printf 'UNBAN_IP:%s\n' "$BLOCKED_V6" | nc -U -q1 "$WORK/control.sock" >/dev/null

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

# FastNetMon hook: an attack report marks the node under attack without blocking the victim.
FNM="$(dirname "$BIN")/sokol-fastnetmon-notify"
wait_metric() {   # wait_metric <name> <value>: up to 8 s for the next metrics refresh
    for _ in $(seq 1 40); do [ "$(metric "$1")" = "$2" ] && return 0; sleep 0.2; done
    return 1
}
echo "attack details from fastnetmon" | "$FNM" "$HOST_IP" incoming 35000 ban 2>/dev/null
check "FastNetMon ban report is active on the node" wait_metric sokol_external_attacks_active 1
check "the report marks this node under attack in the cluster view" wait_metric sokol_cluster_nodes_under_attack 1
check "the reported victim (this node) is not blocked" ping_from "$ALLOWED_IP"
"$FNM" "$HOST_IP" incoming 0 unban </dev/null 2>/dev/null
check "FastNetMon unban clears the report" wait_metric sokol_external_attacks_active 0

# CIDR blocks through the control socket, under the prefix rules.
CIDR_IP=10.231.0.130
ip netns exec "$NS" ip addr add "$CIDR_IP/24" dev "$PEER_IF"
check "an address in 10.231.0.128/26 reaches the node before the prefix block" \
    ip netns exec "$NS" ping -c 1 -W 1 -I "$CIDR_IP" "$HOST_IP"
check "control socket bans a /26 prefix" bash -c "printf 'BAN_IP:10.231.0.128/26\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^OK banned 10.231.0.128/26'"
check "an address inside the banned prefix is dropped in XDP" \
    bash -c "! ip netns exec $NS ping -c 2 -W 1 -I $CIDR_IP $HOST_IP >/dev/null 2>&1"
check "an address outside the prefix still passes" ping_from "$ALLOWED_IP"
check "a prefix covering this node is refused" bash -c "printf 'BAN_IP:10.231.0.0/24\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^ERR 10.231.0.0/24 is protected (address of this node)'"
check "a prefix wider than /16 is refused" bash -c "printf 'BAN_IP:198.0.0.0/8\\n' | nc -U -q1 '$WORK/control.sock' | grep -q 'wider than'"
printf 'UNBAN_IP:10.231.0.128/26\n' | nc -U -q1 "$WORK/control.sock" >/dev/null
sleep 0.3
check "lifting the prefix lets its addresses through again" \
    ip netns exec "$NS" ping -c 1 -W 1 -I "$CIDR_IP" "$HOST_IP"

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

# Suricata -> sokol-suricata -> orchestrator -> XDP, with the time from probe to block.
if command -v suricata >/dev/null; then
    PROBE_IP=10.231.0.5
    ip netns exec "$NS" ip addr add "$PROBE_IP/24" dev "$PEER_IF"
    printf 'alert tcp any any -> any 23 (msg:"SOKOL TEST telnet probe"; flags:S; classtype:attempted-recon; sid:1000001; rev:1;)\n' >"$WORK/sokol.rules"
    mkdir -p "$WORK/suricata"
    suricata -c /etc/suricata/suricata.yaml -S "$WORK/sokol.rules" -i "$HOST_IF" -l "$WORK/suricata" -k none \
        --set outputs.1.eve-log.enabled=yes >"$WORK/suricata.out" 2>&1 &
    SURICATA_PID=$!
    for _ in $(seq 1 120); do
        grep -qi "engine started" "$WORK/suricata/suricata.log" "$WORK/suricata.out" 2>/dev/null && break
        sleep 0.5
    done
    touch "$WORK/suricata/eve.json"
    "$(dirname "$BIN")/sokol-suricata" --eve "$WORK/suricata/eve.json" >"$WORK/adapter.log" 2>&1 &
    ADAPTER_PID=$!
    sleep 1
    check "the probe address reaches the node before the alert" \
        ip netns exec "$NS" ping -c 1 -W 1 -I "$PROBE_IP" "$HOST_IP"
    ip netns exec "$NS" ping -D -i 0.01 -W 1 -I "$PROBE_IP" "$HOST_IP" >"$WORK/probe-ping.log" 2>&1 &
    PING_PID=$!
    sleep 0.3
    T_PROBE=$(date +%s.%N)
    ip netns exec "$NS" nc -z -w 1 -s "$PROBE_IP" "$HOST_IP" 23 2>/dev/null || true
    sleep 3
    kill "$PING_PID" 2>/dev/null || true
    LAST_REPLY=$(grep -o '^\[[0-9.]*\]' "$WORK/probe-ping.log" | tail -1 | tr -d '[]')
    check "Suricata alert is forwarded as a signal" grep -q "SIGNAL:suricata|$PROBE_IP|$HOST_IP|sid:1000001" "$WORK/adapter.log"
    check "Suricata alert blocks the probing address in XDP" \
        bash -c "! ip netns exec $NS ping -c 2 -W 1 -I $PROBE_IP $HOST_IP >/dev/null 2>&1"
    check "the block reason names Suricata and the rule" grep -q "Dynamic block enforced in XDP: $PROBE_IP.*suricata: sid:1000001 SOKOL TEST telnet probe" "$LOG"
    if [ -n "$LAST_REPLY" ]; then
        echo "      probe -> last reply before block: $(awk -v a="$T_PROBE" -v b="$LAST_REPLY" 'BEGIN { printf "%.0f ms", (b - a) * 1000 }')"
    fi
    kill "$ADAPTER_PID" "$SURICATA_PID" 2>/dev/null || true
    ADAPTER_PID=""; SURICATA_PID=""
else
    echo "SKIP  Suricata checks (suricata not installed)"
fi

# CrowdSec decision -> sokol-crowdsec -> orchestrator -> XDP.
if command -v cscli >/dev/null && command -v crowdsec >/dev/null; then
    if ! cscli lapi status >/dev/null 2>&1; then
        crowdsec -c /etc/crowdsec/config.yaml >"$WORK/crowdsec.log" 2>&1 </dev/null &
        CROWDSEC_PID=$!
        for _ in $(seq 1 60); do cscli lapi status >/dev/null 2>&1 && break; sleep 0.5; done
    fi
    CS_BOUNCER="sokol-smoke-$$"
    CS_KEY=$(cscli bouncers add "$CS_BOUNCER" -o raw)
    CS_IP=10.231.0.6
    ip netns exec "$NS" ip addr add "$CS_IP/24" dev "$PEER_IF"
    check "the CrowdSec test address reaches the node before the decision" \
        ip netns exec "$NS" ping -c 1 -W 1 -I "$CS_IP" "$HOST_IP"
    SOKOL_CROWDSEC_KEY="$CS_KEY" "$(dirname "$BIN")/sokol-crowdsec" --poll-secs 1 >"$WORK/crowdsec-adapter.log" 2>&1 </dev/null &
    CS_ADAPTER_PID=$!
    cscli decisions add --ip "$CS_IP" --reason "sokol smoke ban" --duration 5m >/dev/null 2>&1
    for _ in $(seq 1 50); do
        grep -q "Dynamic block enforced in XDP: $CS_IP" "$LOG" && break
        sleep 0.2
    done
    check "CrowdSec ban decision is forwarded as a signal" grep -q "SIGNAL:crowdsec|$CS_IP|-|sokol smoke ban (origin cscli" "$WORK/crowdsec-adapter.log"
    check "CrowdSec ban blocks the address in XDP" \
        bash -c "! ip netns exec $NS ping -c 2 -W 1 -I $CS_IP $HOST_IP >/dev/null 2>&1"
    check "the block reason names CrowdSec and the scenario" grep -q "Dynamic block enforced in XDP: $CS_IP.*crowdsec: sokol smoke ban" "$LOG"
    cscli decisions delete --ip "$CS_IP" >/dev/null 2>&1 || true
    kill "$CS_ADAPTER_PID" 2>/dev/null || true
    cscli bouncers delete "$CS_BOUNCER" >/dev/null 2>&1 || true
    CS_ADAPTER_PID=""; CS_BOUNCER=""
else
    echo "SKIP  CrowdSec checks (crowdsec not installed)"
fi

# Decoy trap: a connection that sends nothing is blocked after 5 s, with the trap's reason.
TRAP_IP=10.231.0.7
ip netns exec "$NS" ip addr add "$TRAP_IP/24" dev "$PEER_IF"
SOKOL_TRAP_PORTS=2323 "$(dirname "$BIN")/trident_trap" >"$WORK/trap.log" 2>&1 </dev/null &
TRAP_PID=$!
sleep 1
ip netns exec "$NS" nc -w 7 -s "$TRAP_IP" "$HOST_IP" 2323 </dev/null >/dev/null 2>&1 || true
sleep 1
check "trident trap blocks a silent connection in XDP" \
    bash -c "! ip netns exec $NS ping -c 2 -W 1 -I $TRAP_IP $HOST_IP >/dev/null 2>&1"
check "the trap's block carries its reason" \
    grep -q "Dynamic block enforced in XDP: $TRAP_IP.*trident: trap port 2323: connected without sending data" "$LOG"
kill "$TRAP_PID" 2>/dev/null || true; TRAP_PID=""

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

# BGP Flowspec: this node's gobgpd (AS 65001) peers with an "upstream" gobgpd (AS 65002).
gobgp_config() {
    local as=$1 local_addr=$2 port=$3 peer_addr=$4 peer_port=$5 peer_as=$6
    printf '[global.config]\n  as = %s\n  router-id = "%s"\n  port = %s\n  local-address-list = ["%s"]\n' \
        "$as" "$local_addr" "$port" "$local_addr"
    printf '[[neighbors]]\n  [neighbors.config]\n    neighbor-address = "%s"\n    peer-as = %s\n' "$peer_addr" "$peer_as"
    printf '  [neighbors.transport.config]\n    local-address = "%s"\n    remote-port = %s\n' "$local_addr" "$peer_port"
    printf '  [[neighbors.afi-safis]]\n    [neighbors.afi-safis.config]\n      afi-safi-name = "ipv4-flowspec"\n'
}
start_gobgp_pair() {
    gobgp_config 65001 127.0.0.1 1790 127.0.0.2 1791 65002 >"$WORK/gobgp-node.toml"
    gobgp_config 65002 127.0.0.2 1791 127.0.0.1 1790 65001 >"$WORK/gobgp-upstream.toml"
    gobgpd -f "$WORK/gobgp-node.toml" --api-hosts 127.0.0.1:50051 >"$WORK/gobgpd-node.log" 2>&1 &
    gobgpd -f "$WORK/gobgp-upstream.toml" --api-hosts 127.0.0.1:50052 >"$WORK/gobgpd-upstream.log" 2>&1 &
    for _ in $(seq 1 40); do
        gobgp -p 50051 neighbor 2>/dev/null | grep -q Establ && return 0
        sleep 0.5
    done
    return 1
}

stop_orchestrator
FLOWSPEC_ARGS=()
if command -v gobgpd >/dev/null; then
    check "BGP session between node gobgpd and upstream gobgpd is established" start_gobgp_pair
    FLOWSPEC_ARGS=(--flowspec-gobgp "$(command -v gobgp)" --flowspec-gobgp-arg=-p --flowspec-gobgp-arg=50051)
else
    echo "SKIP  BGP Flowspec checks (gobgpd not installed)"
fi
start_orchestrator --block-ttl 2 --audit-max-bytes 600 --audit-keep 50 "${FLOWSPEC_ARGS[@]}"
ipc "DROP_IMMEDIATE:$ALLOWED_IP"
sleep 0.5
if [ ${#FLOWSPEC_ARGS[@]} -gt 0 ]; then
    sleep 1.2
    check "Flowspec: upstream receives a discard rule for the dynamic block" bash -c "gobgp -p 50052 global rib -a ipv4-flowspec | grep -q 'source: $ALLOWED_IP/32'"
    check "Flowspec: upstream receives a discard rule for the static block" bash -c "gobgp -p 50052 global rib -a ipv4-flowspec | grep -q 'source: $BLOCKED_IP/32'"
fi
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
if [ ${#FLOWSPEC_ARGS[@]} -gt 0 ]; then
    check "Flowspec: expired block is withdrawn upstream" bash -c "! gobgp -p 50052 global rib -a ipv4-flowspec | grep -q 'source: $ALLOWED_IP/32'"
fi
check "TTL: static --block stays in force" bash -c "! ip netns exec $NS ping -c 1 -W 1 -I $BLOCKED_IP $HOST_IP >/dev/null 2>&1"

stop_orchestrator
if [ ${#FLOWSPEC_ARGS[@]} -gt 0 ]; then
    sleep 1
    check "Flowspec: shutdown withdraws the node's rules upstream" bash -c "! gobgp -p 50052 global rib -a ipv4-flowspec | grep -q source"
fi
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

# Two-node mesh over WireGuard: node 1 on the host, node 2 inside the peer namespace.
if command -v wg >/dev/null && ip link add sokol-wgprobe type wireguard 2>/dev/null; then
    ip link del sokol-wgprobe
    WG1_KEY=$(wg genkey); WG2_KEY=$(wg genkey)
    WG1_PUB=$(echo "$WG1_KEY" | wg pubkey); WG2_PUB=$(echo "$WG2_KEY" | wg pubkey)
    ip link add sokol-wg0 type wireguard
    wg set sokol-wg0 private-key <(echo "$WG1_KEY") listen-port 51820 \
        peer "$WG2_PUB" allowed-ips 10.99.0.2/32 endpoint "$ALLOWED_IP:51821"
    ip addr add 10.99.0.1/24 dev sokol-wg0 && ip link set sokol-wg0 up
    ip netns exec "$NS" ip link add sokol-wg1 type wireguard
    ip netns exec "$NS" wg set sokol-wg1 private-key <(echo "$WG2_KEY") listen-port 51821 \
        peer "$WG1_PUB" allowed-ips 10.99.0.1/32 endpoint "$HOST_IP:51820"
    ip netns exec "$NS" ip addr add 10.99.0.2/24 dev sokol-wg1
    ip netns exec "$NS" ip link set sokol-wg1 up
    check "WireGuard tunnel between the nodes is up" ping -c 2 -W 1 10.99.0.2

    mkdir -p "$WORK/n2"
    N1_PUB=$("$BIN" --key-file "$WORK/node.key" --print-public-key)
    N2_PUB=$("$BIN" --key-file "$WORK/n2/node.key" --print-public-key)
    printf '[{"node_id": 2, "public_key": "%s"}]' "$N2_PUB" >"$WORK/peers-n1.json"
    printf '[{"node_id": 1, "public_key": "%s"}]' "$N1_PUB" >"$WORK/n2/peers.json"
    # Node 2 drops everything from this extra host address; flooding from it puts node 2 under attack.
    ATTACK_SRC=10.231.0.9
    ip addr add "$ATTACK_SRC/24" dev "$HOST_IF"

    P2P_BIND=10.99.0.1:7946 start_orchestrator --node-id 1 --peers-file "$WORK/peers-n1.json" \
        --storm-threshold 0.4 --never-block 10.99.0.2
    ip netns exec "$NS" "$BIN" --interface "$PEER_IF" --node-id 2 --block "$ATTACK_SRC" \
        --db-path "$WORK/n2/events.log" --key-file "$WORK/n2/node.key" \
        --ipc-socket "$WORK/n2/ipc.sock" --control-socket "$WORK/n2/control.sock" \
        --p2p-bind 10.99.0.2:7946 --seed-peer 10.99.0.1:7946 --peers-file "$WORK/n2/peers.json" \
        --metrics-bind 127.0.0.1:9470 --attack-drops-per-sec 20 >"$WORK/n2/node.log" 2>&1 &
    NODE2_PID=$!
    n2_metric() {
        ip netns exec "$NS" curl -s http://127.0.0.1:9470/metrics | awk -v m="$1" '$1 == m { print $2 }'
    }
    for _ in $(seq 1 40); do
        [ "$(metric sokol_cluster_nodes)" = "2" ] && break
        sleep 0.5
    done
    check "mesh over WireGuard: both nodes authenticated each other" \
        bash -c "test \"\$(curl -s http://127.0.0.1:9469/metrics | awk '\$1==\"sokol_p2p_active_peers\"{print \$2}')\" = 1"
    check "telemetry: node 1 sees both nodes in the cluster" test "$(metric sokol_cluster_nodes)" = 2
    check "telemetry: cluster is stable before the attack" test "$(metric sokol_cluster_status)" = 1

    ipc "DROP_IMMEDIATE:203.0.113.77"
    sleep 1.5
    check "mesh: a block on node 1 reaches node 2" grep -q "Synchronized block for 203.0.113.77" "$WORK/n2/node.log"

    timeout 8 ping -f -I "$ATTACK_SRC" "$ALLOWED_IP" >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
        [ "$(metric sokol_cluster_nodes_under_attack)" = "1" ] && break
        sleep 0.5
    done
    echo "      node 2 drops by blocklist: $(n2_metric 'sokol_xdp_dropped_packets_total{reason="blocklist"}')"
    check "telemetry: node 1 learns that node 2 is under attack" test "$(metric sokol_cluster_nodes_under_attack)" = 1
    check "cluster: 1 of 2 nodes over a 0.4 threshold is a distributed storm" test "$(metric sokol_cluster_status)" = 3
    check "cluster: storm latch engaged and audited" bash -c "grep -q 'Distributed storm: 1/2 nodes under attack' '$LOG'"
    check "node 2 (threshold 0.5) counts itself under attack: local incident, not a storm" \
        test "$(n2_metric sokol_cluster_status)" = 2
    kill "$NODE2_PID" 2>/dev/null || true
    NODE2_PID=""
    stop_orchestrator
else
    echo "SKIP  two-node WireGuard mesh checks (no wireguard support)"
fi

if [ "$FAILED" -ne 0 ]; then
    echo "--- orchestrator log ---"
    cat "$LOG"
    exit 1
fi
