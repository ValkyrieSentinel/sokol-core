#!/usr/bin/env bash
# XDP smoke test: attach the real orchestrator to a veth pair and check that
# traffic from a --block'ed source is dropped while other traffic passes.
#
# Needs root, Python 3, bpftool and iputils ping (netns, XDP attach/test-run). Linux only.
#   sudo scripts/xdp-smoke.sh [path/to/orchestrator]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/flowspec-rib.sh"
source "$(dirname "${BASH_SOURCE[0]}")/audit-verdict.sh"

BIN="${1:-target/release/orchestrator}"
NS=sokol-smoke-peer
HOST_IF=sokol-smk0
PEER_IF=sokol-smk1
HOST_IP=10.231.0.1
ALLOWED_IP=10.231.0.2
BLOCKED_IP=10.231.0.3
PROBE_CONTROL_IP=10.231.0.250
XDP_PROBE="$(dirname "${BASH_SOURCE[0]}")/xdp_probe.py"
FLOWSPEC_METRICS="$(dirname "${BASH_SOURCE[0]}")/flowspec-metrics.py"
WORK="$(mktemp -d)"
LOG="$WORK/orchestrator.log"
ORCH_PID=""
OPERATOR_PID=""
FAILED=0
# Logged after XDP/TC attach, IPC socket and P2P setup all succeeded.
READY="Sokol-Core running"

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

# A section whose tool is missing is skipped, which a reader of a green run cannot tell from a
# pass. SMOKE_REQUIRE (e.g. "suricata crowdsec gobgp wireguard", as CI sets it) makes a skip of
# a named section fail instead.
skip() {   # skip <section> <message>
    if [[ " ${SMOKE_REQUIRE:-} " == *" $1 "* ]]; then
        echo "FAIL  $2, but SMOKE_REQUIRE names $1"
        FAILED=1
    else
        echo "SKIP  $2"
    fi
}

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

xdp_drop() {  # source, ping count, optional fragment flag; helper errors never invert to pass
    local source="$1" count="$2"; shift 2
    python3 "$XDP_PROBE" --interface "$HOST_IF" --namespace "$NS" \
        --source "$source" --destination "$HOST_IP" --control "$PROBE_CONTROL_IP" \
        --count "$count" "$@"
}

ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$PEER_IF"
ip link set "$PEER_IF" netns "$NS"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add "$ALLOWED_IP/24" dev "$PEER_IF"
ip netns exec "$NS" ip addr add "$BLOCKED_IP/24" dev "$PEER_IF"
ip netns exec "$NS" ip addr add "$PROBE_CONTROL_IP/24" dev "$PEER_IF"
ip netns exec "$NS" ip link set "$PEER_IF" up
ip netns exec "$NS" ip link set lo up

STARTS=0
start_orchestrator() {   # a fresh state file per start unless STATE_FILE is set
    : >"$LOG"
    STARTS=$((STARTS + 1))
    LAST_STATE=${STATE_FILE:-$WORK/state.$STARTS.json}
    RUST_LOG=info "$BIN" \
        --state-file "$LAST_STATE" \
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
# A pre-v2 key file (raw Dilithium3, 5952 bytes) is moved aside and a new identity created.
head -c 5952 /dev/urandom >"$WORK/legacy.key" && chmod 600 "$WORK/legacy.key"
LEGACY_NEW=$("$BIN" --key-file "$WORK/legacy.key" --print-public-key 2>"$WORK/legacy-key.log")
check "a legacy key file is retired and replaced by an ML-DSA identity" \
    bash -c "echo '$LEGACY_NEW' | grep -q '^mldsa65:' && test \$(stat -c %s '$WORK/legacy.key.dilithium3.retired') = 5952 && test \$(stat -c %s '$WORK/legacy.key') = 36"
printf '[{"node_id": 2, "public_key": "%s"}]' "$PEER_KEY_HEX" >"$WORK/peers.json"

start_orchestrator --peers-file "$WORK/peers.json"

orchestrator_up() {
    grep -q "$READY" "$LOG" && kill -0 "$ORCH_PID" 2>/dev/null
}

check "orchestrator starts on $HOST_IF" orchestrator_up
check "fragmented IPv4 from $ALLOWED_IP passes (issue #5)" ping_fragmented_from "$ALLOWED_IP"
check "traffic from $ALLOWED_IP passes" ping_from "$ALLOWED_IP"
check "traffic from blocked $BLOCKED_IP is dropped" xdp_drop "$BLOCKED_IP" 2

metric() {
    curl -s http://127.0.0.1:9469/metrics | awk -v m="$1" '$1 == m { print $2 }'
}
flowspec_metrics() {  # state, count, minimum age; all sampled in one HTTP response
    python3 "$FLOWSPEC_METRICS" http://127.0.0.1:9469/metrics "$@"
}
check "Flowspec metrics: disabled is explicitly unverified" flowspec_metrics disabled 0 0
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
BLOCKS_BEFORE_FLOOD=$( (grep -a -o "DYNAMIC_BLOCK_V[46]|" "$WORK/events.sntl" || true) | wc -l)
FLOOD_START=$SECONDS
ip netns exec "$NS" bash -c "for i in \$(seq 1 3000); do (echo > /dev/tcp/$HOST_IP/44333) 2>/dev/null; done; true"
FLOOD_SECONDS=$((SECONDS - FLOOD_START + 1))
sleep 1.5
TRAP_EVENTS=$( (grep -a -o "KERNEL_DROP_NOTIFY|IP:[^|]*|Reason:6|" "$WORK/events.sntl" || true) | wc -l)
CPUS=$(nproc)
echo "      trap events recorded: $TRAP_EVENTS for 3000 SYNs; suppressed: $(metric sokol_xdp_events_suppressed_total); cpus: $CPUS"
check "trap SYN flood: excess events are suppressed" test "$(metric sokol_xdp_events_suppressed_total)" -gt 0
# 64 events per CPU per started second of flood (+1 window for the boundary).
check "trap SYN flood: recorded events stay within the per-CPU budget" \
    test "$TRAP_EVENTS" -le $((64 * CPUS * (FLOOD_SECONDS + 1)))
# A single SYN's source is trivially spoofed: an XDP trap event is recorded, never a block
# (ARCHITECTURE §4). The flooding source still reaches the node and no block was added.
check "trap SYN flood: the source is not blocked by trap events" ping_from "$ALLOWED_IP"
check "trap SYN flood: no block was recorded for trap events" \
    test "$( (grep -a -o "DYNAMIC_BLOCK_V[46]|" "$WORK/events.sntl" || true) | wc -l)" -eq "$BLOCKS_BEFORE_FLOOD"
# ABI between the XDP program and userspace (common::abi): every field of an event written by the
# real kernel program reads back as what was sent — source, protocol, IP version and a SYN's frame
# length (Ethernet + IPv4 + TCP with options). A shifted field reads as garbage here.
check "kernel events read back field by field: IP $ALLOWED_IP, TCP, IPv4, SYN-sized frame" bash -c "
    '$(dirname "$BIN")/monitor' --dump '$WORK/events.sntl' | cut -f3 | grep '^KERNEL_DROP_NOTIFY|IP:[^|]*|Reason:6|' >'$WORK/trap-events' &&
    test -s '$WORK/trap-events' &&
    ! grep -v -E '^KERNEL_DROP_NOTIFY\|IP:$ALLOWED_IP\|Reason:6\|Proto:6\|Version:4\|PktLen:([5-9][0-9]|1[01][0-9])\$' '$WORK/trap-events'"
check "no ring-buffer record of the wrong size" test "$(metric sokol_xdp_events_malformed_total)" = 0

# N03: an event the ring buffer cannot take is counted, not lost silently. With the reader
# stopped (SIGSTOP; the XDP program keeps running in the kernel) exactly N trap SYNs are sent
# over ~20 s, so the per-CPU budget admits more events than the ring holds. Then every one of
# them must be accounted for: recorded in the audit, suppressed by the rate limit, or lost.
trap_recorded() { (grep -a -o "KERNEL_DROP_NOTIFY|IP:[^|]*|Reason:6|" "$WORK/events.sntl" || true) | wc -l; }
LOSS_N=20000
R0=$(trap_recorded); S0=$(metric sokol_xdp_events_suppressed_total); L0=$(metric sokol_xdp_events_lost_total)
kill -STOP "$ORCH_PID"
ip netns exec "$NS" python3 - "$ALLOWED_IP" "$HOST_IP" "$LOSS_N" <<'PY'
import socket, struct, sys, time
src, dst, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
def csum(data):
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sock.bind((src, 0))
start = time.monotonic()
for i in range(n):
    hdr = struct.pack("!HHIIBBHHH", 20000 + i % 40000, 44333, i, 0, 5 << 4, 0x02, 1024, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr))
    hdr = hdr[:16] + struct.pack("!H", csum(pseudo + hdr)) + hdr[18:]
    sock.sendto(hdr, (dst, 0))
    while time.monotonic() - start < i / 1000:   # 1 000 SYNs/s, 20 s
        time.sleep(0.0005)
PY
kill -CONT "$ORCH_PID"
accounted() {
    R1=$(trap_recorded); S1=$(metric sokol_xdp_events_suppressed_total); L1=$(metric sokol_xdp_events_lost_total)
    [ $(( (R1 - R0) + (S1 - S0) + (${L1:-0} - ${L0:-0}) )) = "$LOSS_N" ]
}
for _ in $(seq 1 50); do accounted && break; sleep 0.2; done
echo "      $LOSS_N trap SYNs with the reader stopped: recorded $((R1 - R0)), suppressed $((S1 - S0)), lost $((${L1:-0} - ${L0:-0}))"
check "a full ring buffer is counted: events were lost while the reader was stopped" test "$(( ${L1:-0} - ${L0:-0} ))" -gt 0
check "every trap SYN is recorded, suppressed or counted lost ($LOSS_N)" accounted

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

# The protected set follows the host: an address added to this node while it is banned is
# released within the refresh period, and refused afterwards; once removed it may be banned again.
MOVED_IP=10.231.0.16
ip netns exec "$NS" ip addr add "$MOVED_IP/24" dev "$PEER_IF"
printf 'BAN_IP:%s\n' "$MOVED_IP" | nc -U -q1 "$WORK/control.sock" >/dev/null
check "a banned address is dropped before it moves to this node" \
    xdp_drop "$MOVED_IP" 2
ip addr add "$MOVED_IP/32" dev "$HOST_IF"
for _ in $(seq 1 30); do grep -q "Block of $MOVED_IP released: it is protected now" "$LOG" && break; sleep 0.2; done
check "an address that becomes this node's own is released within the refresh period" \
    grep -q "Block of $MOVED_IP released: it is protected now" "$LOG"
check "a ban of the node's new address is refused" \
    bash -c "printf 'BAN_IP:$MOVED_IP\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^ERR $MOVED_IP is protected (address of this node)'"
ip addr del "$MOVED_IP/32" dev "$HOST_IF"
for _ in $(seq 1 30); do grep -q "Protected host addresses changed: +\[\] -\[$MOVED_IP\]" "$LOG" && break; sleep 0.2; done
check "once the address leaves the node it is no longer protected" \
    bash -c "printf 'BAN_IP:$MOVED_IP\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^OK'"
check "host addresses are being re-read" test "$(metric sokol_protected_refresh_ok)" = 1
# Outcomes: each block counts the packets it drops in the kernel; its removal records that.
OUT_BUSY=10.231.0.17; OUT_IDLE=10.231.0.18
ip netns exec "$NS" ip addr add "$OUT_BUSY/24" dev "$PEER_IF"
printf 'BAN_IP:%s\n' "$OUT_BUSY" | nc -U -q1 "$WORK/control.sock" >/dev/null
printf 'BAN_IP:%s\n' "$OUT_IDLE" | nc -U -q1 "$WORK/control.sock" >/dev/null
ip netns exec "$NS" ping -c 5 -i 0.2 -W 1 -I "$OUT_BUSY" "$HOST_IP" >/dev/null 2>&1 || true
printf 'UNBAN_IP:%s\n' "$OUT_BUSY" | nc -U -q1 "$WORK/control.sock" >/dev/null
printf 'UNBAN_IP:%s\n' "$OUT_IDLE" | nc -U -q1 "$WORK/control.sock" >/dev/null
sleep 1.5
BUSY_DROPPED=$(grep -o "Outcome of the block of $OUT_BUSY: [0-9]* packets" "$LOG" | tail -1 | awk '{print $(NF-1)}')
check "a lifted block records the packets it dropped ($BUSY_DROPPED >= 5)" test "${BUSY_DROPPED:-0}" -ge 5
check "a block that saw no traffic records that it dropped none" \
    grep -q "Outcome of the block of $OUT_IDLE: 0 packets dropped" "$LOG"
check "an outcome names the decision behind the block" \
    grep -aq "BLOCK_OUTCOME|IP:$OUT_BUSY|Dropped:[0-9]*|Seconds:[0-9]*|Cause:operator: operator" "$WORK/events.sntl"
check "monitor --outcomes summarises outcomes by cause" bash -c \
    "'$(dirname "$BIN")/monitor' --outcomes '$WORK/events.sntl' | grep -Eq '^ +[0-9]+ +[0-9]+% +[0-9]+ +[0-9]+  operator: '"
check "outcomes are in the audit log and the metrics" bash -c \
    "grep -aq 'BLOCK_OUTCOME|IP:$OUT_BUSY|Dropped:' '$WORK/events.sntl' && test \"\$(curl -s http://127.0.0.1:9469/metrics | awk '\$1 == \"sokol_block_outcomes_total{effect=\\\"none\\\"}\" { print \$2 }')\" -ge 1"
check "the maintenance tick is measured and takes well under its period" \
    awk -v t="$(metric sokol_tick_seconds_max)" 'BEGIN { exit !(t != "" && t < 0.5) }'
# A detector connection past its line budget is slowed, not cut: every line is answered.
python3 - <<'PY' >"$WORK/ipc-flood.txt"
import socket
s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect("/run/sokol.sock")
f = s.makefile("rw")
f.write("ACK\n"); f.flush(); f.readline()
n = 6000
f.write("NOT_A_COMMAND\n" * n); f.flush()
print(sum(1 for _ in range(n) if f.readline().startswith("ERR")))
PY
check "a flooding IPC client gets an answer to every line" test "$(cat "$WORK/ipc-flood.txt")" = 6000
check "and it was paced past its burst" bash -c "sleep 1.2; test \"\$(curl -s http://127.0.0.1:9469/metrics | awk '\$1 == \"sokol_ipc_lines_delayed_total\" { print \$2 }')\" -gt 0"
check "the binary names its build" bash -c "'$BIN' --version | grep -q '(build '"
check "--xdp-mode auto runs in native mode where the driver takes it (veth)" \
    bash -c "curl -s http://127.0.0.1:9469/metrics | grep -q '^sokol_xdp_mode{mode=\"native\"} 1'"
check "the running build is in the metrics" \
    bash -c "curl -s http://127.0.0.1:9469/metrics | grep -q '^sokol_build_info{version=.*,build=.*} 1'"
# A support bundle has what a remote diagnosis needs and never the node key.
BUNDLE=$(CONTROL="$WORK/control.sock" METRICS=http://127.0.0.1:9469/metrics AUDIT="$WORK/events.sntl" \
    PEERS="$WORK/peers.json" BIN="$BIN" MONITOR="$(dirname "$BIN")/monitor" OUT="$WORK" \
    "$(dirname "$0")/support-bundle.sh" 2>/dev/null | tail -1)
mkdir -p "$WORK/bundle" && tar -xzf "$BUNDLE" -C "$WORK/bundle"
check "a support bundle holds version, metrics, bans and the audit verification" bash -c \
    "d=\$(ls -d '$WORK'/bundle/sokol-support-*); grep -q '(build ' \$d/version.txt && grep -q '^sokol_blocks_active' \$d/metrics.txt && grep -q '^OK' \$d/bans.txt && grep -q '^OK' \$d/audit-verify.txt"
check "the support bundle does not contain the node key" python3 -c "
import pathlib, sys
key = pathlib.Path('$WORK/node.key').read_bytes()[4:]
sys.exit(any(key in p.read_bytes() for p in pathlib.Path('$WORK/bundle').rglob('*') if p.is_file()))"
check "mesh admission counters are exported" \
    bash -c "curl -s http://127.0.0.1:9469/metrics | grep -q '^sokol_mesh_handshake_timeouts_total '"
printf 'UNBAN_IP:%s\n' "$MOVED_IP" | nc -U -q1 "$WORK/control.sock" >/dev/null

# Event ids: a detector event is acted on once; a resend (lost ACK) gets OK duplicate.
ipc_ack() {   # ipc_ack <line>...: one ACK-mode connection, prints one reply per line
    python3 - "$@" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect("/run/sokol.sock")
f = s.makefile("rw")
for line in ["ACK"] + sys.argv[1:]:
    f.write(line + "\n"); f.flush(); print(f.readline().strip())
PY
}
# Client audit text cannot open a node run, restore state or declare a gap. Later
# fresh-run --replay must still return 0 after these real socket writes.
ipc_ack "DB_LOG:NODE_START|Build:client|Node:9|TtlBase:1|TtlMax:1|Digest:fake" \
    "DB_LOG:STATE_RESTORED|Blocks:100|Refused:0" \
    "DB_LOG:AUDIT_LOST|Records:1" "DB_LOG:AUDIT_QUEUE_OVERFLOW|Dropped:1" >"$WORK/client-log-replies.txt"
check "DB_LOG keeps its ACK reply" \
    test "$(grep -c '^OK recorded$' "$WORK/client-log-replies.txt")" = 4
sleep 0.3
"$(dirname "$BIN")/monitor" --dump "$WORK/events.sntl" | cut -f3 >"$WORK/client-log-dump.txt"
check "socket client records have a fixed non-decision outer tag" \
    test "$(grep -Ec '^CLIENT_LOG\|Message:(NODE_START\|Build:client|STATE_RESTORED\|Blocks:100|AUDIT_LOST\|Records:1|AUDIT_QUEUE_OVERFLOW\|Dropped:1)' "$WORK/client-log-dump.txt")" = 4
EV_IP=198.51.100.77
ipc_ack "SIGNAL#smoke-1:smoke|$EV_IP|-|first" "SIGNAL#smoke-1:smoke|$EV_IP|-|resend" \
    "SIGNAL#smoke-1:other|$EV_IP|-|same id, other source" "SIGNAL#bad id:smoke|$EV_IP|-|x" >"$WORK/event-ids.txt"
check "an event id is acted on once, a resend is a duplicate" \
    test "$(sed -n 1,3p "$WORK/event-ids.txt" | tr '\n' ,)" = "OK ack,OK applied,OK duplicate,"
check "the same id from another source is another event" test "$(sed -n 4p "$WORK/event-ids.txt")" = "OK applied"
check "a malformed event id is an error" grep -q "^ERR invalid event id 'bad id'" "$WORK/event-ids.txt"
check "the resend added no claim" test "$(grep -c "Dynamic block enforced in XDP: $EV_IP" "$LOG")" = 2
printf 'UNBAN_IP:%s\n' "$EV_IP" | nc -U -q1 "$WORK/control.sock" >/dev/null

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
    xdp_drop "$CIDR_IP" 2
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
check "public keys are ML-DSA-65 (mesh protocol v2)" bash -c "echo '$PEER_KEY_HEX' | grep -Eq '^mldsa65:[0-9a-f]{3904}$'"
# A pre-v2 (Dilithium3, unprefixed) key must not break the reload: that peer is named, not trusted.
LEGACY_HEX=$(printf 'ab%.0s' $(seq 1 1952))
printf '[{"node_id": 2, "public_key": "%s"}, {"node_id": 9, "public_key": "%s"}]' \
    "$PEER_KEY_HEX" "$LEGACY_HEX" >"$WORK/peers.json"
check "RELOAD_PEERS names a peer listed with only a legacy key and keeps the others" \
    bash -c "printf 'RELOAD_PEERS\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^OK 1 pinned peers; not trusted until their ML-DSA key is listed (legacy key only): \\[9\\]'"
# R27-02: a mistyped algorithm prefix is an error; the current trust (node 2) stays.
printf '[{"node_id": 2, "public_key": "%s"}]' "$(echo "$PEER_KEY_HEX" | sed 's/^mldsa65:/mldsa6S:/')" >"$WORK/peers.json"
check "RELOAD_PEERS refuses a mistyped key prefix instead of revoking the peer" \
    bash -c "printf 'RELOAD_PEERS\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^ERR .*neither .mldsa65:<hex>. nor a legacy'"
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
check "operator ban is enforced in XDP" xdp_drop "$ALLOWED_IP" 1
op /api/nodes/1/blacklist "{\"ip\":\"$ALLOWED_IP\",\"action\":\"remove\"}" >/dev/null
sleep 0.3
check "operator unban lifts the block" ping_from "$ALLOWED_IP"
# F08: the node holds the bans. A ban made on the control socket directly (the dashboard never
# saw it) shows up in a restarted dashboard, and the dashboard's flush lifts it.
DIRECT_BAN=10.231.0.12
printf 'BAN_IP:%s\n' "$DIRECT_BAN" | nc -U -q1 "$WORK/control.sock" >/dev/null
kill "$OPERATOR_PID" 2>/dev/null || true; wait "$OPERATOR_PID" 2>/dev/null || true
SOKOL_OPERATOR_TOKEN=$OP_TOKEN SOKOL_OPERATOR_BIND=127.0.0.1:3900 "$OPERATOR_BIN" >"$WORK/operator2.log" 2>&1 &
OPERATOR_PID=$!
for _ in $(seq 1 40); do
    curl -s -H "Authorization: Bearer $OP_TOKEN" http://127.0.0.1:3900/api/data | grep -q "$DIRECT_BAN" && break
    sleep 0.3
done
check "a restarted dashboard shows a ban it never made (read from the node)" \
    bash -c "curl -s -H 'Authorization: Bearer $OP_TOKEN' http://127.0.0.1:3900/api/data | grep -q '$DIRECT_BAN'"
check "dashboard flush lifts operator bans it did not make" \
    bash -c "curl -s -X POST -H 'Authorization: Bearer $OP_TOKEN' http://127.0.0.1:3900/api/nodes/1/flush | grep -q '\"success\":true' && printf 'LIST_BANS\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^OK 0'"
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
    "$(dirname "$BIN")/sokol-suricata" --eve "$WORK/suricata/eve.json" --cursor-file "$WORK/suricata.cursor" \
        >"$WORK/adapter.log" 2>&1 &
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
    check "Suricata alert is forwarded as a signal with an event id" grep -Eq "SIGNAL#[0-9a-f]{32}:suricata\|$PROBE_IP\|$HOST_IP\|sid:1000001" "$WORK/adapter.log"
    check "Suricata alert blocks the probing address in XDP" \
        xdp_drop "$PROBE_IP" 2
    check "the block reason names Suricata and the rule" grep -q "Dynamic block enforced in XDP: $PROBE_IP.*suricata: sid:1000001 SOKOL TEST telnet probe" "$LOG"
    if [ -n "$LAST_REPLY" ]; then
        echo "      probe -> last reply before block: $(awk -v a="$T_PROBE" -v b="$LAST_REPLY" 'BEGIN { printf "%.0f ms", (b - a) * 1000 }')"
    fi
    # An alert written while the adapter is down is forwarded after it restarts (cursor file).
    sleep 1.5   # the cursor is saved about once a second
    kill "$ADAPTER_PID" 2>/dev/null || true
    wait "$ADAPTER_PID" 2>/dev/null || true
    PROBE2_IP=10.231.0.19
    ip netns exec "$NS" ip addr add "$PROBE2_IP/24" dev "$PEER_IF"
    check "the second probe address reaches the node while the adapter is down" \
        ip netns exec "$NS" ping -c 1 -W 1 -I "$PROBE2_IP" "$HOST_IP"
    ip netns exec "$NS" nc -z -w 1 -s "$PROBE2_IP" "$HOST_IP" 23 2>/dev/null || true
    for _ in $(seq 1 30); do grep -q "\"src_ip\":\"$PROBE2_IP\"" "$WORK/suricata/eve.json" && break; sleep 0.2; done
    "$(dirname "$BIN")/sokol-suricata" --eve "$WORK/suricata/eve.json" --cursor-file "$WORK/suricata.cursor" \
        >>"$WORK/adapter.log" 2>&1 &
    ADAPTER_PID=$!
    for _ in $(seq 1 30); do grep -q "Dynamic block enforced in XDP: $PROBE2_IP" "$LOG" && break; sleep 0.2; done
    check "an alert written while the adapter was down is forwarded after its restart" \
        grep -q "Dynamic block enforced in XDP: $PROBE2_IP.*suricata" "$LOG"
    check "the adapter resumed at its saved cursor" grep -q "resumed at the saved position" "$WORK/adapter.log"
    kill "$ADAPTER_PID" "$SURICATA_PID" 2>/dev/null || true
    ADAPTER_PID=""; SURICATA_PID=""
else
    skip suricata "Suricata checks (suricata not installed)"
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
        if grep -q "Dynamic block enforced in XDP: $CS_IP" "$LOG" &&
            grep -Fq "|$CS_IP|-|sokol smoke ban " "$WORK/crowdsec-adapter.log"; then
            break
        fi
        sleep 0.2
    done
    # Preserve the observed TTL before later scenarios reset the orchestrator log.
    # CrowdSec reports remaining duration, so polling delay matters when diagnosing failures.
    echo "--- CrowdSec initial decision delivery ---"
    grep -F "$CS_IP" "$WORK/crowdsec-adapter.log" || true
    grep -F "Dynamic block enforced in XDP: $CS_IP " "$LOG" || true
    check "CrowdSec remaining duration is forwarded and enforced exactly" \
        python3 "$(dirname "$0")/check_crowdsec_ttl.py" "$WORK/crowdsec-adapter.log" "$LOG" "$CS_IP"
    check "CrowdSec ban blocks the address in XDP" \
        xdp_drop "$CS_IP" 2
    check "the block reason names CrowdSec and the scenario" grep -q "Dynamic block enforced in XDP: $CS_IP.*crowdsec: sokol smoke ban" "$LOG"
    # A restarted adapter replays every active decision (startup=true); the node recognises the
    # decision id and adds no strike.
    kill "$CS_ADAPTER_PID" 2>/dev/null || true
    wait "$CS_ADAPTER_PID" 2>/dev/null || true
    SOKOL_CROWDSEC_KEY="$CS_KEY" "$(dirname "$BIN")/sokol-crowdsec" --poll-secs 1 >>"$WORK/crowdsec-adapter.log" 2>&1 </dev/null &
    CS_ADAPTER_PID=$!
    for _ in $(seq 1 50); do
        grep -q "crowdsec event [0-9]* for $CS_IP already handled" "$LOG" && break
        sleep 0.2
    done
    check "a decision replayed by a restarted adapter is a duplicate on the node" \
        grep -q "crowdsec event [0-9]* for $CS_IP already handled" "$LOG"
    check "the adapter logs the duplicate answer" grep -q "$CS_IP.*(Duplicate)" "$WORK/crowdsec-adapter.log"
    # F09: a decision made while the node is down is delivered once it is back (the adapter keeps
    # it until the node answers), instead of being lost.
    CS_IP2=10.231.0.13
    ip netns exec "$NS" ip addr add "$CS_IP2/24" dev "$PEER_IF"
    STATE_FILE=$LAST_STATE stop_orchestrator
    # Preserve the complete fresh run before NODE_START/STATE_RESTORED make later
    # decisions impossible to reconstruct from this audit alone (ADR-0016).
    cp "$WORK/events.sntl" "$WORK/replay-fresh.sntl"
    cscli decisions add --ip "$CS_IP2" --reason "made while the node was down" --duration 5m >/dev/null 2>&1
    sleep 3
    check "the adapter reports the node unreachable and keeps the decision" \
        grep -q "decisions queued, retrying" "$WORK/crowdsec-adapter.log"
    STATE_FILE=$LAST_STATE start_orchestrator
    for _ in $(seq 1 75); do
        grep -q "Dynamic block enforced in XDP: $CS_IP2" "$LOG" && break
        sleep 0.2
    done
    check "a decision made while the node was down is enforced once it is back" \
        xdp_drop "$CS_IP2" 2
    check "the node's answer is logged by the adapter" grep -q "$CS_IP2.*(Applied)" "$WORK/crowdsec-adapter.log"
    # R27-05: the node restarted above; the event memory came back with its state, so a replay
    # by a restarted adapter is still a duplicate (not a new event that renews the block).
    sleep 1.5   # the decision's event reaches the state file
    STATE_FILE=$LAST_STATE stop_orchestrator
    STATE_FILE=$LAST_STATE start_orchestrator
    kill "$CS_ADAPTER_PID" 2>/dev/null || true
    wait "$CS_ADAPTER_PID" 2>/dev/null || true
    SOKOL_CROWDSEC_KEY="$CS_KEY" "$(dirname "$BIN")/sokol-crowdsec" --poll-secs 1 >>"$WORK/crowdsec-adapter.log" 2>&1 </dev/null &
    CS_ADAPTER_PID=$!
    for _ in $(seq 1 50); do
        grep -q "crowdsec event [0-9]* for $CS_IP2 already handled" "$LOG" && break
        sleep 0.2
    done
    check "after a node restart a replayed decision is still a duplicate" \
        grep -q "crowdsec event [0-9]* for $CS_IP2 already handled" "$LOG"
    # ADR-0019 B: a decision deleted in CrowdSec is taken back on the node.
    cscli decisions delete --ip "$CS_IP" >/dev/null 2>&1 || true
    for _ in $(seq 1 50); do
        grep -q "crowdsec took back event [0-9]* for $CS_IP" "$LOG" && break
        sleep 0.2
    done
    check "a decision deleted in CrowdSec is sent as a retraction" \
        grep -Eq "RETRACT#[0-9]+:crowdsec\|$CS_IP" "$WORK/crowdsec-adapter.log"
    check "the retraction lifts the block it alone held" \
        ip netns exec "$NS" ping -c 1 -W 1 -I "$CS_IP" "$HOST_IP"
    check "the lift is in the audit log with its result" \
        bash -c "'$(dirname "$BIN")/monitor' --dump '$WORK/events.sntl' | grep -q 'DETECTOR_RETRACT|IP:$CS_IP|Result:lifted|Claims:'"
    # Deleted while the adapter is down: its first (startup=true) poll reports the deletion, so
    # the adapter needs no state of its own (ADR-0019; seen on CrowdSec 1.4.6).
    kill "$CS_ADAPTER_PID" 2>/dev/null || true
    wait "$CS_ADAPTER_PID" 2>/dev/null || true
    cscli decisions delete --ip "$CS_IP2" >/dev/null 2>&1 || true
    SOKOL_CROWDSEC_KEY="$CS_KEY" "$(dirname "$BIN")/sokol-crowdsec" --poll-secs 1 >>"$WORK/crowdsec-adapter.log" 2>&1 </dev/null &
    CS_ADAPTER_PID=$!
    for _ in $(seq 1 25); do
        grep -Eq "RETRACT#[0-9]+:crowdsec\|$CS_IP2" "$WORK/crowdsec-adapter.log" && break
        sleep 0.2
    done
    check "a decision deleted while the adapter was down is retracted by its startup poll" \
        grep -Eq "RETRACT#[0-9]+:crowdsec\|$CS_IP2" "$WORK/crowdsec-adapter.log"
    kill "$CS_ADAPTER_PID" 2>/dev/null || true
    cscli bouncers delete "$CS_BOUNCER" >/dev/null 2>&1 || true
    CS_ADAPTER_PID=""; CS_BOUNCER=""
else
    skip crowdsec "CrowdSec checks (crowdsec not installed)"
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
    xdp_drop "$TRAP_IP" 2
check "the trap's block carries its reason" \
    grep -q "Dynamic block enforced in XDP: $TRAP_IP.*trident: trap port 2323: connected without sending data" "$LOG"
kill "$TRAP_PID" 2>/dev/null || true; TRAP_PID=""

ipc "DROP_IMMEDIATE:$ALLOWED_IP"
sleep 0.5
check "root IPC DROP_IMMEDIATE blocks $ALLOWED_IP" xdp_drop "$ALLOWED_IP" 2
# F11: a local producer cannot make the node hold connections (and tasks) without bound.
HOLDERS=()
for _ in $(seq 1 70); do
    (sleep 15 | nc -U /run/sokol.sock >/dev/null 2>&1) &
    HOLDERS+=($!)
done
sleep 1.5
check "IPC: connections beyond the limit are refused" grep -q "connections open; refusing another" "$LOG"
for p in "${HOLDERS[@]}"; do kill "$p" 2>/dev/null || true; done
pkill -f "nc -U /run/sokol.sock" 2>/dev/null || true
sleep 0.5
check "IPC: the socket serves again once they close" \
    bash -c "printf 'DB_LOG:after the limit\\n' | nc -U -q1 /run/sokol.sock; sleep 1.5; grep -aq 'after the limit' '$WORK/events.sntl'"

# ADR-4: an operator ban survives a restart; --block is lifted only by the configuration.
PERSIST_IP=10.231.0.11
ip netns exec "$NS" ip addr add "$PERSIST_IP/24" dev "$PEER_IF"
printf 'BAN_IP:%s\n' "$PERSIST_IP" | nc -U -q1 "$WORK/control.sock" >/dev/null
check "operator cannot lift a --block address" bash -c \
    "printf 'UNBAN_IP:$BLOCKED_IP\\n' | nc -U -q1 '$WORK/control.sock' | grep -q 'blocked by --block'"
stop_orchestrator
# ADR-0016: use the complete first run, saved before CrowdSec's state-restoring
# restarts. Without CrowdSec, no restart has occurred yet; this is still the fresh run.
if [ ! -f "$WORK/replay-fresh.sntl" ]; then
    cp "$WORK/events.sntl" "$WORK/replay-fresh.sntl"
else
    "$BIN" --replay "$WORK/events.sntl" >"$WORK/replay-restored.out" 2>&1 && RESTORED_STATUS=0 || RESTORED_STATUS=$?
    echo "      $(tail -1 "$WORK/replay-restored.out")"
    check "decisions after state restoration remain incomplete even when earlier ones reproduce" \
        bash -c "test $RESTORED_STATUS = 2 && grep -Eq ': [1-9][0-9]* reproduced, 0 mismatched, [1-9][0-9]* without enough context,' '$WORK/replay-restored.out' && grep -q 'state file the log does not hold' '$WORK/replay-restored.out'"
fi
"$BIN" --replay "$WORK/replay-fresh.sntl" >"$WORK/replay.out" 2>&1 && REPLAY_STATUS=0 || REPLAY_STATUS=$?
echo "      $(tail -1 "$WORK/replay.out")"
check "the fresh run's detector decisions replay: all reproduced, none mismatched or insufficient" \
    bash -c "test $REPLAY_STATUS = 0 && grep -Eq ': [1-9][0-9]* reproduced, 0 mismatched, 0 without enough context,' '$WORK/replay.out'"
cp "$WORK/events.sntl" "$WORK/tampered.sntl"
# Flip a bit (writing a fixed byte could leave it unchanged: that byte may already hold it).
python3 -c "import sys; f = open(sys.argv[1], 'r+b'); f.seek(200); b = f.read(1)[0]; f.seek(200); f.write(bytes([b ^ 1]))" "$WORK/tampered.sntl"
check "a log that does not verify is not replayed" bash -c \
    "! '$BIN' --replay '$WORK/tampered.sntl' >'$WORK/replay-tampered.out' 2>&1; grep -q '^NOT REPLAYED' '$WORK/replay-tampered.out'"
STATE_FILE=$LAST_STATE start_orchestrator
check "an operator ban survives a restart" \
    xdp_drop "$PERSIST_IP" 2
check "the restart reports restored blocks" grep -q "Restored .* of this node's blocks" "$LOG"
# R26-04: an operator decision is on disk before it is answered OK, so SIGKILL right after the
# answer (no graceful shutdown, no tick in between) does not lose it.
KILL_BAN=10.231.0.14
ip netns exec "$NS" ip addr add "$KILL_BAN/24" dev "$PEER_IF"
python3 - "$WORK/control.sock" "$KILL_BAN" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); f = s.makefile("rw")
f.write("BAN_IP:%s\n" % sys.argv[2]); f.flush(); f.readline()
PY
kill -9 "$ORCH_PID"; wait "$ORCH_PID" 2>/dev/null || true; ORCH_PID=""
check "a killed node leaves no XDP program on the interface" \
    bash -c "! ip -d link show $HOST_IF | grep -q 'prog/xdp'"
STATE_FILE=$LAST_STATE start_orchestrator
check "an operator ban answered OK survives SIGKILL right after the answer" \
    xdp_drop "$KILL_BAN" 2
printf 'UNBAN_IP:%s\n' "$KILL_BAN" | nc -U -q1 "$WORK/control.sock" >/dev/null
printf 'UNBAN_IP:%s\n' "$PERSIST_IP" | nc -U -q1 "$WORK/control.sock" >/dev/null
# R27-03: a hung state write (its temp file is a FIFO nobody reads) must not stall the node:
# the operator gets an answer within the durable wait, the tick keeps running, health turns bad.
# Dedicated addresses: earlier smoke sections already assigned .16 and .17.
HANDOFF_OLD_IP=10.231.0.30
HANDOFF_NEW_IP=10.231.0.31
ip netns exec "$NS" ip addr add "$HANDOFF_OLD_IP/24" dev "$PEER_IF"
ip netns exec "$NS" ip addr add "$HANDOFF_NEW_IP/24" dev "$PEER_IF"
state_handoff_matches() {
    # Claim::target uses show(): a host address is bare, not suffixed with /32.
    python3 - "$LAST_STATE" "$1" "${2:-}" <<'PY_STATE'
import json, sys
with open(sys.argv[1]) as source:
    state = json.load(source)
assert state['schema'] == 1
assert any(claim['target'] == sys.argv[2] for claim in state['claims'])
if sys.argv[3]:
    assert not any(claim['target'] == sys.argv[3] for claim in state['claims'])
PY_STATE
}
# Make the old operator decision durable first: dropping it after recovery or
# restore must demonstrate saved supersession, not a ban that was never saved.
printf 'BAN_IP:%s\n' "$HANDOFF_OLD_IP" | timeout 10 nc -U -q1 "$WORK/control.sock" >/dev/null
check "State handoff: predecessor ban is durable before the write is held" state_handoff_matches "$HANDOFF_OLD_IP"
check "State handoff: predecessor ban is enforced before supersession" xdp_drop "$HANDOFF_OLD_IP" 1
STATE_TMP="${LAST_STATE%.json}.tmp"
sleep 1.5   # let the unbans reach the disk first
rm -f "$STATE_TMP"; mkfifo "$STATE_TMP"
HUNG_IP=10.231.0.15
ip netns exec "$NS" ip addr add "$HUNG_IP/24" dev "$PEER_IF"
T_BAN=$(date +%s.%N)
HUNG_REPLY=$(printf 'BAN_IP:%s\n' "$HUNG_IP" | timeout 10 nc -U -q1 "$WORK/control.sock")
T_REPLY=$(date +%s.%N)
check "a ban is answered within the durable wait while the disk hangs, and says so" \
    bash -c "echo '$HUNG_REPLY' | grep -q '^OK .*WARNING: not yet durable' && awk -v a=$T_BAN -v b=$T_REPLY 'BEGIN { exit !(b - a < 4) }'"
check "the ban is enforced although not yet durable" \
    xdp_drop "$HUNG_IP" 2
check "a hung state write makes the node DEGRADED" wait_metric sokol_state_healthy 0
PENDING1=$(metric sokol_state_pending_seconds); sleep 2.5; PENDING2=$(metric sokol_state_pending_seconds)
check "the maintenance tick keeps running while the write hangs" \
    awk -v a="$PENDING1" -v b="$PENDING2" 'BEGIN { exit !(b > a + 1) }'
# Several authoritative snapshots must supersede while the first write is held.
HANDOFF_REPLY=$(printf 'UNBAN_IP:%s\n' "$HANDOFF_OLD_IP" | timeout 10 nc -U -q1 "$WORK/control.sock")
check "State handoff: superseding unban remains unverified while the disk hangs" \
    grep -q '^OK .*WARNING: not yet durable' <<<"$HANDOFF_REPLY"
ipc "DROP_IMMEDIATE:$HANDOFF_NEW_IP"
sleep 1.2
check "State handoff: newest decision is enforced while the writer is blocked" xdp_drop "$HANDOFF_NEW_IP" 1
check "State handoff: superseded decision is lifted while the writer is blocked" ping_from "$HANDOFF_OLD_IP"
# Keep a reader open through unlink. A queued wake can trigger an immediate
# retry after Linux fsync(FIFO) fails; it must never reopen a readerless FIFO.
(
    exec 3<>"$STATE_TMP"
    rm -f "$STATE_TMP"
    timeout 5 cat <&3 >/dev/null
) &
check "health returns once the disk answers" wait_metric sokol_state_healthy 1

check "State handoff: recovery persisted the latest decision rather than the held predecessor" state_handoff_matches "$HANDOFF_NEW_IP" "$HANDOFF_OLD_IP"
# No graceful final persist may repair the recovered file before the restore check.
kill -9 "$ORCH_PID"; wait "$ORCH_PID" 2>/dev/null || true; ORCH_PID=""
STATE_FILE=$LAST_STATE start_orchestrator
check "State handoff: superseding unban survives restore from the recovered file" ping_from "$HANDOFF_OLD_IP"
check "State handoff: latest ban survives restore from the recovered file" xdp_drop "$HANDOFF_NEW_IP" 1
printf 'UNBAN_IP:%s\n' "$HANDOFF_NEW_IP" | nc -U -q1 "$WORK/control.sock" >/dev/null
printf 'UNBAN_IP:%s\n' "$HUNG_IP" | nc -U -q1 "$WORK/control.sock" >/dev/null
stop_orchestrator
# R27-04: a state file that does not parse is not a first start: its bytes are kept and the node
# stays DEGRADED until the operator accepts the loss.
printf '{ not a state file' >"$LAST_STATE"
STATE_FILE=$LAST_STATE start_orchestrator
check "a corrupt state file keeps the node DEGRADED" wait_metric sokol_state_restore_ok 0
check "the corrupt state bytes are kept aside" test "$(cat "$LAST_STATE.corrupt")" = "{ not a state file"
check "ACCEPT_STATE_LOSS is answered" bash -c "printf 'ACCEPT_STATE_LOSS\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^OK state loss accepted'"
check "after ACCEPT_STATE_LOSS the node is healthy again" wait_metric sokol_state_healthy 1
stop_orchestrator
check "a stopped node leaves no XDP program on the interface (traffic passes unfiltered)" \
    bash -c "! ip -d link show $HOST_IF | grep -q 'prog/xdp'"
TRAP_PROTECTED=10.231.0.8; TRAP_OPEN=10.231.0.10
ip netns exec "$NS" ip addr add "$TRAP_PROTECTED/24" dev "$PEER_IF"
ip netns exec "$NS" ip addr add "$TRAP_OPEN/24" dev "$PEER_IF"
HOME_NET=10.250.0.0/24
start_orchestrator --drop-ipv4-fragments --trap-port 2324 --never-block "$TRAP_PROTECTED" \
    --home-net "$HOME_NET"
check "orchestrator restarts on the same interface" orchestrator_up
# The built-in decoy trap audits what actually happened to its block, not a fixed EnforcedDrop.
for src in "$TRAP_PROTECTED" "$TRAP_OPEN"; do
    ip netns exec "$NS" nc -z -w 1 -s "$src" "$HOST_IP" 2324 >/dev/null 2>&1 || true
done
sleep 1
check "a trap hit from a protected address is audited as refused, not enforced" bash -c \
    "grep -aq 'TRAP_HIT|Port:2324|IP:$TRAP_PROTECTED|Action:Refused' '$WORK/events.sntl' && ! grep -aq 'TRAP_HIT|Port:2324|IP:$TRAP_PROTECTED|Action:EnforcedDrop' '$WORK/events.sntl'"
check "a trap hit from an unprotected address is audited as enforced" \
    grep -aq "TRAP_HIT|Port:2324|IP:$TRAP_OPEN|Action:EnforcedDrop" "$WORK/events.sntl"
# --home-net: an alert on an inside host's outbound traffic blocks the remote side, never the host.
ipc_ack "SIGNAL:smoke|10.250.0.5|198.51.100.88|beacon" "SIGNAL:smoke|10.250.0.5|10.250.0.6|lateral" \
    >"$WORK/home-net.txt"
check "--home-net: an inside source's alert is applied to its remote destination" bash -c \
    "sed -n 2p '$WORK/home-net.txt' | grep -q '^OK applied' && grep -q 'Dynamic block enforced in XDP: 198.51.100.88' '$LOG'"
check "--home-net: the inside host is never blocked, inside to inside nothing is" bash -c \
    "! grep -q 'Dynamic block enforced in XDP: 10.250.0.' '$LOG' && sed -n 3p '$WORK/home-net.txt' | grep -q '^OK refused'"
check "trap decisions are counted under source trap: one enforced" \
    wait_metric 'sokol_detections_total{source="trap",result="enforced"}' 1
check "trap decisions are counted under source trap: one refused (protected)" \
    wait_metric 'sokol_detections_total{source="trap",result="refused"}' 1
MONITOR_BIN="$(dirname "$BIN")/monitor"
check "monitor --verify accepts the audit chain" audit_verdict intact "$WORK/events.sntl"
# Regret by source (ROADMAP: measured, not optimized): the smoke's own
# signal was lifted by the operator early in its block, so its row counts one correction.
check "monitor --regret counts the operator's early lift of the smoke source's block" bash -c \
    "'$MONITOR_BIN' --regret '$WORK/events.sntl' | awk '\$NF == \"smoke\" && \$4 >= 1 { found = 1 } END { exit !found }'"
check "audit log from the first run is re-verified on restart" \
    grep -qE "Audit log .* opened: [1-9][0-9]* records verified" "$LOG"
check "strict mode: unfragmented traffic from $ALLOWED_IP passes" ping_from "$ALLOWED_IP"
check "strict mode: fragmented IPv4 is dropped" xdp_drop "$ALLOWED_IP" 2 --fragment

stop_orchestrator
start_orchestrator --xdp-mode generic
check "--xdp-mode generic attaches in SKB mode" bash -c "ip -d link show $HOST_IF | grep -q xdpgeneric"
stop_orchestrator
start_orchestrator --xdp-mode native
check "--xdp-mode native attaches in driver mode (veth supports it)" bash -c "ip -d link show $HOST_IF | grep -qw xdp && ! ip -d link show $HOST_IF | grep -q xdpgeneric"
check "native mode: blocked source is dropped" xdp_drop "$BLOCKED_IP" 1
# Pilot phase 0 (--enforce observe): every decision is made and counted, nothing is dropped.
stop_orchestrator
start_orchestrator --xdp-mode native --enforce observe --drop-ipv4-fragments
check "observe mode is reported" test "$(metric 'sokol_enforce_mode{mode="observe"}')" = 1
check "observe mode is recorded in the audit" grep -aq 'ENFORCE_MODE|Mode:observe' "$WORK/events.sntl"
check "observe mode: the --block address $BLOCKED_IP is not dropped" ping_from "$BLOCKED_IP"
check "observe mode: fragmented IPv4 passes although fragments are to be dropped" \
    bash -c "ip netns exec $NS ping -c 2 -W 1 -s 3000 -I $ALLOWED_IP $HOST_IP >/dev/null 2>&1"
sleep 1.2
check "observe mode: what would have been dropped is counted, nothing is dropped" bash -c "
    obs=\$(curl -s http://127.0.0.1:9469/metrics | awk '\$1 ~ /^sokol_xdp_observed_packets_total/ {s += \$2} END {print s + 0}')
    drop=\$(curl -s http://127.0.0.1:9469/metrics | awk '\$1 ~ /^sokol_xdp_dropped_packets_total/ {s += \$2} END {print s + 0}')
    echo \"      observed \$obs, dropped \$drop\"; test \"\$obs\" -ge 2 && test \"\$drop\" = 0"
stop_orchestrator
start_orchestrator --xdp-mode native

# BGP Flowspec: this node's gobgpd (AS 65001) peers with an "upstream" gobgpd (AS 65002).
gobgp_config() {
    local as=$1 local_addr=$2 port=$3 peer_addr=$4 peer_port=$5 peer_as=$6 passive=${7:-false}
    printf '[global.config]\n  as = %s\n  router-id = "%s"\n  port = %s\n  local-address-list = ["%s"]\n' \
        "$as" "$local_addr" "$port" "$local_addr"
    printf '[[neighbors]]\n  [neighbors.config]\n    neighbor-address = "%s"\n    peer-as = %s\n' "$peer_addr" "$peer_as"
    printf '  [neighbors.transport.config]\n    local-address = "%s"\n    remote-port = %s\n    passive-mode = %s\n' \
        "$local_addr" "$peer_port" "$passive"
    printf '  [[neighbors.afi-safis]]\n    [neighbors.afi-safis.config]\n      afi-safi-name = "ipv4-flowspec"\n'
}
start_gobgp_pair() {
    gobgp_config 65001 127.0.0.1 1790 127.0.0.2 1791 65002 >"$WORK/gobgp-node.toml"
    # The upstream only listens: two active speakers dialling each other at once could leave the
    # session in OpenConfirm (the Flowspec checks failed that way now and then).
    gobgp_config 65002 127.0.0.2 1791 127.0.0.1 1790 65001 true >"$WORK/gobgp-upstream.toml"
    gobgpd -f "$WORK/gobgp-node.toml" --api-hosts 127.0.0.1:50051 >"$WORK/gobgpd-node.log" 2>&1 &
    gobgpd -f "$WORK/gobgp-upstream.toml" --api-hosts 127.0.0.1:50052 >"$WORK/gobgpd-upstream.log" 2>&1 &
    for _ in $(seq 1 40); do
        # BGP can establish before the upstream's independent gRPC API is ready.
        # The RIB assertions below require both APIs, not just the node's peer state.
        if gobgp -p 50052 neighbor >/dev/null 2>&1 && \
            gobgp -p 50051 neighbor 2>/dev/null | grep -q Establ; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

stop_orchestrator
FLOWSPEC_ARGS=()
if command -v gobgpd >/dev/null; then
    check "BGP session between node gobgpd and upstream gobgpd is established" start_gobgp_pair
    # Forward to the real pinned CLI until the fault marker exists. Faults emit
    # valid JSON but exit nonzero; the worker must keep its old observation.
    GOBGP_REAL=$(command -v gobgp)
    cat >"$WORK/gobgp-wrapper.sh" <<'SH'
#!/bin/sh
if [ -f "$1/startup-trace" ]; then
    printf '%s\n' "$*" >> "$1/startup-calls"
fi
if [ -f "$1/readback-fail" ]; then
    touch "$1/readback-failed"
    printf '{}\n'
    exit 7
fi
if [ -f "$1/readback-slow" ] && [ ! -f "$1/readback-slow-started" ]; then
    touch "$1/readback-slow-started"
    sleep 2
    touch "$1/readback-slow-completed"
fi
if [ -f "$1/readback-changing-slow" ] && [ ! -f "$1/readback-changing-started" ]; then
    touch "$1/readback-changing-started"
    while [ -f "$1/readback-changing-slow" ]; do sleep 0.01; done
    touch "$1/readback-changing-completed"
fi
real=$2
shift 2
exec "$real" "$@"
SH
    FLOWSPEC_ARGS=(--flowspec-gobgp /bin/sh --flowspec-gobgp-arg="$WORK/gobgp-wrapper.sh"
        --flowspec-gobgp-arg="$WORK" --flowspec-gobgp-arg="$GOBGP_REAL"
        --flowspec-gobgp-arg=-p --flowspec-gobgp-arg=50051 --flowspec-community=65001:6666)
    # Another system's rule on the same gobgpd (no Sokol community): Sokol must never touch it.
    FOREIGN_RULE=192.0.2.99/32
    gobgp -p 50051 global rib -a ipv4-flowspec add match source "$FOREIGN_RULE" then discard
else
    skip gobgp "BGP Flowspec checks (gobgpd not installed)"
fi
# Leave time for BGP readback and the kernel/live probe inside the lease.
start_orchestrator --block-ttl 10 --audit-max-bytes 600 --audit-keep 50 "${FLOWSPEC_ARGS[@]}"
ipc "DROP_IMMEDIATE:$ALLOWED_IP"
sleep 0.5
if [ ${#FLOWSPEC_ARGS[@]} -gt 0 ]; then
    sleep 1.2
    check "Flowspec: upstream receives a discard rule for the dynamic block" flowspec_rule present "$ALLOWED_IP/32"
    check "Flowspec: upstream receives a discard rule for the static block" flowspec_rule present "$BLOCKED_IP/32"
    if ! gobgp -p 50052 global rib -a ipv4-flowspec | grep -q "source: $BLOCKED_IP/32"; then
        echo "--- Flowspec diagnostics: node gobgpd neighbors / RIB, upstream RIB, logs"
        gobgp -p 50051 neighbor || true
        gobgp -p 50051 global rib -a ipv4-flowspec || true
        gobgp -p 50052 global rib -a ipv4-flowspec || true
        grep -i flowspec "$LOG" | tail -5 || true
        tail -5 "$WORK/gobgpd-node.log" "$WORK/gobgpd-upstream.log" 2>/dev/null || true
    fi
fi
check "TTL: dynamic block of $ALLOWED_IP is enforced" xdp_drop "$ALLOWED_IP" 1
sleep 11
check "TTL: dynamic block expires after --block-ttl" ping_from "$ALLOWED_IP"
check "audit log rotated into segments" bash -c "ls '$WORK'/events.sntl.0* >/dev/null 2>&1"
check "monitor --verify accepts the chain across rotated segments" audit_verdict intact "$WORK/events.sntl"
FIRST_SEGMENT=$(ls "$WORK"/events.sntl.0* | head -1)
cp "$FIRST_SEGMENT" "$WORK/segment.bak"
# Flip a bit (a fixed byte could already be there, and the "edit" would change nothing).
python3 -c "import sys; f = open(sys.argv[1], 'r+b'); f.seek(40); b = f.read(1)[0]; f.seek(40); f.write(bytes([b ^ 1]))" "$FIRST_SEGMENT"
check "monitor --verify detects an edited segment" audit_verdict broken "$WORK/events.sntl"
cp "$WORK/segment.bak" "$FIRST_SEGMENT"
if [ ${#FLOWSPEC_ARGS[@]} -gt 0 ]; then
    check "Flowspec: expired block is withdrawn upstream" flowspec_rule absent "$ALLOWED_IP/32"
    check "Flowspec metrics: completed read reports the static rule" flowspec_metrics converged 1 0
    # Actual main ticks publish unchanged intent during this two-second CLI read.
    # A notification on every tick would kill the child before it writes completion.
    touch "$WORK/readback-slow"
    check "Flowspec worker: slow read reached the CLI" bash -c "
        for _ in \$(seq 1 80); do [ -f '$WORK/readback-slow-started' ] && exit 0; sleep 0.1; done
        exit 1"
    sleep 2.5
    check "Flowspec worker: unchanged main ticks let the slow read complete" test -f "$WORK/readback-slow-completed"
    check "Flowspec metrics: slow read restores convergence" flowspec_metrics converged 1 0
    rm "$WORK/readback-slow"
    # Change the real block table while another original child is still reading.
    # R6 killed this read on the next main tick, even though its result was useful.
    touch "$WORK/readback-changing-slow"
    check "Flowspec worker: changing-intent slow read reached the CLI" bash -c "
        for _ in \$(seq 1 80); do [ -f '$WORK/readback-changing-started' ] && exit 0; sleep 0.1; done
        exit 1"
    ipc "DROP_IMMEDIATE:$ALLOWED_IP"
    # main publishes wanted before its block-count metrics snapshot; this is an
    # observed caller witness, not an assumed delay across the one-second tick.
    check "Flowspec worker: main publishes changed intent while the read is held" wait_metric 'sokol_blocks_active{family="ipv4"}' 2
    check "Flowspec worker: changing read has not completed before release" test ! -f "$WORK/readback-changing-completed"
    rm "$WORK/readback-changing-slow"
    check "Flowspec worker: changed main intent lets the original read complete" bash -c "
        for _ in \$(seq 1 30); do [ -f '$WORK/readback-changing-completed' ] && exit 0; sleep 0.1; done
        exit 1"
    check "Flowspec: retained read leads to the new dynamic discard upstream" wait_flowspec_rule present "$ALLOWED_IP/32"
    check "Flowspec metrics: retained read recovers the changed target" flowspec_metrics converged 2 0
    check "Flowspec worker: operator acknowledges revocation of the changed block" bash -o pipefail -c "
        printf 'UNBAN_IP:$ALLOWED_IP\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^OK unbanned $ALLOWED_IP'"
    check "Flowspec: dynamic rule after retained read is withdrawn upstream" wait_flowspec_rule absent "$ALLOWED_IP/32"
    check "Flowspec metrics: changed target returns to the static rule" flowspec_metrics converged 1 0
    touch "$WORK/readback-fail"
    # Change the actual local RIB behind the failed reader, independently of the worker.
    gobgp -p 50051 global rib -a ipv4-flowspec del match source "$BLOCKED_IP/32" then discard community 65001:6666
    sleep 3
    check "Flowspec metrics: fault actually reached the CLI" test -f "$WORK/readback-failed"
    check "Flowspec: removed static rule is absent upstream during the fault" flowspec_rule absent "$BLOCKED_IP/32"
    check "Flowspec metrics: failed read keeps count but revokes health" flowspec_metrics failed 1 2
    sleep 1
    check "Flowspec metrics: retained observation continues to age" flowspec_metrics failed 1 3
    rm "$WORK/readback-fail"
    check "Flowspec metrics: successful read restores health" flowspec_metrics converged 1 0
    check "Flowspec: recovered worker restores the wanted static rule" wait_flowspec_rule present "$BLOCKED_IP/32"
fi
check "TTL: static --block stays in force" xdp_drop "$BLOCKED_IP" 1

stop_orchestrator
if [ ${#FLOWSPEC_ARGS[@]} -gt 0 ]; then
    # ADR-0018: an observing node announces nothing upstream, even with --flowspec-gobgp.
    start_orchestrator --enforce observe "${FLOWSPEC_ARGS[@]}"
    ipc "DROP_IMMEDIATE:$ALLOWED_IP"
    sleep 2.5
    check "observe mode: no Flowspec rule reaches upstream for a new block" flowspec_rule absent "$ALLOWED_IP/32"
    check "Flowspec metrics: observe mode is explicitly disabled" flowspec_metrics disabled 0 0
    check "observe mode: the audit says Flowspec is disabled" grep -aq 'FLOWSPEC_DISABLED|Why:observe' "$WORK/events.sntl"
    check "observe mode: another system's upstream rule is untouched" flowspec_rule present "$FOREIGN_RULE"
    stop_orchestrator
fi
if [ ${#FLOWSPEC_ARGS[@]} -gt 0 ]; then
    sleep 1
    check "Flowspec: shutdown withdraws the node's rules upstream" flowspec_rule absent "$BLOCKED_IP/32"
    check "Flowspec: another system's rule is left alone" flowspec_rule present "$FOREIGN_RULE"
    # F03: a crashed orchestrator leaves its rules in gobgpd; the next run reads the RIB and
    # withdraws what it no longer wants (it remembers nothing of the previous run).
    start_orchestrator --block-ttl 3600 "${FLOWSPEC_ARGS[@]}"
    ipc "DROP_IMMEDIATE:$ALLOWED_IP"
    sleep 2
    kill -9 "$ORCH_PID"; wait "$ORCH_PID" 2>/dev/null || true; ORCH_PID=""
    check "Flowspec: a crashed node's rule stays upstream" flowspec_rule present "$ALLOWED_IP/32"
    # Restart the actual node from the same state first. Record every worker CLI
    # call so delete/re-add cannot hide behind a later converged observation.
    STATE_FILE=$LAST_STATE
    : >"$WORK/startup-calls"
    touch "$WORK/startup-trace"
    start_orchestrator --block-ttl 3600 "${FLOWSPEC_ARGS[@]}"
    check "Flowspec startup: persisted state was restored" grep -q "Restored .* of this node's blocks" "$LOG"
    check "Flowspec startup: restored block remains applied in XDP" xdp_drop "$ALLOWED_IP" 1
    check "Flowspec startup: restored and static target converge" flowspec_metrics converged 2 0
    check "Flowspec startup: restored discard remains upstream" flowspec_rule present "$ALLOWED_IP/32"
    check "Flowspec startup: static discard remains upstream" flowspec_rule present "$BLOCKED_IP/32"
    check "Flowspec startup: worker readback actually ran" grep -Fq 'global rib -a ipv6-flowspec -j' "$WORK/startup-calls"
    check "Flowspec startup: no restored or static rule was withdrawn" bash -c '
        for net in "$2" "$3"; do
            if grep -F "global rib -a ipv4-flowspec del match source $net/32" "$1"; then
                exit 1
            else
                [ "$?" -eq 1 ] || exit 2
            fi
        done
    ' -- "$WORK/startup-calls" "$ALLOWED_IP" "$BLOCKED_IP"
    rm "$WORK/startup-trace"
    # Preserve the original fresh-state stale-rule test by crashing again.
    kill -9 "$ORCH_PID"; wait "$ORCH_PID" 2>/dev/null || true; ORCH_PID=""
    unset STATE_FILE
    start_orchestrator "${FLOWSPEC_ARGS[@]}"
    sleep 3
    check "Flowspec: the next run withdraws the crashed run's stale rule" flowspec_rule absent "$ALLOWED_IP/32"
    check "Flowspec: the next run keeps announcing its wanted rules" flowspec_rule present "$BLOCKED_IP/32"
    stop_orchestrator
fi
check "SIGINT/SIGTERM shutdown is graceful" grep -q "terminated gracefully" "$LOG"

# Real shutdown boundary: one active signal client plus an idle accepted control client.
# ACK establishes the decision before the signal; keep submitting audit text until EOF.
start_orchestrator --block-ttl 3600
shutdown_connections() {
    python3 - "$ORCH_PID" "$WORK/control.sock" <<'SHUTDOWN_PY'
import os, signal, socket, sys, threading
active = socket.socket(socket.AF_UNIX); active.settimeout(4); active.connect("/run/sokol.sock")
f = active.makefile("r")
for line, wanted in [("ACK", "OK ack"), ("DROP_IMMEDIATE:198.51.100.199", "OK applied")]:
    active.sendall((line + "\n").encode()); assert f.readline().strip() == wanted
idle = socket.socket(socket.AF_UNIX); idle.settimeout(4); idle.connect(sys.argv[2])
# An answered read-only command proves that the idle connection has a live handler.
idle_file = idle.makefile("rb")
idle.sendall(b"LIST_BANS\n"); assert idle_file.readline().startswith(b"OK ")
started = threading.Event(); closed = threading.Event(); failures = []
def submit_until_closed():
    try:
        for i in range(500):
            active.sendall(("DB_LOG:shutdown-active-%d\n" % i).encode())
            reply = f.readline()
            if not reply:
                closed.set(); return
            assert reply.strip() == "OK recorded"
            started.set()
            closed.wait(0.01)
        failures.append("active socket never closed")
    except (BrokenPipeError, ConnectionResetError):
        closed.set()
    except Exception as error:
        failures.append(str(error))
thread = threading.Thread(target=submit_until_closed); thread.start()
assert started.wait(2), "producer did not become active"
os.kill(int(sys.argv[1]), signal.SIGINT)
assert closed.wait(4), "shutdown left active handler open"
thread.join(1); assert not thread.is_alive() and not failures, failures
try:
    assert idle_file.read(1) == b"", "shutdown left idle handler open"
except ConnectionResetError:
    pass
idle_file.close(); idle.close(); f.close(); active.close()
SHUTDOWN_PY
}
check "shutdown closes active IPC and idle control handlers" shutdown_connections
for _ in $(seq 1 100); do
    kill -0 "$ORCH_PID" 2>/dev/null || break
    sleep 0.1
done
check "shutdown exits without forced kill after producers quiesce" bash -c '! kill -0 "$1" 2>/dev/null' _ "$ORCH_PID"
stop_orchestrator
check "shutdown confirms producer quiescence" grep -q 'Decision and audit producers quiesced' "$LOG"
"$(dirname "$BIN")/monitor" --dump "$WORK/events.sntl" | cut -f3 >"$WORK/shutdown-audit.txt"
check "shutdown terminal audit record is last after active submissions" \
    test "$(tail -n1 "$WORK/shutdown-audit.txt")" = NODE_SHUTDOWN
check "shutdown final snapshot retains the accepted decision" python3 - "$LAST_STATE" <<'SHUTDOWN_STATE_PY'
import json, sys
with open(sys.argv[1]) as file:
    state = json.load(file)
assert any(c["target"] == "198.51.100.199" for c in state["claims"]), state
SHUTDOWN_STATE_PY

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
        --storm-threshold 0.4 --never-block 10.99.0.2 --audit-head-secs 2 \
        --anchor-dir "$WORK/anchors" --anchor-secs 1
    ip netns exec "$NS" "$BIN" --interface "$PEER_IF" --node-id 2 --block "$ATTACK_SRC" \
        --db-path "$WORK/n2/events.log" --key-file "$WORK/n2/node.key" \
        --ipc-socket "$WORK/n2/ipc.sock" --control-socket "$WORK/n2/control.sock" \
        --p2p-bind 10.99.0.2:7946 --seed-peer 10.99.0.1:7946 --peers-file "$WORK/n2/peers.json" \
        --metrics-bind 127.0.0.1:9470 --attack-drops-per-sec 20 --audit-head-secs 2 >"$WORK/n2/node.log" 2>&1 &
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
    check "node 2's WireGuard endpoint $ALLOWED_IP is protected on node 1 without --never-block" \
        bash -c "printf 'BAN_IP:$ALLOWED_IP\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^ERR $ALLOWED_IP is protected (WireGuard peer endpoint)'"
    # A WireGuard peer added while the node runs is protected within the refresh period.
    WG_NEW=10.231.0.21
    wg set sokol-wg0 peer "$(wg genkey | wg pubkey)" allowed-ips 10.99.0.9/32 endpoint "$WG_NEW:51900"
    for _ in $(seq 1 30); do grep -q "Protected host addresses changed: +\[$WG_NEW\]" "$LOG" && break; sleep 0.2; done
    check "a WireGuard peer added at run time gets its endpoint protected" \
        bash -c "printf 'BAN_IP:$WG_NEW\\n' | nc -U -q1 '$WORK/control.sock' | grep -q '^ERR $WG_NEW is protected (WireGuard peer endpoint)'"
    check "telemetry: cluster is stable before the attack" test "$(metric sokol_cluster_status)" = 1

    ipc "DROP_IMMEDIATE:203.0.113.77"
    sleep 1.5
    check "mesh: a block on node 1 reaches node 2" grep -q "Synchronized block for 203.0.113.77" "$WORK/n2/node.log"
    # ADR-7: one peer alone cannot impose a wide prefix; node 1 holds it until a second node agrees.
    printf 'DROP_IMMEDIATE:198.18.0.0/20\n' | ip netns exec "$NS" nc -U -q1 "$WORK/n2/ipc.sock" >/dev/null
    sleep 1.5
    check "quorum: node 1 holds node 2's /20 until a second node agrees" \
        grep -q "Holding block for 198.18.0.0/20 from node 2 (quorum)" "$LOG"
    check "quorum: node 1 does not enforce it" \
        bash -c "! grep -q 'Synchronized block for 198.18.0.0/20' '$LOG'"

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
    # ADR-6: while the storm is engaged node 1's XDP drops packets whose headers do not parse.
    # A bare IPv6 header whose Hop-by-Hop header is missing, from an address nobody blocks: in
    # normal mode XDP cannot parse it and passes it to the stack; in strict mode it is dropped.
    # (A truncated IPv4 header would not do: it is dropped as malformed in every mode.)
    send_truncated_v6() {
        ip netns exec "$NS" python3 - "$PEER_IF" "$1" <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
eth = b"\xff" * 6 + s.getsockname()[4][:6] + struct.pack("!H", 0x86DD)
ip6 = struct.pack("!IHBB", 6 << 28, 0, 0, 64) + socket.inet_pton(socket.AF_INET6, "2001:db8:bad::77") \
    + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
for _ in range(int(sys.argv[2])):
    s.send(eth + ip6)
PY
    }
    malformed() { metric 'sokol_xdp_dropped_packets_total{reason="malformed_header"}'; }
    check "storm: node 1 switched XDP to strict mode" grep -aq "DEFENSE_MODE|Strict" "$WORK/events.sntl"
    check "storm: strict mode is reported" wait_metric sokol_defense_strict 1
    BEFORE=$(malformed); send_truncated_v6 10; sleep 1.2
    check "storm: unparsable headers from an unblocked source are dropped in strict mode ($BEFORE -> $(malformed))" \
        test $(( $(malformed) - BEFORE )) -eq 10
    for _ in $(seq 1 75); do grep -aq "DEFENSE_MODE|Normal" "$WORK/events.sntl" && break; sleep 1; done
    check "storm over: node 1 returns to normal mode" grep -aq "DEFENSE_MODE|Normal" "$WORK/events.sntl"
    BEFORE=$(malformed); send_truncated_v6 10; sleep 1.2
    check "normal mode: unparsable headers pass to the stack again" test "$(malformed)" -eq "$BEFORE"
    # ADR-0021: each node keeps the other's fsynced audit head in its own log.
    check "audit witnesses: node 1 recorded node 2's heads" \
        bash -c "test \"\$(curl -s http://127.0.0.1:9469/metrics | awk '\$1==\"sokol_audit_witnesses_recorded_total\"{print \$2}')\" -gt 0"
    check "audit witnesses: node 2 keeps node 1's head in its own log" grep -aq "AUDIT_WITNESS|Issuer:1|" "$WORK/n2/events.log"
    kill "$NODE2_PID" 2>/dev/null || true
    wait "$NODE2_PID" 2>/dev/null || true
    NODE2_PID=""
    stop_orchestrator
    # Both logs closed: node 1's log checked against node 2's witnesses with the real CLI.
    check "audit witnesses: node 1's log is confirmed by node 2's witnesses" \
        "$(dirname "$0")/check-witnesses.sh" "$BIN" "$WORK/events.sntl" "$WORK/n2/events.log" 1
    # ADR-0022: node 1 wrote its durable heads as statements for an external stamp.
    check "audit anchor: node 1's log is confirmed by its head statements" \
        "$(dirname "$0")/check-anchors.sh" "$BIN" "$WORK/events.sntl" "$WORK/anchors" 1
    check "audit anchor: each statement is recorded in node 1's audit" grep -aq "AUDIT_ANCHOR|Records:" "$WORK/events.sntl"
else
    skip wireguard "two-node WireGuard mesh checks (no wireguard support)"
fi

if [ "$FAILED" -ne 0 ]; then
    echo "--- orchestrator log ---"
    cat "$LOG"
    exit 1
fi
