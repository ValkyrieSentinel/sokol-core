#!/usr/bin/env bash
# Mesh measurements on one Linux host: N orchestrators, each in its own network namespace on a
# shared bridge, fully meshed with pinned keys. Times come from the nodes' own audit logs
# (timestamp_ms of each record), so all nodes share one clock.
#
#   sudo bench/mesh.sh propagation <orchestrator> <monitor> <N> [rounds] [netem args...]
#   sudo bench/mesh.sh partition   <orchestrator> <monitor> <N> <seconds down> [netem args...]
#   sudo bench/mesh.sh soak        <orchestrator> <monitor> <N> <minutes> [netem args...]
#   sudo bench/mesh.sh recover     <orchestrator> <monitor> <N> [signals] [netem args...]
#   sudo bench/mesh.sh clock       <orchestrator> <monitor> 3        (needs libfaketime)
#   sudo bench/mesh.sh observe     <orchestrator> <monitor> 3
#   sudo bench/mesh.sh reaction    <orchestrator> <monitor> <N> [rounds]
#   sudo bench/mesh.sh unblock     <orchestrator> <monitor> <N> [rounds]   (FlowSpec: gobgpd)
#   sudo bench/mesh.sh floors      <orchestrator> <monitor> 3
#   sudo bench/mesh.sh restart     <orchestrator> <monitor> <N> [rounds]
#
# restart:     recovery time after a crash (RTO, ADR-0031). Each round: a detector block on node 1
#              is on disk, the attacker pings node 1 every 10 ms, node 1 is SIGKILLed and started
#              again. Times from the kill: control socket answering, the attacker's last reply
#              (the window in which nothing dropped it; 0 = none), all peers back. Limits, fixed
#              before the first run: X1 control answers <= 10 s, X2 the block holds again
#              <= 10 s and the attacker gets no reply in the last second of the probe, X3 all
#              peers back <= 30 s, in every round. RESTART_CONTROL=1 lifts the block before the
#              kill (a node that restores nothing): X2 must then fail.
#
# propagation: a block is issued on node 1 `rounds` times; for every other node the delay
#              until its MESH_BLOCK record is reported (min / median / p95 / max, and the
#              time until the last node has it).
# partition:   node N's link goes down, a block is issued on node 1, the link comes back after
#              <seconds down>; reports whether and when node N learns the block, and whether the
#              mesh reconnects.
# soak:        <minutes> of load: up to 5 detector signals/s at random nodes (one in ten resent),
#              a random node restarted every $RESTART_EVERY s (600), a random node cut off for
#              30 s every $CUT_EVERY s (900).
#              Every minute each node's RSS, fds, audit and state size, active and pending blocks
#              and tick time go to $BENCH_OUT/soak.csv (or the work dir). At the end: the mesh must
#              agree on the active blocks, every audit chain must verify, no node may have
#              panicked; memory growth after the first 5 minutes is reported. Block TTL: $TTL, default 300 s.
#
# recover:     recovery contract (T2, docs/RETIRED.md). Node 1's link is held to
#              $RECOVER_RATE (8mbit) and it gets <signals> (30000) detector events at the IPC rate,
#              so its per-peer queues overflow. Limits, fixed before the first run:
#                L1 node 1's control socket answers within 1000 ms throughout the flood;
#                L2 no node's maintenance tick exceeds 500 ms (the runbook's alarm);
#                L3 within 120 s after the flood every node holds node 1's active blocks, up to
#                   the per-peer envelope (--peer-max-active, 16384, ADR-0007). Amended after the
#                   first 30000-signal run: as registered it ignored the envelope, and every peer
#                   stopping at exactly 16384 was the envelope, not a repair failure;
#                L4 then no node has blocks waiting for the kernel map;
#                L5 no node exits.
#              If no broadcast was dropped the repair path was not exercised: the run reports
#              NOT EXERCISED and fails, whatever L1-L5 say.
#
# clock:       node clocks that disagree or jump (ADR-0003: expiry is absolute, envelopes are
#              accepted within 30 s). Every node runs under libfaketime reading its offset from
#              $WORK/n<i>/clock live; only the wall clock is shifted (NTP steps it, monotonic
#              time is untouched). Block TTL 60 s. Limits, fixed before the first run:
#                S1 node 3 at +20 s: C1 full mesh; C2 node 1's block reaches node 3;
#                   C3 node 3 lets it expire 17-23 s (real time) before node 1 does.
#                S2 node 3 steps to +60 s: C4 within 45 s node 1 sees 1 peer (node 3 is out);
#                   C5 node 3 still blocks its own detector's target, node 1 does not get it.
#                S3 node 3 back to +0: C6 within 60 s node 1 sees 2 peers again;
#                   C7 within 60 s after that node 1 holds node 3's block.
#                S4 exploratory, observations only: node 2 steps +3600 s and then -3600 s while
#                   holding its own block; how long each block lasts in real time is printed.
#              C8 no node exits; C9 no tick over 500 ms.
#
# observe:     a mixed mesh (ADR-0018): node 1 runs --enforce observe, nodes 2 and 3 drop.
#              Limits, fixed before the first run:
#                O1 a signal at node 1 is a local decision there (node 1 holds 1 block);
#                O2 40 s later (over two digest periods) nodes 2 and 3 hold none of it: an
#                   observing node's decisions cause no drop anywhere;
#                O3 a signal at node 2 still reaches nodes 1 and 3 within 5 s (the mesh works).
#
# reaction:    what the traffic sees, not what the audit log says. An attacker namespace
#              (10.240.0.200) and a legitimate one (10.240.0.201) on the same bridge ping every
#              node every 10 ms. Each round: a detector signal about the attacker at node 1,
#              $REACT_HOLD s (10) of block, UNBAN_IP on node 1's control socket, $REACT_HOLD s
#              lifted. Times come from the replies (ping -D, one host clock): stop = the last
#              attacker reply a node sent after the signal, restore = its first reply after the
#              unban; both within one ping interval. Limits, fixed before the first run:
#                R1 node 1 stops answering the attacker within 500 ms of the signal, every round;
#                R2 every node stops within 3000 ms;
#                R3 every node answers the attacker again within 3000 ms of the unban;
#                R4 the legitimate source loses at most 0.5 % of its pings over the run.
#
# unblock:     how long each layer keeps blocking after a block ends. For each way in
#              $UNBLOCK_WAYS ("retract unban flush expire") and each of `rounds` rounds, a fresh
#              attacker address (10.240.0.100 + k: no round can merge into an earlier claim,
#              R26-05) pings every node every 10 ms. A detector signal about it goes to node 1
#              (`;ttl=$UNBLOCK_TTL`, 4 s, for expire). Once every node is silent to it and node
#              1's rule is in its gobgpd RIB, the block ends: RETRACT on IPC, UNBAN_IP or
#              FLUSH_BANS on the control socket, or expiry. The end decision is node 1's audit
#              record (DETECTOR_RETRACT, OPERATOR_UNBAN_V4, OPERATOR_FLUSH, BLOCK_EXPIRED_V4);
#              every layer is timed from it (one host clock):
#                xdp1   node 1's first reply to the attacker (ping interval resolution);
#                peer   each other node's first reply to it;
#                rib    node 1's rule absent from its own gobgpd RIB (polled every ~50 ms);
#                upstr  absent from the upstream gobgpd's RIB (the BGP withdraw arrived);
#                fsrec  node 1's FLOWSPEC_WITHDRAW audit record.
#              For expire it also reports BLOCK_EXPIRED minus the signed end (tick lag).
#              Node 1 runs --flowspec-gobgp against a gobgpd pair in its own namespace, as
#              scripts/xdp-smoke.sh does; without gobgpd the FlowSpec columns are skipped.
#              Observations, not limits: a layer still blocking $UNBLOCK_WAIT s (20) after
#              the end is listed as a stuck round, and the run exits 1 if there is one.
#
# netem args are applied to every node's link, e.g. `delay 100ms 20ms loss 10%`.
set -euo pipefail

MODE=$1; BIN=$2; MON=$3; N=$4; shift 4
ARG=${1:-20}; [ $# -gt 0 ] && shift
case "$MODE" in propagation|partition|soak|recover|clock|observe|floors|reaction|unblock|relapse|bulkflush|restart) ;;
    *) echo "REFUSED unknown mesh mode"; exit 2 ;; esac
[[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 2 ] && [ "$N" -le 32 ] \
    || { echo "REFUSED mesh node count (2..32)"; exit 2; }
[ -x "$BIN" ] && [ -x "$MON" ] || { echo "REFUSED missing executable"; exit 2; }
# These names belong to one experiment at a time. Never remove another user's resources,
# even on refusal: cleanup is armed only AFTER the exclusive preflight succeeds.
exec 9>"${BENCH_LOCK:-/run/lock/sokol-mesh-bench.lock}"
flock -n 9 || { echo "REFUSED another mesh experiment holds the lock"; exit 2; }
for link in skbr0 skva-h skvl-h $(printf 'skv%s-h\n' $(seq 1 "$N")); do
    if ip link show "$link" >/dev/null 2>&1; then echo "REFUSED existing mesh interface $link"; exit 2; fi
done
namespaces=$(ip netns list) || { echo "REFUSED mesh namespace inventory unavailable"; exit 2; }
if grep -qE '^sk-(n[0-9]+|atk|leg)( |$)' <<<"$namespaces"; then
    echo "REFUSED existing mesh namespace"; exit 2
fi
BENCH_SEED=${BENCH_SEED:-1729}
[[ "$BENCH_SEED" =~ ^[0-9]{1,9}$ ]] || { echo "REFUSED invalid BENCH_SEED"; exit 2; }
RANDOM=$BENCH_SEED
[ "$MODE" = clock ] && TTL=${TTL:-60}
if [ "$MODE" = clock ]; then
    [ "$N" = 3 ] || { echo "clock mode runs on 3 nodes"; exit 2; }
    FAKETIME_LIB=$(ls /usr/lib/*/faketime/libfaketime.so.1 2>/dev/null | head -1)
    [ -n "$FAKETIME_LIB" ] || { echo "clock mode needs libfaketime (apt install faketime)"; exit 2; }
fi
[ "$MODE" = soak ] && TTL=${TTL:-300}   # blocks expire during the soak, so the table churns
NETEM="$*"
WORK="$(mktemp -d)"
BR=skbr0
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null || true; done
    remove_topology
    # Node logs outlive the run when there is somewhere to keep them: a node that died is only
    # explained by its own log (panic=abort writes nothing to the kernel log).
    if [ -n "${BENCH_OUT:-}" ]; then
        mkdir -p "$BENCH_OUT/logs"
        for d in "$WORK"/n*; do [ -f "$d/node.log" ] && cp "$d/node.log" "$BENCH_OUT/logs/$(basename "$d").log"; done
    fi
    rm -rf "$WORK"
}
remove_topology() {
    ip netns del sk-atk 2>/dev/null || true; ip netns del sk-leg 2>/dev/null || true
    ip link del skva-h 2>/dev/null || true; ip link del skvl-h 2>/dev/null || true
    for i in $(seq 1 "$N"); do
        ip link del "skv$i-h" 2>/dev/null || true
        ip netns del "sk-n$i" 2>/dev/null || true
    done
    ip link del "$BR" 2>/dev/null || true
}
trap cleanup EXIT
trap "exit 130" INT TERM   # a killed run still removes its namespaces and nodes

in_ns() { local i=$1; shift; ip netns exec "sk-n$i" "$@"; }
metric() { in_ns "$1" curl -s http://127.0.0.1:9470/metrics | awk -v m="$2" '$1 == m { print $2 }'; }
audit_ts() {
    # audit_ts <node> <record prefix> <ip>: timestamp_ms of the first matching record
    "$MON" --dump "$WORK/n$1/audit.log" 2>/dev/null | awk -F'\t' -v p="$2|IP:$3|" 'index($3, p) == 1 { print $2; exit }'
}

# Preflight established that these names are free; cleanup owns only this run's topology.
ip link add "$BR" type bridge
ip link set "$BR" up
for i in $(seq 1 "$N"); do
    ip netns add "sk-n$i"
    ip link add "skv$i-h" type veth peer name "skv$i"
    ip link set "skv$i-h" master "$BR" up
    ip link set "skv$i" netns "sk-n$i"
    in_ns "$i" ip addr add "10.240.0.$i/24" dev "skv$i"
    in_ns "$i" ip link set "skv$i" up
    in_ns "$i" ip link set lo up
    if [ -n "$NETEM" ]; then
        # shellcheck disable=SC2086
        in_ns "$i" tc qdisc add dev "skv$i" root netem $NETEM
    fi
    mkdir -p "$WORK/n$i"
    "$BIN" --key-file "$WORK/n$i/node.key" --print-public-key >"$WORK/n$i/pub"
done

node_args() {   # extra arguments for node i in some modes
    [ "$MODE" = observe ] && [ "$1" = 1 ] && echo "--enforce observe"
    case "$MODE" in unblock|relapse|bulkflush) true ;; *) false ;; esac && [ "$1" = 1 ] && [ -n "$FLOWSPEC" ] \
        && echo "--flowspec-gobgp $(command -v gobgp) --flowspec-gobgp-arg=-p --flowspec-gobgp-arg=50051"
    return 0
}
# unblock: node 1's gobgpd (AS 65001) peers with an "upstream" gobgpd (AS 65002), both on
# loopback in node 1's namespace, configured as in scripts/xdp-smoke.sh.
gobgp_config() {
    local as=$1 local_addr=$2 port=$3 peer_addr=$4 peer_port=$5 peer_as=$6 passive=${7:-false}
    printf '[global.config]\n  as = %s\n  router-id = "%s"\n  port = %s\n  local-address-list = ["%s"]\n' \
        "$as" "$local_addr" "$port" "$local_addr"
    printf '[[neighbors]]\n  [neighbors.config]\n    neighbor-address = "%s"\n    peer-as = %s\n' "$peer_addr" "$peer_as"
    printf '  [neighbors.transport.config]\n    local-address = "%s"\n    remote-port = %s\n    passive-mode = %s\n' \
        "$local_addr" "$peer_port" "$passive"
    printf '  [[neighbors.afi-safis]]\n    [neighbors.afi-safis.config]\n      afi-safi-name = "ipv4-flowspec"\n'
}
FLOWSPEC=""
if case "$MODE" in unblock|relapse|bulkflush) true ;; *) false ;; esac && command -v gobgpd >/dev/null; then
    gobgp_config 65001 127.0.0.1 1790 127.0.0.2 1791 65002 >"$WORK/gobgp-node.toml"
    gobgp_config 65002 127.0.0.2 1791 127.0.0.1 1790 65001 true >"$WORK/gobgp-upstream.toml"
    ip netns exec sk-n1 gobgpd -f "$WORK/gobgp-node.toml" --api-hosts 127.0.0.1:50051 >"$WORK/gobgpd-node.log" 2>&1 &
    GOBGPD_NODE=$!; PIDS+=($!)
    ip netns exec sk-n1 gobgpd -f "$WORK/gobgp-upstream.toml" --api-hosts 127.0.0.1:50052 >"$WORK/gobgpd-upstream.log" 2>&1 &
    PIDS+=($!)
    for _ in $(seq 1 40); do
        if in_ns 1 gobgp -p 50052 neighbor >/dev/null 2>&1 && in_ns 1 gobgp -p 50051 neighbor 2>/dev/null | grep -q Establ; then
            FLOWSPEC=1; break
        fi
        sleep 0.5
    done
    [ -n "$FLOWSPEC" ] || echo "# WARNING the gobgpd pair did not establish: FlowSpec layer not measured"
fi
start_node() {   # start_node <i> [last seed]: (re)starts node i with its key, state and audit log
    local i=$1 seeds=()
    for j in $(seq 1 "${2:-$N}"); do [ "$j" != "$i" ] && seeds+=(--seed-peer "10.240.0.$j:7946"); done
    # ip netns exec, not in_ns: a backgrounded function would be a subshell, and $! must be
    # the node itself (the soak reads its /proc entry and restarts it).
    local pre=()
    if [ "$MODE" = clock ]; then
        [ -f "$WORK/n$i/clock" ] || echo "+0" >"$WORK/n$i/clock"
        pre=(env "LD_PRELOAD=$FAKETIME_LIB" "FAKETIME_TIMESTAMP_FILE=$WORK/n$i/clock"
            FAKETIME_NO_CACHE=1 DONT_FAKE_MONOTONIC=1)
    fi
    ip netns exec "sk-n$i" "${pre[@]}" "$BIN" --interface "skv$i" --node-id "$i" --xdp-mode generic \
        --db-path "$WORK/n$i/audit.log" --key-file "$WORK/n$i/node.key" \
        --ipc-socket "$WORK/n$i/ipc.sock" --control-socket "$WORK/n$i/ctl.sock" \
        --p2p-bind "10.240.0.$i:7946" --peers-file "$WORK/n$i/peers.json" \
        --metrics-bind 127.0.0.1:9470 --block-ttl "${TTL:-3600}" "${seeds[@]}" $(node_args "$i") \
        >>"$WORK/n$i/node.log" 2>&1 </dev/null &
    NODE_PID[$i]=$!
    PIDS+=($!)
}
declare -A NODE_PID
declare -A LEG

for i in $(seq 1 "$N"); do
    {
        printf '['
        sep=""
        for j in $(seq 1 "$N"); do
            [ "$j" = "$i" ] && continue
            printf '%s{"node_id": %s, "public_key": "%s"}' "$sep" "$j" "$(cat "$WORK/n$j/pub")"
            sep=", "
        done
        printf ']'
    } >"$WORK/n$i/peers.json"
    [ "$MODE" = clock ] && [ "$i" = 3 ] && echo "+20" >"$WORK/n3/clock"   # S1
    start_node "$i" $((i - 1))
done

echo "# nodes=$N netem='${NETEM:-none}' host=$(uname -m) cpus=$(nproc) kernel=$(uname -r)"
deadline=$((SECONDS + 90))
until [ $SECONDS -ge $deadline ]; do
    ready=0
    for i in $(seq 1 "$N"); do
        [ "$(metric "$i" sokol_p2p_active_peers)" = "$((N - 1))" ] && ready=$((ready + 1))
    done
    [ "$ready" = "$N" ] && break
    sleep 0.5
done
echo "# full mesh after ${SECONDS}s: $ready/$N nodes see $((N - 1)) peers"
if [ "$ready" != "$N" ]; then
    # Under heavy loss the mesh may not be complete; measure delivery anyway and report it.
    echo "# WARNING mesh incomplete after 90 s; measuring with the connections that exist"
fi

block_on_node1() {
    printf 'DROP_IMMEDIATE:%s\n' "$1" | ip netns exec sk-n1 nc -U -q1 "$WORK/n1/ipc.sock"
}

stats() {
    sort -n | awk '{ v[NR] = $1 } END {
        if (NR == 0) { print "no samples"; exit }
        p95 = v[int((NR - 1) * 0.95) + 1]
        printf "n=%d min=%d median=%d p95=%d max=%d (ms)\n", NR, v[1], v[int((NR + 1) / 2)], p95, v[NR]
    }'
}

# unblock/relapse/bulkflush: an attacker namespace on the bridge; rounds add their own addresses.
attacker_ns() {
    ip netns add sk-atk
    ip link add skva-h type veth peer name skva
    ip link set skva-h master "$BR" up
    ip link set skva netns sk-atk
    ip netns exec sk-atk ip addr add 10.240.0.200/24 dev skva
    ip netns exec sk-atk ip link set skva up
}
now_ms() { date +%s%3N; }
send() {   # send <ipc|ctl> <line>: one line to node 1's socket, its first reply line printed
    in_ns 1 python3 - "$WORK/n1/$1.sock" "$2" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
ipc = sys.argv[1].endswith("/ipc.sock")   # the IPC socket answers only after ACK (F09)
s.sendall((b"ACK\n" if ipc else b"") + sys.argv[2].encode() + b"\n")
f = s.makefile()
if ipc:
    f.readline()
print(f.readline().strip())
PY
}
audit_after() {   # audit_after <node> <record prefix> <t_min>: first matching record at or after t_min
    "$MON" --dump "$WORK/n$1/audit.log" 2>/dev/null \
        | awk -F'\t' -v p="$2" -v t="$3" 'index($3, p) == 1 && $2 >= t { print $2; exit }'
}
rib_has() {   # rib_has <api port> <prefix>: 0 present, 1 absent, 2 unreadable (never absent)
    local rib
    rib=$(in_ns 1 gobgp -p "$1" global rib -a ipv4-flowspec 2>/dev/null) || return 2
    case "$rib" in *"source: $2]"*) return 0 ;; *) return 1 ;; esac
}
first_reply() { awk -F'[][]' -v a="$2" '/bytes from/ { t = int($2 * 1000); if (t >= a) { print t; exit } }' "$1"; }
last_reply() { awk -F'[][]' '/bytes from/ { t = int($2 * 1000) } END { if (t != "") print t }' "$1"; }

case "$MODE" in
propagation)
    ROUNDS=$ARG
    : >"$WORK/per_node"; : >"$WORK/last_node"; missing=0
    for r in $(seq 1 "$ROUNDS"); do
        ip="198.18.$((r / 250)).$((r % 250 + 1))"
        block_on_node1 "$ip"
        t0=""
        for _ in $(seq 1 100); do
            t0=$(audit_ts 1 DYNAMIC_BLOCK_V4 "$ip"); [ -n "$t0" ] && break; sleep 0.1
        done
        last=0
        for k in $(seq 2 "$N"); do
            tk=""
            for _ in $(seq 1 300); do
                tk=$(audit_ts "$k" MESH_BLOCK_V4 "$ip"); [ -n "$tk" ] && break; sleep 0.1
            done
            if [ -z "$tk" ] || [ -z "$t0" ]; then missing=$((missing + 1)); continue; fi
            d=$((tk - t0)); echo "$d" >>"$WORK/per_node"; [ "$d" -gt "$last" ] && last=$d
        done
        echo "$last" >>"$WORK/last_node"
    done
    echo "per node (issue on node 1 -> recorded on node k): $(stats <"$WORK/per_node")"
    echo "until the last node has it:                       $(stats <"$WORK/last_node")"
    echo "missing deliveries: $missing of $((ROUNDS * (N - 1)))"
    ;;
partition)
    DOWN=$ARG
    ip="198.19.0.1"
    ip link set "skv$N-h" down
    t_cut=$(date +%s%3N)
    sleep 1
    block_on_node1 "$ip"
    sleep "$DOWN"
    ip link set "skv$N-h" up
    t_up=$(date +%s%3N)
    echo "# node $N cut for ${DOWN}s; block issued 1 s into the partition"
    got=""
    for _ in $(seq 1 600); do
        got=$(audit_ts "$N" MESH_BLOCK_V4 "$ip"); [ -n "$got" ] && break; sleep 0.1
    done
    if [ -n "$got" ]; then
        echo "node $N learned the block $((got - t_up)) ms after the link came back"
    else
        echo "node $N did NOT learn the block within 60 s after the link came back"
    fi
    for _ in $(seq 1 60); do
        [ "$(metric "$N" sokol_p2p_active_peers)" = "$((N - 1))" ] && break
        sleep 0.5
    done
    echo "node $N sees $(metric "$N" sokol_p2p_active_peers)/$((N - 1)) peers $(( $(date +%s%3N) - t_up )) ms after the link came back"
    if [ -n "${VERBOSE:-}" ]; then
        echo "node $N log (P2P):"; grep -E "P2P|Mesh" "$WORK/n$N/node.log" | tail -25 | sed 's/^/    /'
    fi
    ;;
soak)
    MINUTES=$ARG
    OUT=${BENCH_OUT:-$WORK}; mkdir -p "$OUT"
    CSV="$OUT/soak.csv"
    TRACE="$OUT/events.csv"
    echo "t_s,node,event_id" >"$TRACE"
    echo "t_s,node,rss_kb,fds,audit_bytes,state_bytes,blocks_active,blocks_pending,tick_max_s,peers" >"$CSV"
    sample() {
        local t=$1
        for i in $(seq 1 "$N"); do
            local pid=${NODE_PID[$i]} rss fds audit state status
            # A node that exited stays a zombie until waited for, so check the state, not kill -0.
            if [ -z "$pid" ] || [ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" = Z ] || [ ! -e "/proc/$pid" ]; then
                if [ -n "$pid" ]; then
                    status=0; wait "$pid" 2>/dev/null || status=$?
                    echo "# t=$t s: FAIL node $i exited on its own (status $status)"
                    DIED+=("$i@$t:$status"); NODE_PID[$i]=""
                fi
                continue
            fi
            rss=$(awk '/VmRSS/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
            fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l || echo 0)
            audit=$(du -cb "$WORK/n$i"/audit.log* 2>/dev/null | tail -1 | cut -f1)
            state=$(stat -c %s "$WORK/n$i/audit.log.blocks.json" 2>/dev/null || echo 0)
            echo "$t,$i,${rss:-0},$fds,${audit:-0},$state,$(metric "$i" 'sokol_blocks_active{family="ipv4"}'),$(metric "$i" sokol_blocks_pending),$(metric "$i" sokol_tick_seconds_max),$(metric "$i" sokol_p2p_active_peers)" >>"$CSV"
        done
    }
    start=$SECONDS; end=$((start + MINUTES * 60))
    next_sample=$start; RESTART_EVERY=${RESTART_EVERY:-600}; CUT_EVERY=${CUT_EVERY:-900}
    next_restart=$((start + RESTART_EVERY)); next_cut=$((start + CUT_EVERY))
    k=0; restarts=0; cuts=0; cutters=(); DIED=()
    echo "# soak ${MINUTES} min, TTL ${TTL:-3600} s, seed $BENCH_SEED (OS scheduling remains uncontrolled)"
    while [ $SECONDS -lt $end ]; do
        for _ in 1 2 3 4 5; do
            i=$((RANDOM % N + 1))
            # One signal in ten repeats the previous event id (a resend): the node must dedup it.
            [ $((RANDOM % 10)) = 0 ] || k=$((k + 1))
            printf '%s,%s,%s\n' "$((SECONDS - start))" "$i" "$k" >>"$TRACE"
            printf 'SIGNAL#soak-%s:soak|100.%s.%s.%s|-|soak\n' "$k" $((64 + k / 65536 % 8)) $((k / 256 % 256)) $((k % 256)) \
                | in_ns "$i" nc -U -q0 "$WORK/n$i/ipc.sock" >/dev/null 2>&1 || true
        done
        if [ $SECONDS -ge $next_restart ]; then
            i=$((RANDOM % N + 1))
            # A node that died stays down: restarting it would hide the failure.
            if [ -z "${NODE_PID[$i]}" ]; then next_restart=$((next_restart + RESTART_EVERY)); continue; fi
            kill -INT "${NODE_PID[$i]}" 2>/dev/null || true
            wait "${NODE_PID[$i]}" 2>/dev/null || true; start_node "$i"
            echo "# t=$((SECONDS - start)) s: node $i restarted"
            restarts=$((restarts + 1)); next_restart=$((next_restart + RESTART_EVERY))
        fi
        if [ $SECONDS -ge $next_cut ]; then
            i=$((RANDOM % N + 1)); ( ip link set "skv$i-h" down; sleep 30; ip link set "skv$i-h" up ) &
            cutters+=($!); echo "# t=$((SECONDS - start)) s: node $i cut off for 30 s"
            cuts=$((cuts + 1)); next_cut=$((next_cut + CUT_EVERY))
        fi
        if [ $SECONDS -ge $next_sample ]; then sample $((SECONDS - start)); next_sample=$((next_sample + 60)); fi
        sleep 1
    done
    [ ${#cutters[@]} = 0 ] || wait "${cutters[@]}"   # not a bare wait: the nodes run in the background
    echo "# load done: $k events, $restarts restarts, $cuts cuts; settling 90 s"
    sleep 90
    sample $((SECONDS - start))
    fail=0
    if [ ${#DIED[@]} -gt 0 ]; then echo "FAIL nodes exited on their own (node@t:status): ${DIED[*]}"; fail=1; fi
    # Blocks keep expiring (TTL), and a sweep of N nodes takes a while, so one sweep can straddle
    # an expiry. Agreement is a sweep in which every node reports the same count, within 30 s.
    agreed=""
    for _ in $(seq 1 30); do
        # Every node must answer: a node that is down has no value, and must not drop out of the vote.
        actives=$(for i in $(seq 1 "$N"); do v=$(metric "$i" 'sokol_blocks_active{family="ipv4"}'); echo "${v:-down}"; done | sort -u | tr '\n' ' ')
        read -ra distinct <<<"$actives"
        [ ${#distinct[@]} = 1 ] && [ "${distinct[0]}" != down ] && { agreed=1; break; }
        sleep 1
    done
    if [ -n "$agreed" ]; then echo "PASS all $N nodes agree on the active blocks ($actives)"; else echo "FAIL active blocks still differ between nodes after 30 s: $actives"; fail=1; fi
    for i in $(seq 1 "$N"); do
        "$MON" --verify "$WORK/n$i/audit.log" >/dev/null 2>&1 || { echo "FAIL node $i audit chain does not verify"; fail=1; }
        grep -q "panicked" "$WORK/n$i/node.log" && { echo "FAIL node $i panicked"; fail=1; }
    done
    [ $fail = 0 ] && echo "PASS every audit chain verifies; no node panicked"
    awk -F, 'NR > 1 && $1 >= 300 { if (!($2 in first)) first[$2] = $3; last[$2] = $3; seen[$2]++; rows++ }
        END { if (!rows) { print "RSS growth: no samples after the first 5 min"; exit }
              for (n in seen) if (seen[n] < 2) { print "RSS growth: under two samples after the first 5 min"; exit }
              for (n in first) { g = (last[n] - first[n]) * 100 / first[n]; if (g > max) max = g; if (min == "" || g < min) min = g }
              printf "RSS growth after the first 5 min: min %.1f%%, max %.1f%% (per node)\n", min, max }' "$CSV"
    echo "samples: $CSV"
    exit $fail
    ;;
recover)
    SIGNALS=$ARG; [ "$SIGNALS" = 20 ] && SIGNALS=30000   # ARG defaults to 20 for the other modes
    RATE=${RECOVER_RATE:-8mbit}
    in_ns 1 tc qdisc replace dev skv1 root tbf rate "$RATE" burst 32kbit latency 400ms
    ctl_ms() {   # ctl_ms <node> <command>: answer time of the control socket in ms, 99999 if none
        # Timed inside one process from connect to the first reply line: nc -q1 would add its
        # own second after end of input.
        in_ns "$1" python3 - "$WORK/n$1/ctl.sock" "$2" <<'PY'
import socket, sys, time
t0 = time.monotonic()
try:
    s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
    s.sendall(sys.argv[2].encode() + b"\n")
    reply = s.makefile().readline()
    print(int((time.monotonic() - t0) * 1000) if reply.startswith("OK") else 99999)
except OSError:
    print(99999)
PY
    }
    echo "# recover: $SIGNALS signals at node 1, its link held to $RATE"
    t0=$SECONDS
    senders=()
    for half in 0 1; do
        awk -v n="$SIGNALS" -v h="$half" 'BEGIN { for (i = h; i < n; i += 2)
            printf "SIGNAL#rec-%d:recover|100.%d.%d.%d|-|recovery flood\n", i, 64 + int(i / 65536) % 64, int(i / 256) % 256, i % 256 }' \
            | in_ns 1 nc -U -q1 "$WORK/n1/ipc.sock" >/dev/null &
        senders+=($!)
    done
    ctl_max=0; ctl_n=0
    # Probe until node 1 has taken every signal (the senders finish long before: the socket
    # buffers what the node's IPC pacing has not read yet), at most 5 minutes.
    while [ "$(metric 1 'sokol_blocks_active{family="ipv4"}')" != "$SIGNALS" ] && [ $((SECONDS - t0)) -lt 300 ]; do
        ms=$(ctl_ms 1 LIST_BANS); ctl_n=$((ctl_n + 1)); [ "$ms" -gt "$ctl_max" ] && ctl_max=$ms
        sleep 0.5
    done
    flood_s=$((SECONDS - t0))
    wait "${senders[@]}"
    dropped=$(metric 1 'sokol_mesh_broadcasts_dropped_total{class="urgent"}')
    echo "# flood done in ${flood_s} s; node 1 dropped ${dropped:-0} urgent broadcasts; control answered $ctl_n times, max ${ctl_max} ms"
    fail=0
    [ "${dropped:-0}" -gt 0 ] || { echo "NOT EXERCISED no broadcast was dropped: raise the signals or lower RECOVER_RATE"; fail=1; }
    if [ "$ctl_n" -gt 0 ] && [ "$ctl_max" -le 1000 ]; then echo "PASS L1 control socket answered within 1000 ms during the flood (max $ctl_max ms)"; else echo "FAIL L1 control socket: max $ctl_max ms over $ctl_n probes"; fail=1; fi
    # L3: every node reaches node 1's count; polled once a second.
    t_end=$SECONDS; converged=""
    while [ $((SECONDS - t_end)) -le 120 ]; do
        want=$(metric 1 'sokol_blocks_active{family="ipv4"}'); behind=0
        [ -n "$want" ] && [ "$want" -gt 16384 ] && want=16384   # ADR-0007 envelope, default
        for i in $(seq 2 "$N"); do [ "$(metric "$i" 'sokol_blocks_active{family="ipv4"}')" = "$want" ] || behind=$((behind + 1)); done
        [ "$behind" = 0 ] && [ -n "$want" ] && { converged=$((SECONDS - t_end)); break; }
        sleep 1
    done
    if [ -n "$converged" ]; then echo "PASS L3 all $N nodes hold node 1's blocks (${want}, envelope 16384) ${converged} s after the flood"; else echo "FAIL L3 after 120 s $behind node(s) still differ from node 1 ($want blocks): $(for i in $(seq 2 "$N"); do printf '%s ' "$(metric "$i" 'sokol_blocks_active{family="ipv4"}')"; done)"; fail=1; fi
    tick=0; pending=0
    for i in $(seq 1 "$N"); do
        t=$(metric "$i" sokol_tick_seconds_max); awk -v t="${t:-9}" 'BEGIN { exit !(t > 0.5) }' && { echo "     node $i tick max ${t}s"; tick=1; }
        [ "$(metric "$i" sokol_blocks_pending)" = 0 ] || pending=$((pending + 1))
    done
    if [ $tick = 0 ]; then echo "PASS L2 no maintenance tick over 500 ms"; else echo "FAIL L2 maintenance tick over 500 ms"; fail=1; fi
    if [ $pending = 0 ]; then echo "PASS L4 no node has blocks waiting for the kernel map"; else echo "FAIL L4 $pending node(s) have pending blocks"; fail=1; fi
    dead=0
    for i in $(seq 1 "$N"); do
        pid=${NODE_PID[$i]}
        { [ -e "/proc/$pid" ] && [ "$(awk '{print $3}' "/proc/$pid/stat")" != Z ]; } || { echo "     node $i exited"; dead=1; }
    done
    if [ $dead = 0 ]; then echo "PASS L5 no node exited"; else echo "FAIL L5 a node exited"; fail=1; fi
    exit $fail
    ;;
clock)
    fail=0
    pass() { echo "PASS $*"; }
    flunk() { echo "FAIL $*"; fail=1; }
    active() { local v; v=$(metric "$1" 'sokol_blocks_active{family="ipv4"}'); echo "${v:-down}"; }
    signal_at() { printf 'SIGNAL:clock|%s|-|clock test\n' "$2" | in_ns "$1" nc -U -q1 "$WORK/n$1/ipc.sock" >/dev/null; }
    wait_for() {   # wait_for <seconds> '<condition>': seconds taken, or failure on timeout
        # The condition is a string evaluated on every try: passed as words, a $(metric ...)
        # in it would be expanded once, at the call.
        local t0=$SECONDS
        until eval "$2"; do [ $((SECONDS - t0)) -ge "$1" ] && return 1; sleep 0.5; done
        echo $((SECONDS - t0))
    }
    # S1 (node 3 was started at +20 s: see below)
    [ "$(metric 1 sokol_p2p_active_peers)" = 2 ] && [ "$(metric 3 sokol_p2p_active_peers)" = 2 ] \
        && pass "C1 node 3 at +20 s is in the full mesh" || flunk "C1 mesh with node 3 at +20 s: node 1 sees $(metric 1 sokol_p2p_active_peers), node 3 sees $(metric 3 sokol_p2p_active_peers)"
    signal_at 1 198.18.7.1
    if t=$(wait_for 10 'test "$(active 3)" = 1'); then pass "C2 node 1's block reached node 3 in ${t} s"; else flunk "C2 node 3 never got node 1's block"; fi
    t_3=""; t_1=""; t0=$SECONDS
    while [ $((SECONDS - t0)) -lt 120 ] && [ -z "$t_1" ]; do
        [ -z "$t_3" ] && [ "$(active 3)" = 0 ] && t_3=$SECONDS
        [ "$(active 1)" = 0 ] && t_1=$SECONDS
        sleep 0.5
    done
    if [ -n "$t_1" ] && [ -n "$t_3" ] && [ $((t_1 - t_3)) -ge 17 ] && [ $((t_1 - t_3)) -le 23 ]; then
        pass "C3 node 3 (+20 s) let the block expire $((t_1 - t_3)) s before node 1"
    else flunk "C3 expiry: node 3 at ${t_3:-never}, node 1 at ${t_1:-never} (script seconds)"; fi
    # S2
    echo "+60" >"$WORK/n3/clock"
    if t=$(wait_for 45 'test "$(metric 1 sokol_p2p_active_peers)" = 1'); then pass "C4 node 3 at +60 s left node 1's mesh after ${t} s"
    else flunk "C4 node 1 still sees $(metric 1 sokol_p2p_active_peers) peers 45 s after node 3 stepped to +60 s"; fi
    signal_at 3 198.18.7.3
    sleep 3
    if [ "$(active 3)" = 1 ] && [ "$(active 1)" = 0 ]; then pass "C5 node 3 still blocks its own detector's target; node 1 did not get it"
    else flunk "C5 node 3 holds $(active 3), node 1 holds $(active 1)"; fi
    # S3
    echo "+0" >"$WORK/n3/clock"
    if t=$(wait_for 60 'test "$(metric 1 sokol_p2p_active_peers)" = 2'); then pass "C6 node 3 back at +0 rejoined node 1 after ${t} s"
        if t=$(wait_for 60 'test "$(active 1)" = 1'); then pass "C7 node 1 got node 3's block ${t} s after the rejoin"
        else flunk "C7 node 1 never got node 3's block"; fi
    else flunk "C6 node 1 sees $(metric 1 sokol_p2p_active_peers) peers 60 s after node 3 came back"; flunk "C7 not reached"; fi
    # S4 (exploratory). The block count is per node, so first let node 2's earlier blocks end
    # (node 3's block from S2 was issued at +60 s and ends later here): then it counts S4's only.
    wait_for 240 'test "$(active 2)" = 0' >/dev/null || echo "OBS  S4 node 2 still holds $(active 2) earlier blocks"
    signal_at 2 198.18.7.21; sleep 2
    echo "+3600" >"$WORK/n2/clock"; t0=$SECONDS
    t=$(wait_for 90 'test "$(active 2)" = 0' || true)
    echo "OBS  S4 node 2 stepped +3600 s holding a fresh 60 s block: it lasted ${t:-over 90} s more (real)"
    echo "+0" >"$WORK/n2/clock"; sleep 3
    signal_at 2 198.18.7.22; sleep 2
    echo "-3600" >"$WORK/n2/clock"
    t=$(wait_for 150 'test "$(active 2)" = 0' || true)
    echo "OBS  S4 node 2 stepped -3600 s holding a fresh 60 s block: it lasted ${t:-over 150} s more (real)"
    echo "+0" >"$WORK/n2/clock"
    for i in $(seq 1 "$N"); do grep -h 'Rejected envelope\|StaleTimestamp' "$WORK/n$i/node.log" | head -1 | sed "s/^/OBS  node $i log: /" | cut -c1-200; done
    dead=0
    for i in $(seq 1 "$N"); do pid=${NODE_PID[$i]}; { [ -e "/proc/$pid" ] && [ "$(awk '{print $3}' "/proc/$pid/stat")" != Z ]; } || dead=1; done
    [ $dead = 0 ] && pass "C8 no node exited" || flunk "C8 a node exited"
    tick=0; for i in $(seq 1 "$N"); do awk -v t="$(metric "$i" sokol_tick_seconds_max)" 'BEGIN { exit !(t == "" || t > 0.5) }' && tick=1; done
    [ $tick = 0 ] && pass "C9 no tick over 500 ms" || flunk "C9 a tick over 500 ms"
    exit $fail
    ;;
observe)
    [ "$N" = 3 ] || { echo "observe mode runs on 3 nodes"; exit 2; }
    fail=0
    active() { local v; v=$(metric "$1" 'sokol_blocks_active{family="ipv4"}'); echo "${v:-down}"; }
    [ "$(metric 1 'sokol_enforce_mode{mode="observe"}')" = 1 ] || { echo "FAIL node 1 is not in observe mode"; exit 1; }
    printf 'SIGNAL:obs|198.18.9.1|-|observed only\n' | in_ns 1 nc -U -q1 "$WORK/n1/ipc.sock" >/dev/null
    sleep 2
    if [ "$(active 1)" = 1 ]; then echo "PASS O1 node 1 decided locally (1 block)"; else echo "FAIL O1 node 1 holds $(active 1)"; fail=1; fi
    sleep 40
    if [ "$(active 2)" = 0 ] && [ "$(active 3)" = 0 ]; then echo "PASS O2 after 40 s nodes 2 and 3 hold none of node 1's decisions"
    else echo "FAIL O2 nodes 2 and 3 hold $(active 2) and $(active 3) of the observing node's blocks"; fail=1; fi
    printf 'SIGNAL:obs|198.18.9.2|-|enforced\n' | in_ns 2 nc -U -q1 "$WORK/n2/ipc.sock" >/dev/null
    ok=""; for _ in $(seq 1 25); do [ "$(active 3)" = 1 ] && [ "$(active 1)" = 2 ] && { ok=1; break; }; sleep 0.2; done
    if [ -n "$ok" ]; then echo "PASS O3 node 2's decision reached nodes 1 and 3"; else echo "FAIL O3 node 1 holds $(active 1), node 3 holds $(active 3)"; fail=1; fi
    exit $fail
    ;;
floors)
    # MESH-N2 end to end: node 1 saves its peers' replay floors with its state, a SIGKILL and
    # restart carries them on, and its peers' later envelopes still pass.
    [ "$N" = 3 ] || { echo "floors mode runs on 3 nodes"; exit 2; }
    fail=0
    floors() { python3 -c 'import json,sys; print(" ".join(f"{a}:{b}" for a, b in json.load(open(sys.argv[1])).get("mesh_floors", [])))' "$WORK/n1/audit.log.blocks.json"; }
    active() { local v; v=$(metric 1 'sokol_blocks_active{family="ipv4"}'); echo "${v:-down}"; }
    for j in 2 3; do printf 'SIGNAL:fl|198.18.10.%s|-|floors\n' "$j" | in_ns "$j" nc -U -q1 "$WORK/n$j/ipc.sock" >/dev/null; done
    sleep 3
    before=$(floors); now=$(now_ms)
    echo "# node 1 saved floors (sender:ms): ${before:-none}; now $now"
    ok=1
    for j in 2 3; do
        f=$(tr ' ' '\n' <<<"$before" | sed -n "s/^$j://p")
        [ -n "$f" ] && [ $((f - now)) -le 30000 ] && [ $((now - f)) -le 60000 ] || ok=""
    done
    if [ -n "$ok" ]; then echo "PASS F1 node 1's state file holds a current floor for nodes 2 and 3"
    else echo "FAIL F1 floors in node 1's state: ${before:-none}"; fail=1; fi
    kill -KILL "${NODE_PID[1]}" 2>/dev/null || true
    wait "${NODE_PID[1]}" 2>/dev/null || true
    start_node 1
    for _ in $(seq 1 100); do send ctl LIST_BANS >/dev/null 2>&1 && break; sleep 0.1; done
    sleep 5   # the peers reconnect
    printf 'SIGNAL:fl|198.18.10.9|-|after the restart\n' | in_ns 2 nc -U -q1 "$WORK/n2/ipc.sock" >/dev/null
    ok=""; for _ in $(seq 1 50); do [ "$(active)" = 3 ] && { ok=1; break; }; sleep 0.2; done
    if [ -n "$ok" ]; then echo "PASS F2 after the restart node 2's new decision reaches node 1 (3 blocks)"
    else echo "FAIL F2 node 1 holds $(active) blocks after the restart"; fail=1; fi
    sleep 2
    after=$(floors)
    echo "# node 1 floors after the restart: ${after:-none}"
    ok=1
    for j in 2 3; do
        b=$(tr ' ' '\n' <<<"$before" | sed -n "s/^$j://p"); a=$(tr ' ' '\n' <<<"$after" | sed -n "s/^$j://p")
        [ -n "$a" ] && [ -n "$b" ] && [ "$a" -ge "$b" ] || ok=""
    done
    if [ -n "$ok" ]; then echo "PASS F3 every floor is carried on, none lowered"
    else echo "FAIL F3 floors went from '${before:-none}' to '${after:-none}'"; fail=1; fi
    exit $fail
    ;;
reaction)
    ROUNDS=$ARG; HOLD=${REACT_HOLD:-10}; fail=0
    for side in atk:skva:200 leg:skvl:201; do
        IFS=: read -r name dev addr <<<"$side"
        ip netns add "sk-$name"
        ip link add "$dev-h" type veth peer name "$dev"
        ip link set "$dev-h" master "$BR" up
        ip link set "$dev" netns "sk-$name"
        ip netns exec "sk-$name" ip addr add "10.240.0.$addr/24" dev "$dev"
        ip netns exec "sk-$name" ip link set "$dev" up
    done
    for k in $(seq 1 "$N"); do
        ip netns exec sk-atk ping -D -n -i 0.01 "10.240.0.$k" >"$WORK/atk$k" 2>&1 &
        PIDS+=($!)
        ip netns exec sk-leg ping -D -n -i 0.01 "10.240.0.$k" >"$WORK/leg$k" 2>&1 &
        LEG[$k]=$!; PIDS+=($!)
    done
    sleep 2
    now_ms() { date +%s%3N; }
    # The first or last reply time (ms) in ping output $2 within [$3, $4). One awk, no
    # `| head`: an early close would be SIGPIPE, which pipefail turns into an exit.
    reply() { awk -v w="$1" -v a="$3" -v b="$4" -F'[][]' '/bytes from/ { t = int($2 * 1000)
        if (t >= a && t < b) { if (w == "first") { print t; exit } last = t } }
        END { if (w == "last" && last != "") print last }' "$2"; }
    : >"$WORK/stop1"; : >"$WORK/stop"; : >"$WORK/restore"; missing=0
    for r in $(seq 1 "$ROUNDS"); do
        t0=$(now_ms)
        printf 'SIGNAL#react%s:bench|10.240.0.200|-|reaction round %s\n' "$r" "$r" \
            | in_ns 1 nc -U -q1 "$WORK/n1/ipc.sock" >/dev/null
        sleep "$HOLD"
        t1=$(now_ms)
        printf 'UNBAN_IP:10.240.0.200\n' | in_ns 1 nc -U -q1 "$WORK/n1/ctl.sock" >/dev/null
        sleep "$HOLD"
        t2=$(now_ms)
        for k in $(seq 1 "$N"); do
            # In force if the node went quiet for the attacker at least 1 s before the unban.
            last=$(reply last "$WORK/atk$k" "$t0" "$t1")
            quiet_from=${last:-$t0}
            if [ $((t1 - quiet_from)) -lt 1000 ]; then
                echo "round $r node $k: still answering the attacker at the unban"
                missing=$((missing + 1)); stop=999999
            else
                stop=$((quiet_from + 10 - t0))
            fi
            echo "$stop" >>"$WORK/stop"; [ "$k" = 1 ] && echo "$stop" >>"$WORK/stop1"
            first=$(reply first "$WORK/atk$k" "$t1" "$t2")
            if [ -z "$first" ]; then
                echo "round $r node $k: no attacker reply within $HOLD s of the unban"
                missing=$((missing + 1)); echo 999999 >>"$WORK/restore"
            else
                echo $((first - t1)) >>"$WORK/restore"
            fi
        done
    done
    for k in $(seq 1 "$N"); do kill -INT "${LEG[$k]}" 2>/dev/null || true; done
    sleep 0.5
    sent=0; got=0
    for k in $(seq 1 "$N"); do
        read -r s g < <(awk '/packets transmitted/ { print $1, $4 }' "$WORK/leg$k")
        sent=$((sent + ${s:-0})); got=$((got + ${g:-0}))
    done
    echo "signal -> node 1 stops the attacker: $(stats <"$WORK/stop1")"
    echo "signal -> a node stops the attacker: $(stats <"$WORK/stop")"
    echo "unban  -> a node answers it again:   $(stats <"$WORK/restore")"
    echo "legitimate pings: $got of $sent answered; round x node without a clean stop or restore: $missing"
    worst() { sort -n | tail -1; }
    if [ "$(worst <"$WORK/stop1")" -le 500 ]; then echo "PASS R1 node 1 stops within 500 ms"; else echo "FAIL R1 node 1 over 500 ms"; fail=1; fi
    if [ "$(worst <"$WORK/stop")" -le 3000 ]; then echo "PASS R2 every node stops within 3000 ms"; else echo "FAIL R2 a node over 3000 ms"; fail=1; fi
    if [ "$(worst <"$WORK/restore")" -le 3000 ]; then echo "PASS R3 every node restored within 3000 ms"; else echo "FAIL R3 a node not restored within 3000 ms"; fail=1; fi
    if [ "$sent" -gt 0 ] && [ $(( (sent - got) * 1000 )) -le $(( sent * 5 )) ]; then echo "PASS R4 legitimate loss <= 0.5 %"
    else echo "FAIL R4 legitimate loss $((sent - got)) of $sent"; fail=1; fi
    exit $fail
    ;;
unblock)
    ROUNDS=$ARG; WAYS=${UNBLOCK_WAYS:-retract unban flush expire}; ETTL=${UNBLOCK_TTL:-6}
    WAIT=${UNBLOCK_WAIT:-20}
    read -ra ways <<<"$WAYS"
    [ $((ROUNDS * ${#ways[@]})) -le 99 ] || { echo "unblock: rounds x ways must be at most 99 (one address each)"; exit 2; }
    attacker_ns
    stuck=(); k=0
    echo "# unblock: ways '$WAYS', $ROUNDS rounds each, expire ttl ${ETTL}s, FlowSpec ${FLOWSPEC:+on}"
    for way in "${ways[@]}"; do
        for col in xdp1 peer rib upstr fsrec lag; do : >"$WORK/u-$way-$col"; done
        for r in $(seq 1 "$ROUNDS"); do
            k=$((k + 1)); a="10.240.0.$((100 + k))"
            ip netns exec sk-atk ip addr add "$a/24" dev skva
            pings=()
            for n in $(seq 1 "$N"); do
                ip netns exec sk-atk ping -D -n -i 0.01 -I "$a" "10.240.0.$n" >"$WORK/p$k.$n" 2>&1 &
                pings+=($!)
            done
            sleep 0.5
            t_sig=$(now_ms)
            ttl=""; [ "$way" = expire ] && ttl=";ttl=$ETTL"
            send ipc "SIGNAL#ub$k$ttl:bench|$a|-|unblock $way round $r" >/dev/null
            # In force: every node silent to the attacker for 300 ms, node 1's rule in both RIBs.
            ok=""
            for _ in $(seq 1 150); do
                sleep 0.1
                quiet=1; t=$(now_ms)
                for n in $(seq 1 "$N"); do
                    l=$(last_reply "$WORK/p$k.$n"); [ -n "$l" ] && [ $((t - l)) -lt 300 ] && quiet=""
                done
                [ -n "$quiet" ] || continue
                if [ -n "$FLOWSPEC" ]; then
                    rib_has 50051 "$a/32" && rib_has 50052 "$a/32" || continue
                fi
                ok=1; break
            done
            if [ -z "$ok" ]; then
                echo "round $way/$r ($a): block not in force on every layer within 15 s; skipped"
                for p in "${pings[@]}"; do kill "$p" 2>/dev/null || true; done
                continue
            fi
            case "$way" in
            retract) send ipc "RETRACT#ub$k:bench|$a" >/dev/null; prefix="DETECTOR_RETRACT|IP:$a|" ;;
            unban) send ctl "UNBAN_IP:$a" >/dev/null; prefix="OPERATOR_UNBAN_V4|IP:$a|" ;;
            stall)
                # Node 1's gobgpd stops answering for $UNBLOCK_STALL s (7) right after the unban;
                # the FlowSpec columns are then counted from when it answers again.
                [ -n "$FLOWSPEC" ] || { echo "stall needs gobgpd"; exit 2; }
                kill -STOP "$GOBGPD_NODE"; send ctl "UNBAN_IP:$a" >/dev/null
                sleep "${UNBLOCK_STALL:-7}"; kill -CONT "$GOBGPD_NODE"; t_cont=$(now_ms)
                prefix="OPERATOR_UNBAN_V4|IP:$a|" ;;
            flush) send ctl "FLUSH_BANS" >/dev/null; prefix="OPERATOR_FLUSH|" ;;
            expire) prefix="BLOCK_EXPIRED_V4|IP:$a" ;;
            *) echo "unknown way $way"; exit 2 ;;
            esac
            t_end=""
            for _ in $(seq 1 $((WAIT * 10 + ETTL * 10))); do
                t_end=$(audit_after 1 "$prefix" "$t_sig"); [ -n "$t_end" ] && break; sleep 0.1
            done
            if [ -z "$t_end" ]; then
                echo "round $way/$r ($a): no end record on node 1"; stuck+=("$way/$r:no-end-record")
                for p in "${pings[@]}"; do kill "$p" 2>/dev/null || true; done
                continue
            fi
            t_rib=""; t_up=""
            if [ -n "$FLOWSPEC" ]; then
                while [ $(($(now_ms) - t_end)) -lt $((WAIT * 1000)) ]; do
                    if [ -z "$t_rib" ]; then s=0; rib_has 50051 "$a/32" || s=$?; [ "$s" = 1 ] && t_rib=$(now_ms); fi
                    if [ -z "$t_up" ]; then s=0; rib_has 50052 "$a/32" || s=$?; [ "$s" = 1 ] && t_up=$(now_ms); fi
                    [ -n "$t_rib" ] && [ -n "$t_up" ] && break
                    sleep 0.05
                done
                t_from=$t_end; [ "$way" = stall ] && t_from=$t_cont
                if [ -n "$t_rib" ]; then echo $((t_rib - t_from)) >>"$WORK/u-$way-rib"; else stuck+=("$way/$r:rib"); fi
                if [ -n "$t_up" ]; then echo $((t_up - t_from)) >>"$WORK/u-$way-upstr"; else stuck+=("$way/$r:upstream"); fi
                f=$(audit_after 1 "FLOWSPEC_WITHDRAW|IP:$a" "$t_end"); [ -n "$f" ] && echo $((f - t_from)) >>"$WORK/u-$way-fsrec"
            fi
            # Every node answers again, or WAIT runs out.
            while [ $(($(now_ms) - t_end)) -lt $((WAIT * 1000)) ]; do
                all=1
                for n in $(seq 1 "$N"); do [ -n "$(first_reply "$WORK/p$k.$n" "$t_end")" ] || all=""; done
                [ -n "$all" ] && break
                sleep 0.1
            done
            sleep 0.2
            for p in "${pings[@]}"; do kill "$p" 2>/dev/null || true; done
            for n in $(seq 1 "$N"); do
                f=$(first_reply "$WORK/p$k.$n" "$t_end")
                if [ -z "$f" ]; then stuck+=("$way/$r:node$n"); continue; fi
                if [ "$n" = 1 ]; then echo $((f - t_end)) >>"$WORK/u-$way-xdp1"; else echo $((f - t_end)) >>"$WORK/u-$way-peer"; fi
            done
            if [ "$way" = expire ]; then
                b=$(audit_after 1 "DYNAMIC_BLOCK_V4|IP:$a|" "$t_sig")
                [ -n "$b" ] && echo $((t_end - b - ETTL * 1000)) >>"$WORK/u-$way-lag"
            fi
            ip netns exec sk-atk ip addr del "$a/24" dev skva
        done
        echo "== $way"
        echo "   xdp1  node 1 answers again:        $(stats <"$WORK/u-$way-xdp1")"
        echo "   peer  another node answers again:  $(stats <"$WORK/u-$way-peer")"
        if [ -n "$FLOWSPEC" ]; then
            echo "   rib   rule gone from node gobgpd:  $(stats <"$WORK/u-$way-rib")"
            echo "   upstr rule gone upstream:          $(stats <"$WORK/u-$way-upstr")"
            echo "   fsrec FLOWSPEC_WITHDRAW record:    $(stats <"$WORK/u-$way-fsrec")"
        fi
        [ "$way" = expire ] && echo "   lag   BLOCK_EXPIRED - signed end:  $(stats <"$WORK/u-$way-lag")"
    done
    if [ ${#stuck[@]} -gt 0 ]; then echo "STUCK (still blocking ${WAIT} s after the end): ${stuck[*]}"; exit 1; fi
    echo "no layer kept blocking ${WAIT} s after an end"
    ;;
restart)
    ROUNDS=$ARG; fail=0
    [ "$ROUNDS" -le 40 ] || { echo "restart: at most 40 rounds (one address each)"; exit 2; }
    attacker_ns
    echo "# restart: $ROUNDS rounds, node 1 SIGKILLed with a detector block on disk; X1<=10000 X2<=10000 X3<=30000 ms"
    for r in $(seq 1 "$ROUNDS"); do
        a="10.240.0.$((150 + r))"
        ip netns exec sk-atk ip addr add "$a/24" dev skva
        send ipc "SIGNAL#rs$r:bench|$a|-|restart round $r" >/dev/null
        sleep 3   # over one tick: the block is on disk
        [ -n "${RESTART_CONTROL:-}" ] && { send ctl "UNBAN_IP:$a" >/dev/null; sleep 1.5; }
        ip netns exec sk-atk ping -D -n -i 0.01 -I "$a" 10.240.0.1 >"$WORK/rs$r" 2>&1 &
        pinger=$!
        sleep 0.5
        t0=$(now_ms)
        kill -KILL "${NODE_PID[1]}" 2>/dev/null || true
        wait "${NODE_PID[1]}" 2>/dev/null || true
        start_node 1
        ctl=""; peers=""
        while [ $(($(now_ms) - t0)) -lt 30000 ]; do
            [ -z "$ctl" ] && send ctl LIST_BANS >/dev/null 2>&1 && ctl=$(($(now_ms) - t0))
            if [ -n "$ctl" ] && [ "$(metric 1 sokol_p2p_active_peers || true)" = $((N - 1)) ]; then
                peers=$(($(now_ms) - t0)); break
            fi
            sleep 0.05
        done
        sleep 2
        t_stop=$(now_ms)
        kill "$pinger" 2>/dev/null || true; wait "$pinger" 2>/dev/null || true
        # The last reply after the kill (ping -D prints [epoch.micro]); none = the block never lapsed.
        last=$(awk -v t0="$t0" '/bytes from/ { gsub(/[\[\]]/, "", $1); ms = int($1 * 1000); if (ms >= t0) l = ms - t0 } END { print l + 0 }' "$WORK/rs$r")
        echo "round $r: control ${ctl:-none} ms, attacker last reply ${last} ms, peers ${peers:-none} ms"
        { [ -n "$ctl" ] && [ "$ctl" -le 10000 ]; } || { echo "FAIL X1 round $r"; fail=1; }
        { [ "$last" -le 10000 ] && [ "$last" -lt $((t_stop - t0 - 1000)) ]; } || { echo "FAIL X2 round $r (the attacker still got replies)"; fail=1; }
        { [ -n "$peers" ] && [ "$peers" -le 30000 ]; } || { echo "FAIL X3 round $r"; fail=1; }
        ip netns exec sk-atk ip addr del "$a/24" dev skva
    done
    exit $fail
    ;;
relapse)
    ROUNDS=$ARG; WAY=${RELAPSE_WAY:-retract}
    [ "$ROUNDS" -le 99 ] || { echo "relapse: at most 99 rounds (one address each)"; exit 2; }
    attacker_ns
    relapsed=0; peers_relapsed=0
    echo "# relapse: $ROUNDS rounds, end by $WAY, node 1 killed (SIGKILL) right after the answer"
    for r in $(seq 1 "$ROUNDS"); do
        a="10.240.0.$((100 + r))"
        ip netns exec sk-atk ip addr add "$a/24" dev skva
        send ipc "SIGNAL#rl$r:bench|$a|-|relapse round $r" >/dev/null
        sleep 3   # over one tick (the block is on disk) and one FlowSpec round (announced)
        case "$WAY" in
        retract) reply=$(send ipc "RETRACT#rl$r:bench|$a") ;;
        unban) reply=$(send ctl "UNBAN_IP:$a") ;;
        *) echo "unknown way $WAY"; exit 2 ;;
        esac
        kill -KILL "${NODE_PID[1]}" 2>/dev/null || true
        wait "${NODE_PID[1]}" 2>/dev/null || true
        t_restart=$(now_ms)
        start_node 1
        for _ in $(seq 1 100); do send ctl LIST_BANS >/dev/null 2>&1 && break; sleep 0.1; done
        rib=""
        if [ -n "$FLOWSPEC" ]; then
            # The lift was answered before the rule was withdrawn: when does the new process do it?
            rib="still in node 1's gobgpd RIB 20 s after the restart"
            while [ $(($(now_ms) - t_restart)) -lt 20000 ]; do
                s=0; rib_has 50051 "$a/32" || s=$?
                [ "$s" = 1 ] && { rib="gone from the RIB $(($(now_ms) - t_restart)) ms after the restart"; break; }
                sleep 0.05
            done
        fi
        sleep 2   # the restored table is applied and a tick ran
        got=$(ip netns exec sk-atk ping -n -c 20 -i 0.05 -W 1 -I "$a" 10.240.0.1 2>/dev/null | awk '/packets transmitted/ { print $4 }' || true)
        active=$(metric 1 'sokol_blocks_active{family="ipv4"}' || true)
        line="round $r: '$reply'; after the restart node 1 answers ${got:-0}/20 pings from $a, blocks_active=${active:-?}${rib:+, rule $rib}"
        for n in $(seq 2 "$N"); do
            pg=$(ip netns exec sk-atk ping -n -c 5 -i 0.05 -W 1 -I "$a" "10.240.0.$n" 2>/dev/null | awk '/packets transmitted/ { print $4 }' || true)
            line="$line, node $n ${pg:-0}/5"
            [ "${pg:-0}" = 0 ] && peers_relapsed=$((peers_relapsed + 1))
        done
        echo "$line"
        [ "${got:-0}" = 0 ] && relapsed=$((relapsed + 1))
        ip netns exec sk-atk ip addr del "$a/24" dev skva
    done
    echo "node 1 blocks a lifted target again after a crash in $relapsed of $ROUNDS rounds; peer x round: $peers_relapsed"
    [ "$relapsed" = 0 ]
    ;;
bulkflush)
    COUNT=$ARG; [ "$COUNT" = 20 ] && COUNT=3000   # ARG defaults to 20 for the other modes
    echo "# bulkflush: $COUNT detector blocks at node 1, then FLUSH_BANS"
    awk -v n="$COUNT" 'BEGIN { for (i = 0; i < n; i++)
        printf "SIGNAL#bf-%d:bulk|100.%d.%d.%d|-|bulk flush\n", i, 64 + int(i / 65536) % 64, int(i / 256) % 256, i % 256 }' \
        | in_ns 1 nc -U -q1 "$WORK/n1/ipc.sock" >/dev/null
    t0=$SECONDS; held=""
    while [ $((SECONDS - t0)) -lt 180 ]; do
        held=1
        for n in $(seq 1 "$N"); do [ "$(metric "$n" 'sokol_blocks_active{family="ipv4"}')" = "$COUNT" ] || held=""; done
        [ -n "$held" ] && break
        sleep 1
    done
    [ -n "$held" ] || { echo "FAIL not every node holds $COUNT blocks after 180 s"; exit 1; }
    rules() { in_ns 1 gobgp -p 50051 global rib -a ipv4-flowspec 2>/dev/null | grep -c "source: 100\." || true; }
    if [ -n "$FLOWSPEC" ]; then
        # 64 FlowSpec operations per round (MAX_OPS_PER_ROUND): the announcements take a while.
        t1=$(now_ms)
        while [ "$(rules)" != "$COUNT" ] && [ $(($(now_ms) - t1)) -lt 600000 ]; do sleep 1; done
        echo "# node 1's gobgpd holds $(rules) of the $COUNT rules ($(($(now_ms) - t1)) ms after every node held the blocks)"
    fi
    t_ask=$(now_ms)
    echo "# every node holds $COUNT blocks; FLUSH_BANS answered: $(send ctl FLUSH_BANS)"
    t_end=$(audit_after 1 "OPERATOR_FLUSH|" "$t_ask")
    fail=0
    for n in $(seq 2 "$N"); do
        gone=""
        while [ $(($(now_ms) - t_end)) -lt 120000 ]; do
            [ "$(metric "$n" 'sokol_blocks_active{family="ipv4"}')" = 0 ] && { gone=$(now_ms); break; }
            sleep 0.05
        done
        dropped=$(grep -c "exceeds limit" "$WORK/n$n/node.log" || true)
        if [ -n "$gone" ]; then echo "node $n holds none of them $((gone - t_end)) ms after the flush; 'frame exceeds limit' in its log: $dropped"
        else echo "node $n still holds $(metric "$n" 'sokol_blocks_active{family="ipv4"}') of them 120 s after the flush"; fail=1; fi
    done
    if [ -n "$FLOWSPEC" ]; then
        gone=""
        while [ $(($(now_ms) - t_end)) -lt 600000 ]; do
            [ "$(rules)" = 0 ] && { gone=$(now_ms); break; }
            sleep 0.5
        done
        if [ -n "$gone" ]; then echo "node 1's gobgpd holds none of the rules $((gone - t_end)) ms after the flush"
        else echo "node 1's gobgpd still holds $(rules) rules 600 s after the flush"; fail=1; fi
    fi
    exit $fail
    ;;
*) echo "unknown mode $MODE"; exit 2 ;;
esac
