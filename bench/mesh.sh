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
# recover:     recovery contract (docs/reviews/2026-09-28-transfer, T2). Node 1's link is held to
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
# netem args are applied to every node's link, e.g. `delay 100ms 20ms loss 10%`.
set -euo pipefail

MODE=$1; BIN=$2; MON=$3; N=$4; shift 4
ARG=${1:-20}; [ $# -gt 0 ] && shift
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

# Leftovers from an earlier run would make the setup below fail. Deleting a namespace frees
# its veth pair asynchronously, so delete the host ends explicitly.
remove_topology
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
        --metrics-bind 127.0.0.1:9470 --block-ttl "${TTL:-3600}" "${seeds[@]}" \
        >>"$WORK/n$i/node.log" 2>&1 </dev/null &
    NODE_PID[$i]=$!
    PIDS+=($!)
}
declare -A NODE_PID

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
    echo "# soak ${MINUTES} min, TTL ${TTL:-3600} s"
    while [ $SECONDS -lt $end ]; do
        for _ in 1 2 3 4 5; do
            i=$((RANDOM % N + 1))
            # One signal in ten repeats the previous event id (a resend): the node must dedup it.
            [ $((RANDOM % 10)) = 0 ] || k=$((k + 1))
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
    # S4 (exploratory)
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
*) echo "unknown mode $MODE"; exit 2 ;;
esac
