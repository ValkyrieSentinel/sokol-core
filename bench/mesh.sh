#!/usr/bin/env bash
# Mesh measurements on one Linux host: N orchestrators, each in its own network namespace on a
# shared bridge, fully meshed with pinned keys. Times come from the nodes' own audit logs
# (timestamp_ms of each record), so all nodes share one clock.
#
#   sudo bench/mesh.sh propagation <orchestrator> <monitor> <N> [rounds] [netem args...]
#   sudo bench/mesh.sh partition   <orchestrator> <monitor> <N> <seconds down> [netem args...]
#
# propagation: a block is issued on node 1 `rounds` times; for every other node the delay
#              until its MESH_BLOCK record is reported (min / median / p95 / max, and the
#              time until the last node has it).
# partition:   node N's link goes down, a block is issued on node 1, the link comes back after
#              <seconds down>; reports whether and when node N learns the block, and whether the
#              mesh reconnects.
#
# netem args are applied to every node's link, e.g. `delay 100ms 20ms loss 10%`.
set -euo pipefail

MODE=$1; BIN=$2; MON=$3; N=$4; shift 4
ARG=${1:-20}; [ $# -gt 0 ] && shift
NETEM="$*"
WORK="$(mktemp -d)"
BR=skbr0
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null || true; done
    remove_topology
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
    seeds=()
    for j in $(seq 1 $((i - 1))); do seeds+=(--seed-peer "10.240.0.$j:7946"); done
    in_ns "$i" "$BIN" --interface "skv$i" --node-id "$i" --xdp-mode generic \
        --db-path "$WORK/n$i/audit.log" --key-file "$WORK/n$i/node.key" \
        --ipc-socket "$WORK/n$i/ipc.sock" --control-socket "$WORK/n$i/ctl.sock" \
        --p2p-bind "10.240.0.$i:7946" --peers-file "$WORK/n$i/peers.json" \
        --metrics-bind 127.0.0.1:9470 --block-ttl 3600 "${seeds[@]}" \
        >"$WORK/n$i/node.log" 2>&1 </dev/null &
    PIDS+=($!)
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
*) echo "unknown mode $MODE"; exit 2 ;;
esac
