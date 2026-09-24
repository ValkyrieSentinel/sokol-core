#!/usr/bin/env bash
# Single-node measurements.
#
#   sudo bench/local.sh latency <orchestrator> [rounds]
#       B4: time from a block signal on the IPC socket to the first dropped packet. A peer pings
#       the node every 2 ms from a fresh address; the signal is sent at t0; the result is the
#       time of the last echo reply after t0 (so it bounds the delay from above, 2 ms resolution).
#
#   sudo bench/local.sh fill <orchestrator> [count]
#       B7: <count> blocks (default 65 536, the map capacity) over one IPC connection with a 20 s
#       TTL: signal rate, time until all are in the kernel map, memory, legitimate traffic
#       during the fill, and time until all have expired again.
set -euo pipefail

MODE=$1; BIN=$2; ARG=${3:-}
NS=skl-peer; HIF=skl0; PIF=skl1; HOST=10.241.0.1
WORK="$(mktemp -d)"; ORCH=""

cleanup() {
    [ -n "$ORCH" ] && { kill "$ORCH" 2>/dev/null || true; wait "$ORCH" 2>/dev/null || true; }
    ip link del "$HIF" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
ip link del "$HIF" 2>/dev/null || true; ip netns del "$NS" 2>/dev/null || true

ip netns add "$NS"
ip link add "$HIF" type veth peer name "$PIF"
ip link set "$PIF" netns "$NS"
ip addr add "$HOST/16" dev "$HIF"; ip link set "$HIF" up
ip netns exec "$NS" ip addr add 10.241.0.2/16 dev "$PIF"
ip netns exec "$NS" ip link set "$PIF" up
ip netns exec "$NS" ip link set lo up

start() {
    "$BIN" --interface "$HIF" --xdp-mode generic --db-path "$WORK/audit.log" --key-file "$WORK/node.key" \
        --ipc-socket "$WORK/ipc.sock" --control-socket "$WORK/ctl.sock" --p2p-bind 127.0.0.1:0 \
        --metrics-bind 127.0.0.1:9471 "$@" >"$WORK/node.log" 2>&1 </dev/null &
    ORCH=$!
    for _ in $(seq 1 100); do grep -q "Sokol-Core running" "$WORK/node.log" && return; sleep 0.1; done
    echo "FAIL node did not start"; cat "$WORK/node.log"; exit 1
}
metric() { curl -s http://127.0.0.1:9471/metrics | awk -v m="$1" '$1 == m { print $2 }'; }
stats() {
    sort -n | awk '{ v[NR] = $1 } END {
        printf "n=%d min=%d median=%d p95=%d max=%d (ms)\n", NR, v[1], v[int((NR + 1) / 2)], v[int((NR - 1) * 0.95) + 1], v[NR]
    }'
}
echo "# host=$(uname -m) cpus=$(nproc) kernel=$(uname -r)"

case "$MODE" in
latency)
    ROUNDS=${ARG:-20}
    start
    : >"$WORK/samples"
    for r in $(seq 1 "$ROUNDS"); do
        src="10.241.1.$r"
        ip netns exec "$NS" ip addr add "$src/16" dev "$PIF"
        ip netns exec "$NS" ping -D -i 0.002 -W 1 -I "$src" "$HOST" >"$WORK/ping.$r" 2>&1 &
        pp=$!
        sleep 0.5
        t0=$(date +%s.%N)
        printf 'DROP_IMMEDIATE:%s\n' "$src" | nc -U -q0 "$WORK/ipc.sock"
        sleep 0.5
        kill "$pp" 2>/dev/null || true; wait "$pp" 2>/dev/null || true
        last=$(grep -o '^\[[0-9.]*\]' "$WORK/ping.$r" | tail -1 | tr -d '[]')
        replies_before=$(awk -v a="$t0" 'match($0, /^\[[0-9.]+\]/) { t = substr($0, 2, RLENGTH - 2); if (t < a) n++ } END { print n + 0 }' "$WORK/ping.$r")
        [ "$replies_before" -gt 0 ] || { echo "FAIL round $r: no echo replies before the signal"; exit 1; }
        awk -v a="$t0" -v b="$last" 'BEGIN { d = (b - a) * 1000; printf "%d\n", (d < 0 ? 0 : d) }' >>"$WORK/samples"
    done
    after=$(awk '$1 > 0' "$WORK/samples" | wc -l)
    echo "B4 signal -> drop: $ROUNDS rounds, pinging every 2 ms; rounds with any reply after the signal: $after"
    echo "   last reply after the signal: $(stats <"$WORK/samples")  (0 = the block took effect within one 2 ms ping interval)"
    ;;
fill)
    COUNT=${ARG:-65536}
    start --block-ttl 20 --block-ttl-max 20
    rss0=$(grep VmRSS /proc/"$ORCH"/status | awk '{print $2}')
    ip netns exec "$NS" ping -i 0.05 "$HOST" >"$WORK/legit.ping" 2>&1 &
    lp=$!
    t0=$(date +%s%3N)
    awk -v n="$COUNT" 'BEGIN { for (i = 0; i < n; i++) printf "DROP_IMMEDIATE:100.%d.%d.%d\n", 64 + int(i / 65536) % 64, int(i / 256) % 256, i % 256 }' \
        | nc -U -q1 "$WORK/ipc.sock"
    t_sent=$(date +%s%3N)
    for _ in $(seq 1 1200); do
        [ "$(metric 'sokol_blocks_active{family="ipv4"}')" = "$COUNT" ] && break
        sleep 0.1
    done
    t_all=$(date +%s%3N)
    rss1=$(grep VmRSS /proc/"$ORCH"/status | awk '{print $2}')
    echo "B7 $COUNT signals written in $((t_sent - t0)) ms; all $(metric 'sokol_blocks_active{family="ipv4"}') in the kernel map after $((t_all - t0)) ms ($(( COUNT * 1000 / (t_all - t0 + 1) )) blocks/s)"
    echo "   RSS $((rss0 / 1024)) MB -> $((rss1 / 1024)) MB; watermark logged: $(grep -c 'blocklist is' "$WORK/node.log")"
    for _ in $(seq 1 600); do
        [ "$(metric 'sokol_blocks_active{family="ipv4"}')" = "0" ] && break
        sleep 0.1
    done
    t_gone=$(date +%s%3N)
    kill -INT "$lp" 2>/dev/null || true; wait "$lp" 2>/dev/null || true
    echo "   all expired $((t_gone - t_all)) ms after the fill completed (TTL 20 s)"
    echo "   legitimate ping during the test: $(grep -E 'packet loss' "$WORK/legit.ping")"
    echo "   rtt: $(grep -E 'rtt' "$WORK/legit.ping")"
    ;;
*) echo "unknown mode $MODE"; exit 2 ;;
esac
