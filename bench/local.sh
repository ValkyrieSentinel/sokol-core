#!/usr/bin/env bash
# Single-node measurements.
#
#   sudo bench/local.sh latency <orchestrator> [rounds]
#       B4: time from a block signal on the IPC socket (t0) to the block's onset. A peer pings
#       the node every 2 ms from a fresh address (ping -O reports each request left unanswered);
#       the onset is the first unanswered request followed by at least ONSET_RUN more unanswered
#       ones, so a single lost packet is not taken for the block. A second address pings in
#       parallel as a control: a round in which the control lost packets is reported as unknown,
#       not as a number. The node's own audit time for the block is reported next to it.
#
#   sudo bench/local.sh fill <orchestrator> [count]
#       B7: <count> blocks (default 65 536, the map capacity) over one IPC connection with a 20 s
#       TTL: signal rate, time until all are in the kernel map, memory, legitimate traffic
#       during the fill, and time until all have expired again. Postconditions are checked, not
#       assumed: the run fails if the map never holds them all or they never all expire, and a
#       packet witness (sampled blocked addresses sending real packets) must see them dropped
#       after the fill and passing after the expiry.
#
# Raw samples and logs are kept in $BENCH_OUT if it is set. A failed postcondition exits 1.
set -euo pipefail
ONSET_RUN=5

MODE=$1; BIN=$2; ARG=${3:-}
NS=skl-peer; HIF=skl0; PIF=skl1; HOST=10.241.0.1
WORK="$(mktemp -d)"; ORCH=""

cleanup() {
    [ -n "$ORCH" ] && { kill "$ORCH" 2>/dev/null || true; wait "$ORCH" 2>/dev/null || true; }
    if [ -n "${BENCH_OUT:-}" ]; then mkdir -p "$BENCH_OUT" && cp -r "$WORK"/. "$BENCH_OUT"/; fi
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
    MON="$(dirname "$BIN")/monitor"
    start
    : >"$WORK/samples"; : >"$WORK/audit_samples"; unknown=0
    ip netns exec "$NS" ip addr add 10.241.2.1/16 dev "$PIF"
    for r in $(seq 1 "$ROUNDS"); do
        src="10.241.1.$r"
        ip netns exec "$NS" ip addr add "$src/16" dev "$PIF"
        ip netns exec "$NS" ping -D -O -i 0.002 -W 1 -I "$src" "$HOST" >"$WORK/ping.$r" 2>&1 &
        pp=$!
        ip netns exec "$NS" ping -D -O -i 0.002 -W 1 -I 10.241.2.1 "$HOST" >"$WORK/control.$r" 2>&1 &
        cp=$!
        sleep 0.5
        t0=$(date +%s.%N)
        printf 'DROP_IMMEDIATE:%s\n' "$src" | nc -U -q0 "$WORK/ipc.sock"
        sleep 0.5
        kill "$pp" "$cp" 2>/dev/null || true; wait "$pp" "$cp" 2>/dev/null || true
        replies_before=$(awk -v a="$t0" '/bytes from/ && match($0, /^\[[0-9.]+\]/) { t = substr($0, 2, RLENGTH - 2); if (t < a) n++ } END { print n + 0 }' "$WORK/ping.$r")
        [ "$replies_before" -gt 0 ] || { echo "FAIL round $r: no echo replies before the signal"; exit 1; }
        # Onset, from sequence numbers (ping prints "no answer yet" late, so its timestamp is not
        # used): M = first request reported unanswered and followed by ONSET_RUN more unanswered
        # ones. Request M-1 was answered, so the block took effect after it and before request M,
        # sent one interval later: onset <= reply(M-1) + 2 ms.
        onset=$(awk -v k="$ONSET_RUN" '
            /bytes from/ && match($0, /icmp_seq=[0-9]+/) {
                seq = substr($0, RSTART + 9, RLENGTH - 9) + 0
                match($0, /^\[[0-9.]+\]/); reply[seq] = substr($0, 2, RLENGTH - 2)
            }
            /no answer yet/ && match($0, /icmp_seq=[0-9]+/) {
                seq = substr($0, RSTART + 9, RLENGTH - 9) + 0
                if (seq == last + 1 && run > 0) run++; else { run = 1; first = seq }
                last = seq
                if (run > k && !done) { done = 1; m = first }
            }
            END { if (done && ((m - 1) in reply)) print reply[m - 1] }' "$WORK/ping.$r")
        control_lost=$(awk -v a="$t0" 'match($0, /^\[[0-9.]+\]/) { t = substr($0, 2, RLENGTH - 2); if (t >= a && $0 ~ /no answer yet/) n++ } END { print n + 0 }' "$WORK/control.$r")
        if [ -z "$onset" ] || [ "$control_lost" -gt 0 ]; then
            unknown=$((unknown + 1))
            echo "   round $r: unknown (onset found: ${onset:-no}; control lost $control_lost)"
            continue
        fi
        awk -v a="$t0" -v b="$onset" 'BEGIN { d = (b - a) * 1000 + 2; printf "%d\n", (d < 0 ? 0 : d) }' >>"$WORK/samples"
        audit=$("$MON" --dump "$WORK/audit.log" 2>/dev/null | awk -F'\t' -v p="DYNAMIC_BLOCK_V4|IP:$src|" 'index($3, p) == 1 { print $2; exit }')
        [ -n "$audit" ] && awk -v a="$t0" -v b="$audit" 'BEGIN { d = b - a * 1000; printf "%d\n", (d < 0 ? 0 : d) }' >>"$WORK/audit_samples"
    done
    measured=$(wc -l <"$WORK/samples")
    echo "B4 signal -> drop: $ROUNDS rounds, pinging every 2 ms; measured $measured, unknown $unknown"
    [ "$measured" -gt 0 ] || { echo "FAIL no round produced a measurement"; exit 1; }
    echo "   onset of the drop, upper bound (last answered request + 2 ms, then >= $((ONSET_RUN + 1)) unanswered): $(stats <"$WORK/samples")"
    echo "   node's audit record of the block:                                   $(stats <"$WORK/audit_samples")"
    ;;
fill)
    COUNT=${ARG:-65536}
    start --block-ttl 20 --block-ttl-max 20
    # Packet witness: a few of the addresses that will be blocked, sending real packets.
    WITNESS=()
    for i in 7 4099 20011 40009 $((COUNT - 1)); do
        [ "$i" -lt "$COUNT" ] || continue
        WITNESS+=("100.$((64 + i / 65536 % 64)).$((i / 256 % 256)).$((i % 256))")
    done
    for w in "${WITNESS[@]}"; do ip netns exec "$NS" ip addr add "$w/32" dev "$PIF"; done
    ip route add 100.64.0.0/10 dev "$HIF" 2>/dev/null || true   # replies back to the witnesses
    witness_pass() { local n=0; for w in "${WITNESS[@]}"; do ip netns exec "$NS" ping -c 1 -W 1 -I "$w" "$HOST" >/dev/null 2>&1 && n=$((n + 1)); done; echo "$n"; }
    before=$(witness_pass)
    [ "$before" = "${#WITNESS[@]}" ] || { echo "FAIL witness: only $before of ${#WITNESS[@]} addresses reach the node before the fill"; exit 1; }
    rss0=$(grep VmRSS /proc/"$ORCH"/status | awk '{print $2}')
    ip netns exec "$NS" ping -i 0.05 -I 10.241.0.2 "$HOST" >"$WORK/legit.ping" 2>&1 &
    lp=$!
    t0=$(date +%s%3N)
    awk -v n="$COUNT" 'BEGIN { for (i = 0; i < n; i++) printf "DROP_IMMEDIATE:100.%d.%d.%d\n", 64 + int(i / 65536) % 64, int(i / 256) % 256, i % 256 }' \
        | nc -U -q1 "$WORK/ipc.sock"
    t_sent=$(date +%s%3N)
    filled=""; peak=0
    for _ in $(seq 1 1200); do
        now=$(metric 'sokol_blocks_active{family="ipv4"}'); now=${now:-0}
        [ "$now" -gt "$peak" ] && peak=$now
        [ "$now" = "$COUNT" ] && { filled=1; break; }
        sleep 0.1
    done
    t_all=$(date +%s%3N)
    [ -n "$filled" ] || { echo "FAIL the kernel map never held all $COUNT blocks within 120 s (peak $peak, capacity $(metric sokol_blocks_capacity), pending now $(metric sokol_blocks_pending))"; exit 1; }
    during=$(witness_pass)
    [ "$during" = 0 ] || { echo "FAIL witness: $during of ${#WITNESS[@]} blocked addresses still reach the node"; exit 1; }
    rss1=$(grep VmRSS /proc/"$ORCH"/status | awk '{print $2}')
    echo "B7 $COUNT signals written in $((t_sent - t0)) ms; all $COUNT in the kernel map after $((t_all - t0)) ms ($(( COUNT * 1000 / (t_all - t0 + 1) )) blocks/s); witness: ${#WITNESS[@]}/${#WITNESS[@]} sampled addresses dropped"
    echo "   RSS $((rss0 / 1024)) MB -> $((rss1 / 1024)) MB; watermark logged: $(grep -c 'blocklist is' "$WORK/node.log")"
    gone=""
    for _ in $(seq 1 600); do
        [ "$(metric 'sokol_blocks_active{family="ipv4"}')" = "0" ] && { gone=1; break; }
        sleep 0.1
    done
    t_gone=$(date +%s%3N)
    kill -INT "$lp" 2>/dev/null || true; wait "$lp" 2>/dev/null || true
    [ -n "$gone" ] || { echo "FAIL $(metric 'sokol_blocks_active{family="ipv4"}') blocks still active 60 s after the fill (TTL 20 s)"; exit 1; }
    after=$(witness_pass)
    [ "$after" = "${#WITNESS[@]}" ] || { echo "FAIL witness: only $after of ${#WITNESS[@]} addresses pass again after the expiry"; exit 1; }
    echo "   all expired $((t_gone - t_all)) ms after the fill completed (TTL 20 s); witness: all pass again"
    echo "   legitimate ping during the test: $(grep -E 'packet loss' "$WORK/legit.ping")"
    echo "   rtt: $(grep -E 'rtt' "$WORK/legit.ping")"
    ;;
*) echo "unknown mode $MODE"; exit 2 ;;
esac
