#!/usr/bin/env bash
# Event-memory saturation: one node gets <count> (200000) unique detector events through IPC with
# a 10 s block TTL, so the block table churns while the detector-event memory (ADR-0009,
# 65536 ids) fills and then evicts. Every 10 s: RSS, remembered and evicted ids, active blocks,
# state file size. The plateau claim is: once remembered ids reach the cap, RSS and the state
# file stop growing while events keep arriving. A node's event memory holds its own detectors'
# events only, so a mesh soak at a few events/s would need days to reach it.
#   sudo bench/event-saturation.sh <orchestrator> [count]
set -euo pipefail
BIN=$1; COUNT=${2:-200000}
W=$(mktemp -d); trap 'kill $P 2>/dev/null; wait $P 2>/dev/null; ip link del evs0 2>/dev/null; rm -rf $W' EXIT
ip link add evs0 type veth peer name evs1; ip link set evs0 up; ip link set evs1 up
"$BIN" --interface evs0 --node-id 1 --xdp-mode generic --db-path $W/audit.log --key-file $W/node.key \
  --ipc-socket $W/ipc.sock --control-socket $W/ctl.sock --p2p-bind 127.0.0.1:0 \
  --metrics-bind 127.0.0.1:9479 --block-ttl 10 >$W/node.log 2>&1 & P=$!
for _ in $(seq 1 50); do [ -S $W/ipc.sock ] && break; sleep 0.2; done
m() { curl -s 127.0.0.1:9479/metrics | awk -v k="$1" '$1==k {print $2}'; }
echo "t_s,rss_kb,remembered,evicted,blocks_active,state_bytes"
( awk -v n=$COUNT 'BEGIN { for (i = 0; i < n; i++) printf "SIGNAL#sat-%d:sat|100.%d.%d.%d|-|sat\n", i, 64 + int(i/65536)%64, int(i/256)%256, i%256 }' | nc -U -q1 $W/ipc.sock >/dev/null ) & S=$!
t0=$SECONDS
while kill -0 $S 2>/dev/null || [ $((SECONDS - t0)) -lt 5 ]; do
  echo "$((SECONDS-t0)),$(awk '/VmRSS/{print $2}' /proc/$P/status),$(m sokol_event_ids_remembered),$(m sokol_event_ids_evicted_total),$(m 'sokol_blocks_active{family="ipv4"}'),$(stat -c %s $W/audit.log.blocks.json 2>/dev/null || echo 0)"
  sleep 10
done
sleep 20
echo "$((SECONDS-t0)),$(awk '/VmRSS/{print $2}' /proc/$P/status),$(m sokol_event_ids_remembered),$(m sokol_event_ids_evicted_total),$(m 'sokol_blocks_active{family="ipv4"}'),$(stat -c %s $W/audit.log.blocks.json 2>/dev/null || echo 0)"
echo "# panics: $(grep -c panicked $W/node.log || true)"
