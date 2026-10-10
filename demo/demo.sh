#!/usr/bin/env bash
# Sokol-Core demo: three nodes in a mesh, an attacker, a rogue node, Suricata on node 1 and the
# operator dashboard — on one Linux machine, in network namespaces. Every step checks its own
# outcome, so the demo is also a test.
#
#   sudo demo/demo.sh [target/release]          # pauses before each step (press Enter)
#   sudo DEMO_AUTO=1 demo/demo.sh               # no pauses (recording with narration, or CI)
#
# Needs: iproute2, ping, nc (openbsd), curl, suricata. Open http://127.0.0.1:3000 during the demo
# to watch the dashboard (the token is printed below).
set -euo pipefail

BIN_DIR="${1:-target/release}"
ORCH="$BIN_DIR/orchestrator"; MON="$BIN_DIR/monitor"
WORK="$(mktemp -d)"; BR=sdemo0; PIDS=(); FAILED=0
ATTACKER=10.250.0.66; ROGUE=10.250.0.99; OPERATOR=10.250.0.10
TTL=25

bold() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
say() { printf '   %s\n' "$*"; }
ok() { printf '   \033[1;32m✔ %s\033[0m\n' "$*"; }
bad() { printf '   \033[1;31m✘ %s\033[0m\n' "$*"; FAILED=1; }
expect() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
pause() { if [ -z "${DEMO_AUTO:-}" ]; then read -r -p "   [Enter] " _ </dev/tty; else sleep 1; fi; }
now_ms() { date +%s%3N; }

cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null || true; done
    for n in n1 n2 n3 attacker rogue; do
        ip link del "sd-$n-h" 2>/dev/null || true
        ip netns del "sd-$n" 2>/dev/null || true
    done
    ip link del "$BR" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
# A missing tool would otherwise show up as "node 1 does not drop the attacker".
for tool in ip ping nc curl suricata; do
    command -v "$tool" >/dev/null || { echo "demo needs $tool (see the header)"; exit 2; }
done
cleanup_quiet() { cleanup 2>/dev/null; WORK="$(mktemp -d)"; }
cleanup_quiet

in_ns() { local n=$1; shift; ip netns exec "sd-$n" "$@"; }
metric() { in_ns "$1" curl -s http://127.0.0.1:9470/metrics | awk -v m="$2" '$1 == m { print $2 }'; }
reaches() { in_ns "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1; }
audit_ts() { "$MON" --dump "$WORK/$1/audit.log" 2>/dev/null | awk -F'\t' -v p="$2|IP:$3|" 'index($3, p) == 1 { print $2; exit }'; }

# ---------------------------------------------------------------- topology
ip link add "$BR" type bridge && ip link set "$BR" up
declare -A ADDR=([n1]=10.250.0.1 [n2]=10.250.0.2 [n3]=10.250.0.3 [attacker]=$ATTACKER [rogue]=$ROGUE)
for n in n1 n2 n3 attacker rogue; do
    ip netns add "sd-$n"
    ip link add "sd-$n-h" type veth peer name "sd-$n"
    ip link set "sd-$n-h" master "$BR" up
    ip link set "sd-$n" netns "sd-$n"
    in_ns "$n" ip addr add "${ADDR[$n]}/24" dev "sd-$n"
    in_ns "$n" ip link set "sd-$n" up
    in_ns "$n" ip link set lo up
done
in_ns attacker ip addr add "$OPERATOR/24" dev sd-attacker   # a second, "operator" address used in step 4

for n in n1 n2 n3 rogue; do
    mkdir -p "$WORK/$n"
    "$ORCH" --key-file "$WORK/$n/node.key" --print-public-key >"$WORK/$n/pub" 2>/dev/null
done
for n in n1 n2 n3; do
    {
        printf '['; sep=""
        for m in n1 n2 n3; do
            [ "$m" = "$n" ] && continue
            printf '%s{"node_id": %s, "public_key": "%s"}' "$sep" "${m#n}" "$(cat "$WORK/$m/pub")"; sep=", "
        done
        printf ']'
    } >"$WORK/$n/peers.json"
done
printf '[{"node_id": 1, "public_key": "%s"}]' "$(cat "$WORK/n1/pub")" >"$WORK/rogue/peers.json"

start_node() {   # start_node <name> <id> [extra args...]
    local n=$1 id=$2; shift 2
    # ip netns exec, not in_ns: $! of a backgrounded function is its subshell, and cleanup
    # killed only that, leaving the node running (and heartbeating) after the demo.
    ip netns exec "sd-$n" "$ORCH" --interface "sd-$n" --node-id "$id" --xdp-mode generic \
        --db-path "$WORK/$n/audit.log" --key-file "$WORK/$n/node.key" \
        --ipc-socket "$WORK/$n/ipc.sock" --control-socket "$WORK/$n/ctl.sock" \
        --p2p-bind "${ADDR[$n]}:7946" --peers-file "$WORK/$n/peers.json" \
        --metrics-bind 127.0.0.1:9470 --block-ttl "$TTL" --attack-drops-per-sec 50 \
        --storm-threshold 0.3 --never-block "$OPERATOR" "$@" >"$WORK/$n/node.log" 2>&1 </dev/null &
    PIDS+=($!)
}

bold "Setup: three Sokol nodes, fully meshed with pinned keys"
start_node n1 1
start_node n2 2 --seed-peer 10.250.0.1:7946
start_node n3 3 --seed-peer 10.250.0.1:7946 --seed-peer 10.250.0.2:7946
for _ in $(seq 1 60); do
    [ "$(metric n1 sokol_p2p_active_peers)" = 2 ] && [ "$(metric n2 sokol_p2p_active_peers)" = 2 ] \
        && [ "$(metric n3 sokol_p2p_active_peers)" = 2 ] && break
    sleep 0.5
done
expect "each node is connected to the other two" test "$(metric n3 sokol_p2p_active_peers)" = 2

OP_TOKEN=demo-operator-token-0123
SOKOL_OPERATOR_TOKEN=$OP_TOKEN SOKOL_OPERATOR_BIND=127.0.0.1:3000 "$BIN_DIR/sokol-operator" >"$WORK/operator.log" 2>&1 </dev/null &
PIDS+=($!)
say "Operator dashboard: http://127.0.0.1:3000  (token: $OP_TOKEN)"

printf 'alert tcp any any -> any 23 (msg:"DEMO telnet scan"; flags:S; classtype:attempted-recon; sid:1000001; rev:1;)\n' >"$WORK/demo.rules"
mkdir -p "$WORK/suricata"
ip netns exec sd-n1 suricata -c /etc/suricata/suricata.yaml -S "$WORK/demo.rules" -i sd-n1 -l "$WORK/suricata" -k none \
    --set outputs.1.eve-log.enabled=yes >"$WORK/suricata.out" 2>&1 </dev/null &
PIDS+=($!)
for _ in $(seq 1 120); do grep -qi "engine started" "$WORK/suricata/suricata.log" 2>/dev/null && break; sleep 0.5; done
touch "$WORK/suricata/eve.json"
"$BIN_DIR/sokol-suricata" --eve "$WORK/suricata/eve.json" --ipc-socket "$WORK/n1/ipc.sock" >"$WORK/adapter.log" 2>&1 </dev/null &
PIDS+=($!)
say "Suricata watches node 1 with a rule for telnet scans; sokol-suricata forwards its alerts."
expect "the attacker can reach all three nodes" bash -c "$(declare -f in_ns reaches); reaches attacker 10.250.0.1 && reaches attacker 10.250.0.2 && reaches attacker 10.250.0.3"
pause

# ---------------------------------------------------------------- step 1
bold "1. The attacker scans node 1. Suricata alerts; all three nodes block the attacker."
t_scan=$(now_ms)
in_ns attacker nc -z -w 1 -s "$ATTACKER" 10.250.0.1 23 2>/dev/null || true
for _ in $(seq 1 50); do [ -n "$(audit_ts n3 MESH_BLOCK_V4 "$ATTACKER")" ] && break; sleep 0.1; done
t1=$(audit_ts n1 DYNAMIC_BLOCK_V4 "$ATTACKER"); t2=$(audit_ts n2 MESH_BLOCK_V4 "$ATTACKER"); t3=$(audit_ts n3 MESH_BLOCK_V4 "$ATTACKER")
if [ -n "$t1" ] && [ -n "$t2" ] && [ -n "$t3" ]; then
    say "scan -> blocked on node 1: $((t1 - t_scan)) ms; node 2: +$((t2 - t1)) ms; node 3: +$((t3 - t1)) ms"
fi
say "reason on node 1: $(grep -o "Dynamic block enforced in XDP: $ATTACKER.*" "$WORK/n1/node.log" | head -1 | cut -c1-110)"
expect "node 1 drops the attacker" bash -c "$(declare -f in_ns reaches); ! reaches attacker 10.250.0.1"
expect "node 2 drops the attacker (it never saw the scan)" bash -c "$(declare -f in_ns reaches); ! reaches attacker 10.250.0.2"
expect "node 3 drops the attacker (it never saw the scan)" bash -c "$(declare -f in_ns reaches); ! reaches attacker 10.250.0.3"
pause

# ---------------------------------------------------------------- step 2
bold "2. A rogue node with its own valid key tries to order a block."
say "Its key is not pinned in the other nodes' peers files."
start_node rogue 99 --seed-peer 10.250.0.1:7946
sleep 3
printf 'DROP_IMMEDIATE:%s\n' "10.250.0.3" | in_ns rogue nc -U -q1 "$WORK/rogue/ipc.sock" || true
sleep 1
say "node 1: $(grep -o 'Rejected envelope .*UnknownSender' "$WORK/n1/node.log" | head -1)"
expect "node 1 rejected the rogue node" grep -q "UnknownSender" "$WORK/n1/node.log"
expect "no node blocked node 3's address on the rogue's order" bash -c "! grep -q 'Synchronized block for 10.250.0.3' '$WORK'/n1/node.log '$WORK'/n2/node.log"
pause

# ---------------------------------------------------------------- step 3
bold "3. A flood hits node 2. XDP drops it; node 1 sees a distributed storm."
in_ns attacker timeout 8 ping -f -I "$ATTACKER" 10.250.0.2 >/dev/null 2>&1 || true
for _ in $(seq 1 30); do [ "$(metric n1 sokol_cluster_status)" = 3 ] && break; sleep 0.5; done
say "node 2 dropped $(metric n2 'sokol_xdp_dropped_packets_total{reason="blocklist"}') packets from the blocked attacker"
say "cluster as seen by node 1: $(metric n1 sokol_cluster_nodes_under_attack) of $(metric n1 sokol_cluster_nodes) nodes under attack, status $(metric n1 sokol_cluster_status) (3 = storm)"
expect "node 1 reports a distributed storm" test "$(metric n1 sokol_cluster_status)" = 3
pause

# ---------------------------------------------------------------- step 4
bold "4. Automation tries to block the operator's address. The policy refuses."
printf 'SIGNAL:suricata|%s|10.250.0.1|sid:9999 false positive on the operator\n' "$OPERATOR" | in_ns n1 nc -U -q1 "$WORK/n1/ipc.sock"
sleep 1
say "node 1: $(grep -o "signal not enforced: source $OPERATOR is protected.*" "$WORK/n1/node.log" | head -1)"
expect "the operator's address is still reachable" bash -c "$(declare -f in_ns); in_ns attacker ping -c 1 -W 1 -I $OPERATOR 10.250.0.1 >/dev/null 2>&1"
pause

# ---------------------------------------------------------------- step 5
bold "5. Blocks expire on their own ($TTL s); the audit trail verifies."
say "waiting for the TTL..."
for _ in $(seq 1 $((TTL * 2 + 10))); do
    [ -n "$(audit_ts n3 BLOCK_EXPIRED_V4 "$ATTACKER")" ] && break; sleep 1
done
expect "all nodes let the attacker through again after the TTL" bash -c "$(declare -f in_ns reaches); reaches attacker 10.250.0.1 && reaches attacker 10.250.0.2 && reaches attacker 10.250.0.3"
for n in n1 n2 n3; do
    say "$n audit: $("$MON" --verify "$WORK/$n/audit.log" | cut -c1-100)"
done
expect "every node's audit chain verifies" bash -c "for n in n1 n2 n3; do '$MON' --verify '$WORK'/\$n/audit.log >/dev/null || exit 1; done"

bold "Done"
[ "$FAILED" -eq 0 ] && ok "all demo steps behaved as expected" || { bad "some steps failed; logs: $WORK"; exit 1; }
