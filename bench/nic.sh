#!/usr/bin/env bash
# Packet-rate measurement of the XDP filter (P4: the one thing the lab cannot do is a real NIC).
#
#   sudo bench/nic.sh local <orchestrator> [mode] [rates...]
#       One host: the node in netns "dut" on a veth, the kernel's pktgen on the other end.
#       A dry run of the method; veth takes native XDP, so mode (default native) is real here.
#   sudo bench/nic.sh dut <orchestrator> <iface> [mode]
#       On the machine under test: starts the node on <iface> blocking 198.18.0.0/24 and prints
#       its drop counters every second until interrupted. Metrics on 127.0.0.1:9469.
#   sudo bench/nic.sh gen <iface> <dut-mac> <dut-ip> <pps> <seconds>
#       On the traffic source: pktgen from 198.18.0.1-254 (blocked) to <dut-ip> at <pps>
#       (0 = as fast as it goes), 64-byte frames.
#
# For each rate `local` reports: packets sent, dropped by XDP, the drop share, the node's
# CPU (softirq and total, over the step) and a legitimate ping's loss and p50/p99 RTT from an
# unblocked address under load. Read the results as a curve: the rate at which the drop share
# falls below 99.9 % or the ping starts losing is the filter's capacity on this machine.
# Rates default to 10k, 100k, 300k, 1M pps and unlimited; each step lasts $STEP s (10). The first
# row, idle, is the same step without traffic: CPU under load is read against it. In `local`
# the generator runs on the same CPUs, so its own cost is in the CPU columns too.
# A node that is not running with XDP fails the run instead of printing zeros.
set -uo pipefail

ROLE=${1:?role}; shift
STEP=${STEP:-10}
BLOCKED=198.18.0.0/24
MAC_OF() { cat "/sys/class/net/$1/address"; }

pktgen_run() {   # pktgen_run <iface> <dst-mac> <dst-ip> <pps> <seconds>: prints packets sent
    local ifc=$1 mac=$2 ip=$3 pps=$4 secs=$5 count
    modprobe pktgen
    local thread=/proc/net/pktgen/kpktgend_0 dev=/proc/net/pktgen/$1
    echo "rem_device_all" >"$thread"
    echo "add_device $ifc" >"$thread"
    count=$(( pps > 0 ? pps * secs : 0 ))
    {
        echo "count $count"; echo "pkt_size 60"; echo "delay 0"
        [ "$pps" -gt 0 ] && echo "ratep $pps"
        echo "dst $ip"; echo "dst_mac $mac"
        echo "src_min 198.18.0.1"; echo "src_max 198.18.0.254"
        echo "flag IPSRC_RND"; echo "udp_dst_min 9"; echo "udp_dst_max 9"
    } | while read -r line; do echo "$line" >"$dev"; done
    if [ "$pps" = 0 ]; then
        ( sleep "$secs"; echo stop >/proc/net/pktgen/pgctrl ) &
    fi
    echo start >/proc/net/pktgen/pgctrl 2>/dev/null
    wait 2>/dev/null
    awk '/pkts-sofar/ {print $2}' "$dev"
}

# /proc/stat "cpu": user nice system idle iowait irq softirq steal. Prints: total softirq busy.
cpu_sample() { awk '/^cpu / {t = $2+$3+$4+$5+$6+$7+$8+$9; print t, $8, t - $5 - $6}' /proc/stat; }

case "$ROLE" in
gen)
    pktgen_run "$1" "$2" "$3" "$4" "$5" | sed 's/^/sent /'
    ;;
dut)
    BIN=$1; IFC=$2; MODE=${3:-native}
    W=$(mktemp -d); trap 'kill $P 2>/dev/null; wait $P 2>/dev/null; rm -rf $W' EXIT
    "$BIN" --interface "$IFC" --xdp-mode "$MODE" --block "$BLOCKED" --db-path "$W/audit.log" \
        --key-file "$W/node.key" --ipc-socket "$W/ipc.sock" --control-socket "$W/ctl.sock" \
        --p2p-bind 127.0.0.1:0 --metrics-bind 127.0.0.1:9469 >"$W/node.log" 2>&1 &
    P=$!
    sleep 3
    ip -d link show "$IFC" | grep -q 'prog/xdp' || { echo "FAIL no XDP on $IFC:"; tail -5 "$W/node.log"; exit 1; }
    grep -o 'XDP program successfully.*' "$W/node.log"
    prev=0; read -r t0 s0 b0 < <(cpu_sample)
    while sleep 1; do
        d=$(curl -s 127.0.0.1:9469/metrics | awk '$1 == "sokol_xdp_dropped_packets_total{reason=\"static_block\"}" || $1 == "sokol_xdp_dropped_packets_total{reason=\"blocklist\"}" {s += $2} END {print s + 0}')
        read -r t1 s1 b1 < <(cpu_sample); dt=$((t1 - t0)); [ "$dt" -gt 0 ] || dt=1
        echo "dropped/s $((d - prev))  total $d  softirq $(awk -v a=$((s1 - s0)) -v t=$dt 'BEGIN {printf "%.1f", 100 * a / t}')%  busy $(awk -v a=$((b1 - b0)) -v t=$dt 'BEGIN {printf "%.1f", 100 * a / t}')%"
        prev=$d; t0=$t1; s0=$s1; b0=$b1
    done
    ;;
local)
    BIN=$1; shift; MODE=${1:-native}; [ $# -gt 0 ] && shift
    RATES=("$@"); [ ${#RATES[@]} = 0 ] && RATES=(10000 100000 300000 1000000 0)
    W=$(mktemp -d)
    cleanup() { kill "$P" 2>/dev/null; wait "$P" 2>/dev/null; ip netns del dut 2>/dev/null; ip link del nicg0 2>/dev/null; rm -rf "$W"; }
    trap cleanup EXIT; trap "exit 130" INT TERM
    ip link add nicg0 type veth peer name nicd0
    ip netns add dut; ip link set nicd0 netns dut
    ip addr add 10.252.0.1/24 dev nicg0; ip addr add 10.252.0.3/24 dev nicg0; ip link set nicg0 up
    ip netns exec dut ip addr add 10.252.0.2/24 dev nicd0
    ip netns exec dut ip link set nicd0 up; ip netns exec dut ip link set lo up
    # Replies to the blocked sources would need a route; the XDP drop happens before that.
    ip netns exec dut "$BIN" --interface nicd0 --xdp-mode "$MODE" --block "$BLOCKED" \
        --db-path "$W/audit.log" --key-file "$W/node.key" --ipc-socket "$W/ipc.sock" \
        --control-socket "$W/ctl.sock" --p2p-bind 127.0.0.1:0 --metrics-bind 127.0.0.1:9469 \
        >"$W/node.log" 2>&1 </dev/null &
    P=$!
    for _ in $(seq 1 50); do ip netns exec dut curl -s 127.0.0.1:9469/metrics >/dev/null 2>&1 && break; sleep 0.2; done
    # A node that did not start measures nothing: refuse to print a table of zeros.
    ip netns exec dut ip -d link show nicd0 | grep -q 'prog/xdp' \
        || { echo "FAIL the node is not running with XDP on nicd0:"; tail -5 "$W/node.log"; exit 1; }
    dropped() { ip netns exec dut curl -s 127.0.0.1:9469/metrics | awk '$1 == "sokol_xdp_dropped_packets_total{reason=\"static_block\"}" || $1 == "sokol_xdp_dropped_packets_total{reason=\"blocklist\"}" {s += $2} END {print s + 0}'; }
    DMAC=$(ip netns exec dut cat /sys/class/net/nicd0/address)
    echo "# $(grep -o 'XDP program successfully.*' "$W/node.log") | host=$(uname -m) cpus=$(nproc) kernel=$(uname -r) step=${STEP}s"
    printf '%-10s %12s %12s %8s %9s %9s %8s %9s %9s\n' target_pps sent_pps dropped_pps drop_% softirq_% busy_% ping_loss p50_ms p99_ms
    # Baseline: the same step with no generator, so CPU under load reads against it.
    read -r t0 s0 b0 < <(cpu_sample)
    ping -I 10.252.0.3 -i 0.01 -w "$STEP" -D 10.252.0.2 >"$W/ping" 2>&1
    read -r t1 s1 b1 < <(cpu_sample); dt=$((t1 - t0)); [ "$dt" -gt 0 ] || dt=1
    read -r p50 p99 < <(grep -o 'time=[0-9.]*' "$W/ping" | cut -d= -f2 | sort -n | awk '{a[NR]=$1} END {print a[int(NR*0.5)+1], a[int(NR*0.99)+1]}')
    printf '%-10s %12s %12s %8s %9s %9s %8s %9s %9s\n' idle 0 0 - \
        "$(awk -v a=$((s1 - s0)) -v t=$dt 'BEGIN {printf "%.1f", 100 * a / t}')" \
        "$(awk -v a=$((b1 - b0)) -v t=$dt 'BEGIN {printf "%.1f", 100 * a / t}')" \
        "$(grep -o '[0-9.]*% packet loss' "$W/ping" | cut -d% -f1)%" "$p50" "$p99"
    for pps in "${RATES[@]}"; do
        d0=$(dropped); read -r t0 s0 b0 < <(cpu_sample)
        ping -I 10.252.0.3 -i 0.01 -w "$STEP" -D 10.252.0.2 >"$W/ping" 2>&1 &
        pp=$!
        sent=$(pktgen_run nicg0 "$DMAC" 10.252.0.2 "$pps" "$STEP")
        wait "$pp" 2>/dev/null
        sleep 1.5   # metrics refresh
        d1=$(dropped); read -r t1 s1 b1 < <(cpu_sample)
        dt=$((t1 - t0)); [ "$dt" -gt 0 ] || dt=1
        loss=$(grep -o '[0-9.]*% packet loss' "$W/ping" | cut -d% -f1)
        read -r p50 p99 < <(grep -o 'time=[0-9.]*' "$W/ping" | cut -d= -f2 | sort -n | awk '{a[NR]=$1} END {if (NR) print a[int(NR*0.5)+(NR*0.5>int(NR*0.5))], a[int(NR*0.99)+(NR*0.99>int(NR*0.99))]; else print "-", "-"}')
        drop=$((d1 - d0))
        share=$(awk -v d="$drop" -v s="${sent:-0}" 'BEGIN { if (s > 0) printf "%.2f", 100 * d / s; else print "-" }')
        printf '%-10s %12s %12s %8s %9s %9s %8s %9s %9s\n' "${pps/#0/max}" "$(( ${sent:-0} / STEP ))" "$(( drop / STEP ))" "$share" \
            "$(awk -v a=$((s1 - s0)) -v t=$dt 'BEGIN {printf "%.1f", 100 * a / t}')" \
            "$(awk -v a=$((b1 - b0)) -v t=$dt 'BEGIN {printf "%.1f", 100 * a / t}')" "${loss:--}%" "$p50" "$p99"
    done
    ;;
*) echo "role: local | dut | gen"; exit 2 ;;
esac
