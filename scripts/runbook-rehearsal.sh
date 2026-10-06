#!/usr/bin/env bash
# Runbook rehearsal: follows docs/RUNBOOK.md on a clean host as an operator would, with its
# commands as written, and reports every place where the runbook and the software disagree.
#
#   sudo scripts/runbook-rehearsal.sh <dir with orchestrator, monitor> <dir with another build>
#
# Needs a fresh systemd host (it creates the sokol user, groups, unit and /etc files) and root.
# Traffic runs over a veth pair to a network namespace ("remote"), not over the host's own
# link, so a ban cannot cut the operator off. The second build stands in for an upgrade.
# Not rehearsed: §1 building from source (installs the given binaries), §2/§6 with other
# nodes (one node, empty peers file), §5.5/§5.6 (need peers and detectors).
set -uo pipefail

A=$(cd "$1" && pwd); B=$(cd "$2" && pwd)
REPO=$(cd "$(dirname "$0")/.." && pwd)
IF=pilot0; PEER_IF=pilot1; NS=remote
HOST_IP=10.250.0.1; REMOTE_IP=10.250.0.2; SUSPECT=10.250.0.7
fails=0; deviations=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
deviation() { echo "RUNBOOK DEVIATION  $*"; deviations=$((deviations + 1)); }
step() { echo; echo "== $*"; }

# The runbook's own shorthands, verbatim.
ctl() { printf '%s\n' "$1" | sudo nc -U -q1 /run/sokol/control.sock; }
metric() { curl -s http://127.0.0.1:9469/metrics | grep "^$1"; }
value() { metric "$1" | awk '{print $2}' | head -1; }
# Required node health, matching the runbook §4 and the dashboard/alert scope.
# Optional worker status (e.g. FlowSpec pending/disabled) has its own contract.
node_health() {
    local snapshot
    if ! snapshot=$(curl -fsS --max-time 2 http://127.0.0.1:9469/metrics); then
        printf 'UNVERIFIED node health: HTTP read failed\n' >&2
        return 2
    fi
    printf '%s\n' "$snapshot" | awk '
        BEGIN {
            split("sokol_audit_healthy sokol_state_healthy sokol_state_restore_ok sokol_protected_refresh_ok", names)
            for (i in names) required[names[i]] = 1
        }
        $1 in required {
            if (seen[$1]++ || NF != 2 || $2 !~ /^1(\.0+)?$/) bad[$1] = $0
        }
        END {
            failed = 0
            for (name in required) {
                if (!seen[name]) {print "missing " name; failed = 1}
                else if (name in bad) {print "unhealthy " bad[name]; failed = 1}
            }
            exit failed
        }'
}
reachable() { ip netns exec "$NS" ping -c 1 -W 1 -I "$1" "$HOST_IP" >/dev/null 2>&1; }
wait_until() { local t=$1; shift; for _ in $(seq 1 $((t * 5))); do "$@" && return 0; sleep 0.2; done; return 1; }
up() { systemctl is-active --quiet sokol-orchestrator && [ -n "$(value sokol_build_info)" ]; }

cleanup() {
    systemctl stop sokol-orchestrator 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    ip link del "$IF" 2>/dev/null
}
trap cleanup EXIT
trap "exit 130" INT TERM

# The rehearsal needs a fresh host. State it left on an earlier run (marked) is removed, so it
# can be repeated on one machine (scripts/local-ci.sh); state it did not create is never touched.
MARK=/var/lib/sokol/.runbook-rehearsal
if [ -e /var/lib/sokol ]; then
    if [ -e "$MARK" ]; then
        systemctl stop sokol-orchestrator 2>/dev/null
        rm -rf /var/lib/sokol /etc/sokol /etc/default/sokol
        echo "removed the state of an earlier rehearsal"
    else
        echo "FAIL  /var/lib/sokol exists and was not made by this rehearsal: needs a fresh host"
        exit 1
    fi
fi

ip link add "$IF" type veth peer name "$PEER_IF"
ip netns add "$NS"; ip link set "$PEER_IF" netns "$NS"
ip addr add "$HOST_IP/24" dev "$IF"; ip link set "$IF" up
ip netns exec "$NS" ip addr add "$REMOTE_IP/24" dev "$PEER_IF"
ip netns exec "$NS" ip addr add "$SUSPECT/24" dev "$PEER_IF"
ip netns exec "$NS" ip link set "$PEER_IF" up
ip netns exec "$NS" ip link set lo up

step "§1 install (binaries given; building from source is not rehearsed)"
id sokol >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin sokol
getent group sokol-ipc >/dev/null || sudo groupadd --system sokol-ipc
getent group sokol-ops >/dev/null || sudo groupadd --system sokol-ops
sudo install -m 0755 "$A/orchestrator" /usr/local/bin/sokol-orchestrator
sudo install -m 0755 "$A/monitor" /usr/local/bin/sokol-monitor
sudo install -m 0644 "$REPO/deploy/sokol-orchestrator.service" /etc/systemd/system/
sudo install -d -o sokol -g sokol -m 0700 /var/lib/sokol
sudo touch "$MARK"
sudo install -d -m 0755 /etc/sokol
systemctl daemon-reload
# §1's example with this host's interface and without a seed peer (one node).
cat >/etc/default/sokol <<EOF
SOKOL_ARGS=--interface $IF --node-id 1 --peers-file /etc/sokol/peers.json \
  --metrics-bind 127.0.0.1:9469 \
  --never-block 203.0.113.0/24
EOF
id sokol >/dev/null && getent group sokol-ipc sokol-ops >/dev/null && pass "§1 user, groups, binaries and unit installed as written"

step "§2 keys and peers"
out=$(sudo -u sokol /usr/local/bin/sokol-orchestrator --key-file /var/lib/sokol/node.key --print-public-key 2>&1)
if echo "$out" | grep -q '^mldsa65:'; then
    pass "§2 --print-public-key before the first start prints the key"
else
    deviation "§2 --print-public-key before the first start fails: $(echo "$out" | tail -1 | cut -c1-160)"
fi
echo '[]' | sudo tee /etc/sokol/peers.json >/dev/null

step "§3 first start"
sudo systemctl enable --now sokol-orchestrator >/dev/null 2>&1
if wait_until 20 up; then pass "§3 the service starts"; else
    fail "§3 the service does not start: $(journalctl -u sokol-orchestrator -n 5 --no-pager | tail -3 | cut -c1-200)"
    exit 1
fi
if ! echo "$out" | grep -q '^mldsa65:'; then
    out=$(sudo -u sokol /usr/local/bin/sokol-orchestrator --key-file /var/lib/sokol/node.key --print-public-key 2>&1)
    echo "$out" | grep -q '^mldsa65:' && pass "§2 after the first start the key prints" || fail "§2 the key does not print even after the first start"
fi
[ "$(stat -c %a /var/lib/sokol/node.key)" = 600 ] && pass "§2 the key file is 0600" || fail "§2 key file mode $(stat -c %a /var/lib/sokol/node.key)"
metric sokol_build_info | grep -q "build=\"$( /usr/local/bin/sokol-orchestrator --version | sed 's/.*build \(.*\))/\1/')\"" \
    && pass "§3 build: $(metric sokol_build_info | grep -o 'build="[^"]*"')" || fail "§3 sokol_build_info: $(metric sokol_build_info)"
if health=$(node_health); then
    pass "§3 all four required node health metrics are 1"
else
    fail "§3 node health unverified or unhealthy: $health"
fi
ip -d link show "$IF" | grep -q 'prog/xdp' && pass "§3 prog/xdp on $IF" || fail "§3 no XDP program on $IF"
[ "$(value sokol_p2p_active_peers)" = 0 ] && pass "§3 peers: 0 (a single node)" || fail "§3 peers $(value sokol_p2p_active_peers)"
ctl LIST_BANS | grep -q '^OK 0' && pass "§3 ctl LIST_BANS: $(ctl LIST_BANS | head -1)" || fail "§3 ctl LIST_BANS: $(ctl LIST_BANS | head -1)"
sudo sokol-monitor --verify /var/lib/sokol/audit.log | grep -q '^OK' && pass "§3 the audit chain verifies" || fail "§3 audit: $(sudo sokol-monitor --verify /var/lib/sokol/audit.log)"
[ "$(value sokol_protected_refresh_ok)" = 1 ] && pass "§3 protected addresses are read" || fail "§3 protected refresh $(value sokol_protected_refresh_ok)"

step "§5.1 a wrong block"
reachable "$SUSPECT" && pass "§5.1 $SUSPECT reaches the node before" || fail "§5.1 $SUSPECT does not reach the node before any block"
printf 'SIGNAL:rehearsal|%s|-|a wrong detection\n' "$SUSPECT" | sudo nc -U -q1 /run/sokol/sokol.sock >/dev/null
wait_until 5 bash -c "! ip netns exec $NS ping -c 1 -W 1 -I $SUSPECT $HOST_IP >/dev/null 2>&1" \
    && pass "§5.1 a detector's signal blocks $SUSPECT" || fail "§5.1 the signal did not block $SUSPECT"
reachable "$REMOTE_IP" && pass "§5.1 other traffic still passes" || fail "§5.1 $REMOTE_IP is cut too"
ctl "UNBAN_IP:$SUSPECT" | grep -q '^OK unbanned' && pass "§5.1 ctl \"UNBAN_IP:$SUSPECT\": $(ctl LIST_BANS | head -1 | cut -c1-40)" || fail "§5.1 UNBAN_IP did not answer OK"
wait_until 5 reachable "$SUSPECT" && pass "§5.1 $SUSPECT passes again" || fail "§5.1 $SUSPECT still blocked after the unban"
wait_until 5 bash -c "sudo sokol-monitor --dump /var/lib/sokol/audit.log | grep -q 'BLOCK_OUTCOME|IP:$SUSPECT|Dropped:'" \
    && pass "§5.1 the audit says what the lifted block did: $(sudo sokol-monitor --dump /var/lib/sokol/audit.log | grep -o "BLOCK_OUTCOME|IP:$SUSPECT|Dropped:[0-9]*|Seconds:[0-9]*" | tail -1)" \
    || fail "§5.1 no BLOCK_OUTCOME for $SUSPECT"

step "§5.4 state not restored at start"
ctl "BAN_IP:$SUSPECT" >/dev/null
sudo systemctl stop sokol-orchestrator
STATE=/var/lib/sokol/audit.log.blocks.json
[ -f "$STATE" ] && pass "§5.4 the state file is $STATE" || fail "§5.4 no state file at $STATE"
echo 'not json' | sudo tee "$STATE" >/dev/null
sudo systemctl start sokol-orchestrator
wait_until 20 up || fail "§5.4 the service does not start with a damaged state file"
journalctl -u sokol-orchestrator -n 100 --no-pager | grep -q 'Restore failed' && pass "§5.4 the journal says: $(journalctl -u sokol-orchestrator -n 100 --no-pager | grep -o 'Restore failed.*' | tail -1 | cut -c1-90)" || fail "§5.4 no 'Restore failed' in the journal"
[ "$(value sokol_state_restore_ok)" = 0 ] && pass "§5.4 sokol_state_restore_ok 0" || fail "§5.4 sokol_state_restore_ok $(value sokol_state_restore_ok)"
ls /var/lib/sokol/ | grep -q 'blocks.json.corrupt' && pass "§5.4 the bytes are kept ($(ls /var/lib/sokol/ | grep corrupt | head -1))" || fail "§5.4 no .corrupt copy kept"
ans=$(ctl ACCEPT_STATE_LOSS)
[ "$ans" = "OK state loss accepted" ] && pass "§5.4 ctl ACCEPT_STATE_LOSS: $ans" || fail "§5.4 ACCEPT_STATE_LOSS answered: $ans"
reachable "$SUSPECT" && pass "§5.4 as documented, the ban in the lost state is gone ($SUSPECT passes)" || fail "§5.4 $SUSPECT blocked although its ban was lost"
ctl "BAN_IP:$SUSPECT" | grep -q '^OK banned' && pass "§5.4 the operator restores the ban by hand" || fail "§5.4 BAN_IP failed"

step "§7 upgrade and rollback"
old=$(value sokol_build_info >/dev/null; metric sokol_build_info | grep -o 'build="[^"]*"')
sudo install -m 0755 "$B/orchestrator" /usr/local/bin/sokol-orchestrator
sudo systemctl restart sokol-orchestrator
wait_until 20 up || fail "§7 the upgraded service does not start"
new=$(metric sokol_build_info | grep -o 'build="[^"]*"')
[ "$new" != "$old" ] && pass "§7 upgrade: $old -> $new" || fail "§7 the build did not change ($new)"
! reachable "$SUSPECT" && pass "§7 the operator ban survives the upgrade" || fail "§7 the ban was lost on upgrade"
sudo install -m 0755 "$A/orchestrator" /usr/local/bin/sokol-orchestrator
sudo systemctl restart sokol-orchestrator
wait_until 20 up || fail "§7 the rolled-back service does not start"
[ "$(metric sokol_build_info | grep -o 'build="[^"]*"')" = "$old" ] && pass "§7 rollback: back to $old" || fail "§7 rollback build $(metric sokol_build_info)"
! reachable "$SUSPECT" && pass "§7 the ban survives the rollback" || fail "§7 the ban was lost on rollback"

step "§8 emergency removal of the filter"
sudo systemctl stop sokol-orchestrator
! ip -d link show "$IF" | grep -q 'prog/xdp' && pass "§8 systemctl stop: prog/xdp is gone from $IF" || fail "§8 XDP still attached after stop"
reachable "$SUSPECT" && pass "§8 traffic runs without the filter" || fail "§8 $SUSPECT still blocked with the service stopped"
sudo systemctl start sokol-orchestrator
wait_until 20 up && ! reachable "$SUSPECT" && pass "§8 the operator ban is back after the next start" || fail "§8 the ban did not come back"

step "support bundle"
cd /tmp
bundle_out=$(sudo CONTROL=/run/sokol/control.sock PEERS=/etc/sokol/peers.json "$REPO/scripts/support-bundle.sh" 2>&1)
bundle=$(ls -t /tmp/sokol-support-*.tar.gz 2>/dev/null | head -1)
if [ -n "$bundle" ]; then
    [ "$(stat -c %a "$bundle")" = 600 ] && pass "support bundle $bundle (0600)" || fail "support bundle mode $(stat -c %a "$bundle")"
    key_hex=$(sudo od -An -tx1 /var/lib/sokol/node.key | tr -d " \n" | cut -c1-32)
    tmp=$(mktemp -d); tar -xzf "$bundle" -C "$tmp"
    if grep -rq "$key_hex" "$tmp" || grep -rqaF "$(sudo head -c 16 /var/lib/sokol/node.key)" "$tmp"; then fail "the bundle contains key bytes"; else pass "the bundle holds no key bytes"; fi
    rm -rf "$tmp"
else
    fail "no support bundle: $(echo "$bundle_out" | tail -2)"
fi

echo
echo "rehearsal: $fails failed, $deviations runbook deviation(s)"
[ $fails = 0 ] && [ $deviations = 0 ]
