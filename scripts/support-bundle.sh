#!/usr/bin/env bash
# Collects what is needed to diagnose a node into one archive, for someone who is not at the
# machine. Never includes the node key or the raw state/audit files (only their verification).
#
#   sudo scripts/support-bundle.sh                     # systemd layout (deploy/)
#   CONTROL=/run/sokol/control.sock METRICS=http://127.0.0.1:9469/metrics \
#   AUDIT=/var/lib/sokol/audit.log PEERS=/etc/sokol/peers.json BIN=/usr/local/bin/sokol-orchestrator \
#   MONITOR=/usr/local/bin/sokol-monitor OUT=/tmp scripts/support-bundle.sh
set -u
CONTROL=${CONTROL:-/run/sokol/control.sock}
METRICS=${METRICS:-http://127.0.0.1:9469/metrics}
AUDIT=${AUDIT:-/var/lib/sokol/audit.log}
PEERS=${PEERS:-/etc/sokol/peers.json}
BIN=${BIN:-/usr/local/bin/sokol-orchestrator}
MONITOR=${MONITOR:-/usr/local/bin/sokol-monitor}
UNIT=${UNIT:-sokol-orchestrator}
OUT=${OUT:-.}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
dir=$(mktemp -d)/sokol-support-$stamp
mkdir -p "$dir"
umask 077
run() {   # run <file> <command...>: output and exit status, never failing the bundle
    local file=$1; shift
    { echo "\$ $*"; "$@" 2>&1; echo "[exit $?]"; } >"$dir/$file" 2>&1 || true
}

run system.txt bash -c 'date -u; uname -a; cat /etc/os-release 2>/dev/null; nproc; free -m 2>/dev/null'
run version.txt "$BIN" --version
run binary.txt bash -c "sha256sum '$BIN' 2>/dev/null || shasum -a 256 '$BIN'"
if command -v systemctl >/dev/null; then
    run systemd.txt systemctl status --no-pager "$UNIT"
    run journal.txt journalctl -u "$UNIT" --no-pager -n 3000
fi
run metrics.txt curl -s --max-time 5 "$METRICS"
run bans.txt bash -c "printf 'LIST_BANS\n' | nc -U -q1 '$CONTROL'"
run audit-verify.txt "$MONITOR" --verify "$AUDIT"
run links.txt ip -d link show
if command -v bpftool >/dev/null; then
    run bpf.txt bash -c 'bpftool prog show; bpftool map show'
fi
# The peers file holds public keys only; the bundle keeps just who is pinned.
run peers.txt python3 -c '
import json, sys
for e in json.load(open(sys.argv[1])):
    keys = ([e["public_key"]] if e.get("public_key") else []) + e.get("public_keys", [])
    print(e.get("node_id"), [k.split(":")[0] if ":" in k else "legacy" for k in keys], e.get("envelope", ""))
' "$PEERS"

archive="$OUT/sokol-support-$stamp.tar.gz"
tar -czf "$archive" -C "$(dirname "$dir")" "$(basename "$dir")"
chmod 600 "$archive"
rm -rf "$(dirname "$dir")"
echo "$archive"
