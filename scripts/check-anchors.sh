#!/usr/bin/env bash
# xdp-smoke's anchor gate (ADR-0022):
#   scripts/check-anchors.sh <orchestrator> <own audit log> <anchor dir> <node id>
# Passes only if the verifier exits 0 AND its summary shows at least one confirmed statement and
# nothing contradicted or missing.
set -uo pipefail
out=$("$1" --db-path "$2" --node-id "$4" --verify-anchors "$3")
status=$?
printf '%s\n' "$out"
if [ "$status" -ne 0 ]; then
    echo "FAIL verifier exited $status"
    exit 1
fi
grep -Eq '^anchored heads for node [0-9]+: [1-9][0-9]* confirmed, 0 contradicted, 0 missing, ' <<<"$out"
