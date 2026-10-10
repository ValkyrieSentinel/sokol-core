#!/usr/bin/env bash
# xdp-smoke's audit witness gate (ADR-0021):
#   scripts/check-witnesses.sh <orchestrator> <own audit log> <peer audit log> <node id>
# Passes only if the verifier exits 0 AND its summary shows at least one confirmed witness and
# nothing contradicted or missing. A valid-looking summary from a failed process is a failure.
set -uo pipefail
out=$("$1" --db-path "$2" --node-id "$4" --verify-witnesses "$3")
status=$?
printf '%s\n' "$out"
if [ "$status" -ne 0 ]; then
    echo "FAIL verifier exited $status"
    exit 1
fi
grep -Eq '^witnesses for node [0-9]+: [1-9][0-9]* confirmed, 0 contradicted, 0 missing, ' <<<"$out"
