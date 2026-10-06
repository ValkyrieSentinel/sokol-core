#!/usr/bin/env bash
# Stamps the node's audit head statements with OpenTimestamps (ADR-0022). The node only writes
# the statements (--anchor-dir); this runs elsewhere, as another user, with network access
# (deploy/sokol-anchor.timer), using the official client:  pip install opentimestamps-client
#
#   scripts/anchor-ots.sh <anchor dir>
#
# Each head-*.txt without a .ots is stamped (its SHA-256 goes to the public calendars, nothing
# else). Every run then tries to upgrade the pending stamps: a stamp is complete once its
# calendar commitment is in a Bitcoin block (hours). `ots verify <file>.ots` checks one.
# Exit 0: every unstamped statement was stamped; 1: a stamp failed; 2: no ots client.
set -uo pipefail
dir=${1:?usage: $0 <anchor dir>}
command -v ots >/dev/null || { echo "ots not found (pip install opentimestamps-client)"; exit 2; }
stamped=0; failed=0
shopt -s nullglob
for statement in "$dir"/head-*.txt; do
    [ -e "$statement.ots" ] && continue
    if ots stamp "$statement"; then
        stamped=$((stamped + 1))
    else
        echo "FAIL  stamping $statement"
        failed=$((failed + 1))
    fi
done
for proof in "$dir"/head-*.txt.ots; do
    ots upgrade "$proof" >/dev/null 2>&1 || true   # still pending is not an error
done
echo "stamped $stamped, failed $failed"
[ "$failed" -eq 0 ]
