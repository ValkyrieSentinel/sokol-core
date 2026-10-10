#!/usr/bin/env bash
# The alert rules and the dashboard name metrics by string; a renamed metric would silently turn
# an alert into one that never fires. Every sokol_* name they use must be exported by the node
# (orchestrator/src/metrics.rs). Finding no name at all fails.
set -euo pipefail
cd "$(dirname "$0")/.."
exported=$(grep -oE '"sokol_[a-z0-9_]+' orchestrator/src/metrics.rs | tr -d '"' | sort -u)
used=$(grep -ohE 'sokol_[a-z0-9_]+' deploy/prometheus/sokol-alerts.yml deploy/grafana/sokol-dashboard.json \
    | grep -vE '^sokol_(core|dashboard)$' | sort -u)
[ -n "$used" ] || { echo "FAIL no sokol_* metric found in the rules or the dashboard"; exit 1; }
fail=0
for m in $used; do
    # A regex alternation like sokol_(a|b) is checked by its parts below.
    grep -qx "$m" <<<"$exported" || { echo "FAIL $m is used but not exported"; fail=1; }
done
for part in $(grep -ohE 'sokol_\([a-z_|]+\)' deploy/prometheus/sokol-alerts.yml deploy/grafana/sokol-dashboard.json | sed 's/sokol_(\(.*\))/\1/' | tr '|' ' '); do
    grep -qx "sokol_$part" <<<"$exported" || { echo "FAIL sokol_$part (in a regex) is not exported"; fail=1; }
done
[ $fail = 0 ] && echo "ok   $(echo "$used" | wc -l | tr -d ' ') metric names in the rules and the dashboard, all exported"
exit $fail
