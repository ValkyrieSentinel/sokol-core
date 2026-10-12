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
# A label value an alert selects on is a name too: renamed in the exporter, the selector matches
# nothing and the alert never fires, while promtool's rule tests (synthetic series) stay green.
# Each value (each part of a =~ alternation) must be a string literal in the code that renders
# the labels, outside its tests. `instance`, `job` and dashboard variables are Prometheus' own.
label_src=$(for f in orchestrator/src/metrics.rs orchestrator/src/detections.rs orchestrator/src/p2p.rs \
    orchestrator/src/block_table.rs common/src/lib.rs; do sed '/^#\[cfg(test)\]/q' "$f"; done)
values=$(grep -ohE 'sokol_[a-z0-9_]+\{[^}]*\}' deploy/prometheus/sokol-alerts.yml deploy/grafana/sokol-dashboard.json \
    | grep -oE '[a-z_]+=~?\\?"[^"\\]*' | grep -vE '^(instance|job)=' | grep -v '\$' \
    | sed -E 's/^[a-z_]+=~?\\?"//' | tr '|' '\n' | sort -u)
[ -n "$values" ] || { echo "FAIL no label value found in the rules: the scan is broken"; exit 1; }
nvalues=0
for v in $values; do
    nvalues=$((nvalues + 1))
    grep -qE "(\"|\\\\\")${v}(\\\\\"|\")" <<<"$label_src" || { echo "FAIL label value \"$v\" is selected but not rendered"; fail=1; }
done
[ $fail = 0 ] && echo "ok   $(echo "$used" | wc -l | tr -d ' ') metric names and $nvalues label values in the rules and the dashboard, all exported"
exit $fail
