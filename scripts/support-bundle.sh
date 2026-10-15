#!/usr/bin/env bash
# Bounded private collection; no service changes or raw key/state/audit contents.
set -euo pipefail
collector="$(dirname "$0")/support_bundle.py"
if [ ! -f "$collector" ]; then collector=/usr/local/share/sokol/support_bundle.py; fi
exec python3 "$collector"
