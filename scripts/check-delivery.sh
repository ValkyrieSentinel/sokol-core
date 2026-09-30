#!/usr/bin/env bash
# The production outbox is standard-library-only: exercise it without Linux/XDP.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
rustc --edition=2021 --test orchestrator/src/delivery.rs -o "$work/tests"
"$work/tests"
rustc --edition=2021 scripts/stargate_delivery_probe.rs -o "$work/probe"
"$work/probe"
