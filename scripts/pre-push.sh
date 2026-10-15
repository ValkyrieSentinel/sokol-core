#!/usr/bin/env bash
# The checks that turned CI red for a reason a few seconds would have shown (2026-10-12..14:
# an undeclared flag cited in a document, three times; unformatted Rust; a stale gate pin).
# Runs on any machine, including one that cannot build the Linux eBPF workspace.
#   scripts/pre-push.sh                      by hand
#   git config core.hooksPath .githooks      to run it before every push
set -euo pipefail
# A hook runs with GIT_DIR (and, in a linked worktree, more) exported for this repository. The
# regressions below build fixture repositories with git init/commit/tag; with these variables
# inherited they wrote into this repository instead (2026-10-15: core.bare=true, an archive
# tag moved, fixture commits on the checked-out branch). Clear them before anything runs.
# shellcheck disable=SC2046  # the names are single words
unset $(git rev-parse --local-env-vars)
cd "$(dirname "$0")/.."
step() { printf '== %s\n' "$*"; }
step "format"
cargo fmt --all --check
(cd ebpf && cargo fmt --check)
step "cited metrics, flags, ADRs, paths (test names: CI)"
SOKOL_SKIP_TEST_NAMES=1 scripts/check-claims.sh
step "retired surface"
scripts/check-retired.sh
step "owner pins"
python3 -I scripts/witness-pin.py check --every-pin
step "gate and contract regressions"
for t in test_witness_pin test_contract_tool test_check_retired test_gate_provenance test_counterexample_registry; do
    python3 "scripts/$t.py" 2>&1 | tail -1 | grep -qx OK || { echo "FAIL scripts/$t.py"; exit 1; }
done
echo "ok   pre-push checks passed"
