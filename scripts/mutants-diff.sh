#!/usr/bin/env bash
# Mutants of the changed code only (docs/MUTATION.md): every mutant cargo-mutants makes in the
# lines this change touches must be caught by a test, or excluded in .cargo/mutants.toml with
# the reason it is equivalent. Used by CI's mutants job and by scripts/local-ci.sh.
#
#   scripts/mutants-diff.sh <base commit>
#   MUTANTS_SHARD=k/n scripts/mutants-diff.sh <base>   only shard k of n (CI runs four in parallel)
#
# The working tree is compared with the base (an uncommitted change counts; a new file must be
# tracked). A timeout counts as caught: the suite did not pass. Fails on any missed mutant, and
# on anything cargo-mutants itself could not do (a failing baseline, a usage error).
set -euo pipefail
cd "$(dirname "$0")/.."
base=${1:?usage: mutants-diff.sh <base commit>}
out=${MUTANTS_OUT:-target/mutants-diff}
jobs=${MUTANTS_JOBS:-2}
shard=()
[ -n "${MUTANTS_SHARD:-}" ] && shard=(--shard "$MUTANTS_SHARD")
rm -rf "$out"
mkdir -p "$out"
git diff "$base" -- orchestrator common >"$out/change.diff"

run() {   # run <package> <extra cargo arg>...
    local package=$1 status=0
    shift
    cargo mutants -j "$jobs" --in-diff "$out/change.diff" -p "$package" \
        --cargo-arg=--locked ${shard[@]+"${shard[@]}"} "$@" -o "$out/$package" || status=$?
    # 4: the unmutated baseline failed. Wall-clock tests can fail on a loaded runner (a test
    # failing under a mutant only counts it caught, so only the baseline needs this): one
    # more run, then the failure stands. A missed mutant is never retried.
    if [ "$status" = 4 ]; then
        echo "the baseline failed; running once more"
        status=0
        cargo mutants -j "$jobs" --in-diff "$out/change.diff" -p "$package" \
            --cargo-arg=--locked ${shard[@]+"${shard[@]}"} "$@" -o "$out/$package" || status=$?
    fi
    # 0: all caught; 2: some missed; 3: some timed out. Anything else is not a verdict.
    case $status in
        0 | 2 | 3) ;;
        *) echo "FAIL cargo mutants for $package exited $status (baseline or usage)"; exit 1 ;;
    esac
}
# The node: --bins keeps the build away from the targets that embed the eBPF object.
run orchestrator --cargo-arg=--bins
run common

missed=$(cat "$out"/*/mutants.out/missed.txt 2>/dev/null || true)
if [ -n "$missed" ]; then
    echo "FAIL mutants of the changed code that no test catches:"
    printf '%s\n' "$missed" | sed 's/^/    /'
    echo "Each needs a test that fails on it, or, if it is equivalent, an exclusion with its"
    echo "reason in .cargo/mutants.toml (check its boundary value; docs/MUTATION.md)."
    exit 1
fi
echo "ok   every mutant of the changed code is caught (or excluded with a reason)"
