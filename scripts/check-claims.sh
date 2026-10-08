#!/usr/bin/env bash
# What the documents cite as evidence or as an instruction must exist: a test named in an ADR's
# "Перевірка", a metric in the runbook, a command-line flag, an ADR number, a file path. A test
# renamed or removed leaves its claim standing with no evidence behind it; this makes that fail.
# Finding nothing to check fails too: an empty scope is not a pass.
set -euo pipefail
cd "$(dirname "$0")/.."
DOCS=(README.md ARCHITECTURE.md ROADMAP.md AGENTS.md docs/*.md docs/adr/*.md docs/measurements/*/README.md)
EXTERNAL_FLAGS='--locked --bin --bins --in-diff --release --quick'  # flags of other tools (cargo, scripts/local-ci.sh) the docs mention
fail=0; n_tests=0; n_metrics=0; n_flags=0; n_adrs=0; n_paths=0
bad() { echo "FAIL $*"; fail=1; }
# shellcheck disable=SC2207  # paths in this tree have no spaces
SRC=($(git ls-files 'orchestrator/src/*.rs'))

metrics=$(grep -oE '"sokol_[a-z0-9_]+' orchestrator/src/metrics.rs | tr -d '"' | sort -u)
# Flags: fields of the clap Parser structs (not of any struct), plus the ones parsed by hand.
flags=$({ awk '/derive\(.*Parser/ {p = 1; next} p && /^}/ {p = 0} p && match($0, /^ +(pub )?[a-z][a-z0-9_]*:/) {
              f = substr($0, RSTART, RLENGTH); sub(/^ +(pub )?/, "", f); sub(/:$/, "", f); gsub(/_/, "-", f); print "--" f
          }' "${SRC[@]}"
          grep -rhoE '"--[a-z][a-z0-9-]+' orchestrator/src | tr -d '"'
          echo --help   # clap adds it; --version only where the command declares a version
          grep -lq 'version = ' "${SRC[@]}" && echo --version; } | sort -u)

# Code spans only: prose may use any words.
# shellcheck disable=SC2016  # the backticks are literal
spans=$(grep -ohE '`[^`]+`' "${DOCS[@]}" | tr -d '`')

# Metrics: any sokol_* name inside a code span (with labels or in an expression), not a path.
for m in $(echo "$spans" | grep -oE '(^|[^/a-z0-9_])sokol_[a-z0-9_]+' | grep -oE 'sokol_[a-z0-9_]+' | sort -u); do
    n_metrics=$((n_metrics + 1))
    case "$m" in
        *_) echo "$metrics" | grep -q "^$m" || bad "metric family $m* is cited but none is exported" ;;
        *) echo "$metrics" | grep -qx "$m" || bad "metric $m is cited but not exported" ;;
    esac
done
# Tests: a whole code span that is a long snake_case name.
for id in $(echo "$spans" | grep -oxE '[a-z][a-z0-9]*(_[a-z0-9]+){3,}' | grep -v '^sokol_' | sort -u); do
    n_tests=$((n_tests + 1))
    git grep -h -B4 -w "fn $id" -- '*.rs' | grep -qE '#\[(tokio::)?test' \
        || bad "test $id is cited but no #[test] fn has that name"
done
# Kani proofs: a code span `<module>::proofs::<name>` (docs/VERIFICATION.md).
for id in $(echo "$spans" | grep -oxE '[a-z_]+::proofs::[a-z0-9_]+' | sed 's/.*:://' | sort -u); do
    n_tests=$((n_tests + 1))
    git grep -h -B4 -w "fn $id" -- '*.rs' | grep -qF '#[kani::proof]' \
        || bad "proof $id is cited but no #[kani::proof] fn has that name"
done
for f in $(echo "$spans" | grep -oE '(^| )--[a-z][a-z0-9-]+' | tr -d ' ' | sort -u); do
    n_flags=$((n_flags + 1))
    echo "$flags" | grep -qx -- "$f" || echo "$EXTERNAL_FLAGS" | grep -qw -- "$f" || bad "flag $f is cited but no binary declares it"
done
for a in $(grep -ohE 'ADR-0[0-9]{3}' "${DOCS[@]}" | sort -u); do
    n_adrs=$((n_adrs + 1))
    ls docs/adr/"${a#ADR-}"-*.md >/dev/null 2>&1 || bad "$a is cited but docs/adr has no such record"
done
# AGENTS.md: every rule under "Changing code" names what checks it, or says only review does.
# The checker's exit status decides, not only its lines: a checker that cannot run (a lost
# executable bit, a broken interpreter) fails this check too (review of #168).
rules_status=0
rules_out=$("${AGENTS_RULES_CHECK:-scripts/check-agents-rules.sh}" AGENTS.md 2>&1) || rules_status=$?
if [ "$rules_status" != 0 ]; then
    [ -n "$rules_out" ] || bad "the AGENTS.md rule check exited $rules_status without output"
    while IFS= read -r line; do
        [ -n "$line" ] && bad "${line#FAIL }"
    done <<<"$rules_out"
fi
# docs/RETIRED.md names retired paths on purpose (scripts/check-retired.sh checks it).
# shellcheck disable=SC2016
live_spans=$(for d in "${DOCS[@]}"; do [ "$d" = docs/RETIRED.md ] || grep -ohE '`[^`]+`' "$d"; done | tr -d '`')
for p in $(echo "$live_spans" | grep -oxE '(bench|scripts|deploy|demo|docs|common|orchestrator|ebpf|ai)/[A-Za-z0-9_./-]+' | sed 's/:[0-9]*$//' | sort -u); do
    n_paths=$((n_paths + 1))
    [ -e "$p" ] || bad "path $p is cited but does not exist"
done

total=$((n_tests + n_metrics + n_flags + n_adrs + n_paths))
[ "$total" -gt 0 ] || { echo "FAIL nothing cited was found: the check has nothing to check"; exit 1; }
[ $fail = 0 ] && echo "ok   $n_tests tests, $n_metrics metrics, $n_flags flags, $n_adrs ADRs, $n_paths paths cited, all exist"
exit $fail
