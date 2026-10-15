#!/usr/bin/env bash
# The changed-line mutation job needs no compiler/tool install when its inputs are unchanged.
# Unknown comparison or an untracked input always mutates. Native tests remain independent.
set -uo pipefail
cd "$(dirname "$0")/.."
base=${1:?usage: mutants-scope.sh BASE}
inputs=(orchestrator/ common/ Cargo.toml Cargo.lock rust-toolchain rust-toolchain.toml .cargo/
        scripts/mutants-diff.sh scripts/mutants-scope.sh scripts/test_mutants_diff.py
        scripts/test_mutants_scope.py)
untracked=$(git ls-files --others --exclude-standard -- "${inputs[@]}" 2>/dev/null) || untracked=error
if git diff --quiet "$base" -- "${inputs[@]}" 2>/dev/null && [ -z "$untracked" ]; then
    echo skip
else
    echo mutate
fi
