#!/usr/bin/env bash
# Controlled forgetting, checked (docs/RETIRED.md): every review finding ID still cited in the
# repository is decoded there, no live file points at a retired path, and the archive tag that
# holds the retired bytes exists. Finding no ID at all fails: an empty scope is not a pass.
set -euo pipefail
cd "$(dirname "$0")/.."
LEDGER=docs/RETIRED.md
TAGS=(archive/2026-09-29 archive/2026-10-05)
RETIRED_PATHS='docs/reviews/|docs/vision/|experiments/chromatic-boundaries|sokol-client|(^|[^A-Za-z0-9_])ai/|STRATEGY_REVIEW_2026-10-03|ci-protection-proposal'
fail=0

cited=$(git grep -hoEw 'F(0[1-9]|1[0-2])|R2[67]-0[1-9]|N0[1-6]|T[1-5]' -- . ":!$LEDGER" | sort -u)
[ -n "$cited" ] || { echo "FAIL no finding ID found: the check has nothing to check"; exit 1; }
for id in $cited; do
    grep -q "^| $id |" "$LEDGER" || { echo "FAIL $id is cited but not decoded in $LEDGER"; fail=1; }
done
echo "ok   $(echo "$cited" | wc -w | tr -d ' ') cited finding IDs, all decoded in $LEDGER"

if refs=$(git grep -nE "$RETIRED_PATHS" -- . ":!$LEDGER" ":!scripts/check-retired.sh"); then
    echo "FAIL live files point at retired paths:"; echo "$refs"; fail=1
else
    echo "ok   no live file points at a retired path"
fi

for TAG in "${TAGS[@]}"; do
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || git ls-remote --exit-code --tags origin "$TAG" >/dev/null 2>&1; then
        echo "ok   $TAG exists"
    else
        echo "FAIL tag $TAG, which holds the retired bytes, is missing"; fail=1
    fi
done
exit $fail
