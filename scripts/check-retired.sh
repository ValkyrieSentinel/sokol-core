#!/usr/bin/env bash
# Controlled forgetting, checked (docs/RETIRED.md): every review finding ID still cited in the
# repository is decoded there, no live file points at a retired path, and the archive tag that
# holds the retired bytes exists. Finding no ID at all fails: an empty scope is not a pass.
set -euo pipefail
cd "$(dirname "$0")/.."
LEDGER=docs/RETIRED.md
TAGS=(archive/2026-09-29 archive/2026-10-05 archive/2026-10-12)
RETIRED_PATHS='docs/reviews/|docs/vision/|experiments/chromatic-boundaries|sokol-client|(^|[^A-Za-z0-9_])ai/|STRATEGY_REVIEW_2026-10-03|ci-protection-proposal|CONTRACT-SHADOW-PILOT|AGENT-PILOT|STATE-AND-PLAN'
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
# Retired files, one table row each (docs/RETIRED.md, 2026-10-12 on): the exact subject is gone
# from the tree, its bytes are at the tag with the recorded digest (I1), its loss is named (I4),
# and its replacement exists. A table that lists nothing fails: an empty scope is not a pass.
# CI checks out one commit: fetch the tag that holds the bytes if this clone lacks it.
git rev-parse -q --verify "refs/tags/archive/2026-10-12^{commit}" >/dev/null ||
    git fetch -q --depth=1 origin "refs/tags/archive/2026-10-12:refs/tags/archive/2026-10-12" 2>/dev/null || true
rows=$(awk '/<!-- retired-files:/ {p = 1; next} p && /^\| `/ {print; next} p && !/^\|/ {p = 0}' "$LEDGER")
[ -n "$rows" ] || { echo "FAIL $LEDGER has no retired-files rows"; fail=1; }
while IFS='|' read -r _ path mode digest replacement loss _; do
    path=$(echo "$path" | tr -d '` '); mode=$(echo "$mode" | tr -d ' '); digest=$(echo "$digest" | tr -d ' ')
    replacement=$(echo "$replacement" | sed 's/^ *//; s/ *$//'); loss=$(echo "$loss" | sed 's/^ *//; s/ *$//')
    case "$mode" in SUPERSEDED|WITHDRAWN|REFUTED|ARCHIVED) ;; *) echo "FAIL $path: mode $mode"; fail=1 ;; esac
    [ ! -e "$path" ] || { echo "FAIL $path is retired but still in the tree"; fail=1; }
    got=$( (git show "archive/2026-10-12:$path" 2>/dev/null || true) | shasum -a 256 | cut -c1-64)
    [ "$got" = "$digest" ] || { echo "FAIL $path: bytes at archive/2026-10-12 are not $digest"; fail=1; }
    [ -n "$loss" ] && [ "$loss" != "—" ] || { echo "FAIL $path: a retirement names what is lost"; fail=1; }
    case "$replacement" in
        —) [ "$mode" != SUPERSEDED ] || { echo "FAIL $path: SUPERSEDED names its replacement"; fail=1; } ;;
        ADR-*) ls docs/adr/"${replacement#ADR-}"-*.md >/dev/null 2>&1 || { echo "FAIL $path: $replacement does not exist"; fail=1; } ;;
        *) [ -e "$replacement" ] || { echo "FAIL $path: replacement $replacement does not exist"; fail=1; } ;;
    esac
done <<<"$rows"
[ $fail = 0 ] && echo "ok   $(echo "$rows" | wc -l | tr -d ' ') retired files: absent, digests match at archive/2026-10-12, losses named"
exit $fail
