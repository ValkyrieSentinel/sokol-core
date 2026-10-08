#!/usr/bin/env bash
# Every rule under "## Changing code" in AGENTS.md (or the given file) names what checks it
# ("Checked by:") or says that only review does ("Review only"). Prints one FAIL line per rule
# that does neither; exits 1 if there is one, or if the section has no rules.
#
#   scripts/check-agents-rules.sh [file]
#
# A rule starts at any top-level list item (-, *, +, 1. or 1)) and at any other unindented
# line after the first item, so the marker of one rule never covers the next (review of #168).
set -euo pipefail
cd "$(dirname "$0")/.."
file=${1:-AGENTS.md}
rules=$(awk '
    /^## Changing code/ { p = 1; next }
    /^## / { p = 0 }
    !p { next }
    /^([-*+]|[0-9]+[.)])[ \t]/ || (started && /^[^ \t]/) {
        if (rule != "") print rule
        rule = $0; started = 1; next
    }
    started && NF { sub(/^[ \t]+/, ""); rule = rule " " $0 }
    END { if (rule != "") print rule }
' "$file")
[ -n "$rules" ] || { echo "FAIL $file has no rules under Changing code"; exit 1; }
fail=0
while IFS= read -r rule; do
    case "$rule" in
        *"Checked by:"* | *"Review only"* | *"review only"*) ;;
        *) echo "FAIL $file rule names no check and is not marked review only: ${rule:0:70}"; fail=1 ;;
    esac
done <<<"$rules"
exit $fail
