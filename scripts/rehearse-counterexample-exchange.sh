#!/usr/bin/env bash
# Two fresh executions and distinct DEMO actors; not two independent model reviews.
set -euo pipefail
cd "$(dirname "$0")/.."
binary=${SOKOL_WARRANT_BIN:?set SOKOL_WARRANT_BIN to the recipient-selected warrant-rs}
output=${1:-$(mktemp -d /tmp/sokol-exchange-rehearsal.XXXXXXXX)}
mkdir -p "$output"
output=$(cd "$output" && pwd)
verifier_hash=$(sha256sum "$binary" | cut -d' ' -f1)
toolchain=$(dirname "$(dirname "$(rustup which rustc)")")
registry=${CARGO_HOME:-$HOME/.cargo}/registry
"$binary" keygen --out "$output/demo-author.key" >"$output/author-public-key.txt"
"$binary" keygen --out "$output/demo-recipient.key" >"$output/recipient-public-key.txt"
common=(--warrant "$binary" --warrant-sha256 "$verifier_hash")
python3 scripts/counterexample-task.py export "$output/proposal" "${common[@]}" \
    --actor demo-author-NOT-A-MODEL-IDENTITY --key "$output/demo-author.key" >"$output/export.json"
python3 scripts/check-counterexample-isolation.py >"$output/isolation.txt"
python3 scripts/counterexample-task.py replay "$output/proposal" "${common[@]}" \
    --output "$output/recipient-1" --toolchain "$toolchain" --registry "$registry" \
    --actor demo-recipient-NOT-A-MODEL-IDENTITY --key "$output/demo-recipient.key" >"$output/replay-1.json"
observation=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["observation"])' "$output/replay-1.json")
python3 scripts/counterexample-task.py replay "$output/recipient-1" "${common[@]}" \
    --respond-to "$observation" --output "$output/recipient-2" --toolchain "$toolchain" --registry "$registry" \
    --actor demo-author-NOT-A-MODEL-IDENTITY --key "$output/demo-author.key" >"$output/replay-2.json"
python3 scripts/counterexample-task.py view "$output/recipient-2" "${common[@]}" >"$output/view.json"
python3 scripts/counterexample-task.py view "$output/recipient-2" "${common[@]}" --markdown >"$output/view.md"
python3 - "$output" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
for name in ('replay-1.json', 'replay-2.json'):
    report = json.loads((p / name).read_text())
    assert report['status'] == 'REPRODUCED', report
    assert report['execution'] == 'FRESH_LOCAL_RUN', report
view = json.loads((p / 'view.json').read_text())
assert view['observations_total'] == 2 and not view['projection_partial'], view
assert all(r['execution'] == 'RECORDED_NOT_REPLAYED' for r in view['observations']), view
assert view['comparison'] == 'RECORDED_AGREEMENT_NOT_SETTLEMENT', view
print('PASS: two fresh processes, linked observations, recorded-only projection')
print('Artifacts:', p)
PY
# Demo secret keys remain local, outside both portable packs.
