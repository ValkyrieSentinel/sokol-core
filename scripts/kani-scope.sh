#!/usr/bin/env bash
# Whether the Kani proofs (docs/VERIFICATION.md) can come out differently than at BASE: prints
# `prove` or `skip`. Used by CI's kani job and by scripts/local-ci.sh, so both decide alike.
#
#   scripts/kani-scope.sh <base commit>
#
# The inputs are everything `cargo kani -p common` reads: the crate, the workspace manifest
# (Kani takes its own configuration from [workspace.metadata.kani]), the lock file, the
# toolchain and cargo configuration, the CI file that pins Kani, and this list. The working
# tree is compared, so an uncommitted or untracked change counts. Anything git cannot compare
# proves.
set -uo pipefail
cd "$(dirname "$0")/.."
base=${1:?usage: kani-scope.sh <base commit>}
INPUTS=(
    common/
    Cargo.toml
    Cargo.lock
    rust-toolchain.toml
    rust-toolchain
    .cargo/config.toml
    .cargo/config
    .github/workflows/ci.yml
    scripts/kani-scope.sh
)
# A new file that is not tracked yet (a fresh .cargo/config.toml) is not in `git diff`.
untracked=$(git ls-files --others --exclude-standard -- "${INPUTS[@]}" 2>/dev/null) || untracked=error
if git diff --quiet "$base" -- "${INPUTS[@]}" 2>/dev/null && [ -z "$untracked" ]; then
    echo skip
else
    echo prove
fi
