# Candidate delivery

`deploy/candidate.json` is the product inventory, including monitor, adapters, the
systemd unit, support collector, licenses and operator instructions. An absent
required file refuses packaging. CI's `candidate-<sha>-<arch>` artifact is separate
from its potentially partial diagnostic build artifact.

The producer builds in a clean committed checkout with locked dependencies, then:

    python3 scripts/candidate.py build --binaries target/release --output /tmp/candidate.tar.gz

The producer needs Rust. Consumers need Python only. Supply the archive SHA256
from an independently authenticated channel; the archive cannot choose trust.
The consumer commands are `candidate.py verify ARCHIVE`, `install ARCHIVE` and
`remove ARCHIVE`, each with a required expected SHA256 argument. Install/remove
also accept a prefix for a disposable host filesystem rehearsal. They never
start/stop services, touch node state/keys or create a configuration. Create the
user/groups, configure and start as described in RUNBOOK, using package binaries.
Stop the service before changing installed files. File replacement is per-file,
not a crash-atomic package transaction; after an interrupted install inspect and
reapply the selected candidate (or previous candidate) before starting. Removal
refuses locally modified files before removing any product file.

The archive contains a bounded manifest, SHA256SUMS, a Cargo build-graph SPDX 2.3
inventory and an unsigned builder-input record. The latter is not a provenance
signature; the graph is not symbol-level binary dependency measurement. The
producer refuses an orchestrator build ID that differs from its clean commit.
Incremental identity tracks source inputs and actual Git files, including worktrees.
Identity text alone does not authenticate a binary or prove complete build closure.

On main, a separate credentialed job attests the candidate digest's build origin
and SBOM using GitHub OIDC after the native suites and Kani. It neither executes
candidate bytes nor grants release/deployment authority. Consumers authenticate
attestations against the intended repository and workflow identity using GitHub's
attestation verifier; offline expected-digest verification only establishes integrity.
Documentation: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations .

All candidates remain NOT_ADMITTED / NOT_QUALIFIED. Native NIC, actual router,
support commitments and public RC acceptance remain separate. Installation is
not activation or admission. Keep the previously authenticated candidate archive
and matching state/key backup for rollback; a label-only rehearsal is not a
different-version compatibility test.

Limits: 128 MiB compressed and total file bytes, 512 regular files, 64 MiB per
payload, 1 MiB per metadata file. Decompression is bounded before parsing tar
extension headers. Symlinks, hardlinks, device entries, duplicate/unsafe paths,
unknown installation prefixes, changed digests/modes and platform mismatch are
refused. Installation targets must be trusted root-owned directories; concurrent
replacement of their parents by another privileged process is outside this tool.
Consumers do not execute archive recipes. Failure during installation can leave
partial file changes; it never implies the running node changed successfully.

Checks: `scripts/test_candidate.py`, `scripts/test_build_identity.py`; real
Linux package-only installation and systemd rehearsal remain distinct executions.
