# One contract, three views: IPC-A1

IPC-A1's editable source is `docs/contracts/IPC-A1.shadow.json`. Its statement and named
witnesses retain the existing owner pin (ADR-0023); explanatory annotations remain unsigned.
No signing key is read and no signature is created. The other 31 rows keep their current
Markdown sources.

Run `python3 scripts/contract-shadow.py` (option --signers selects a trusted signer file).
It prints a new temporary directory with `IPC-A1.md` for a human, `IPC-A1.agent.json` for
an agent and the complete `INVARIANTS.md` with IPC-A1 rendered from JSON. To refresh the
checked-in materialization after an authorized contract change, copy that generated
INVARIANTS.md back. Do not edit its generated row by hand.

The checked-in row is a marked generated copy, kept so the gate from the current base branch
can still read its existing signed statement and witnesses. The updated gate discovers any docs/contracts/<ID>.shadow.json source, validates its ID,
marker and unique row, and requires its materialization to match. Missing sources/markers,
filename aliases, duplicate rows and stale materializations fail. It contains no IPC-A1
identity or path special case. Discovery stops at 256 contracts; files are limited to 2 MiB.
It has not become a second editable source. Removing the checked-in row altogether requires
a later staged migration of the trusted base gate and downstream Markdown consumers.

The renderer verifies the owner signature before trusting manifest digests. By default the
signer file comes from the local checkout; this is key-relative verification, not independent
authority discovery. Automation should supply its trusted base signer file explicitly.
The packet records the signers' digest and provenance. Coordinated substitution of the
contract and manifest without a valid owner signature is refused.

The gate exposes `rust_witness_hashes(source, relative_path, names)` as a pure public API,
`contract_row` and `project_invariants` as projection APIs, and `verify_manifest` for explicit
manifest/signature/signer paths. The renderer uses these without rewriting gate globals.
The normalizer and all existing signed witness hashes stay unchanged.

Inputs are bounded and hashed; changed inputs during projection are refused. The packet is
bounded to 16384 bytes with deterministic identity for the same inputs and signer provenance.
Only signature verification executes externally; generation never runs native tests or
contract-provided recipes. Signature status remains separate from execution UNKNOWN,
annotation acceptance NOT_ESTABLISHED and semantic adequacy NOT_ESTABLISHED. Scope, policy
reference and agent task are unsigned annotations, not an extension of signature coverage.

IPC-A1's evidence cell says “overflow test above”. Preserve that text and expose the unresolved
cross-row coverage instead of silently promoting extra witnesses into IPC-A1.

Verification: `python3 scripts/test_contract_shadow.py` covers assertion-level witness
mutation, statement drift, witness removal, coordinated unsigned manifest replacement,
stale display regeneration/gate refusal, annotation promotion, packet identity, symlink
refusal and the signature-only subprocess boundary. It runs in CI and local-ci alongside
`python3 scripts/test_witness_pin.py` and `python3 scripts/test_outbox_task.py`.
`python3 scripts/witness-pin.py check` verifies the full owner pin independently.
Native execution receipts remain a separate next step, not a status inferred from generation.

This stays intentionally limited to IPC-A1. A general contract schema, signed annotation
coverage and migration of every invariant require a separate owner decision.

## Delivery and CI cost

The contracts/generated-projection branch starts at merged PR #1 (b16d5c5). The scoped-policy
planning commit remains on ci/scoped-policy-pilot and is excluded from this branch. Test
registrations in ci.yml/local-ci.sh and the Outbox packet source hash are part of this contract
change. Prepare one complete PR and one remote CI run after the required local checks.

A local comparison using the actual b16d5c5 gate confirmed all 32 row identities and 72
witness identities remain unchanged and the old gate accepts the existing owner signature.
The signature authenticates manifest bytes, not the merge commit SHA, so this migration
does not require a new owner signature. This is compatibility evidence, not a claim that
GitHub CI has already run for this branch.
