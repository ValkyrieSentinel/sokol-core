# Agent pilot: IPC-A1 and preservation of the checking boundary

Status: local implementation, not a merged policy or a production qualification.

The first task packet is read-only context for IPC-A1. It derives the actual row and
witness names from INVARIANTS and the owner manifest; it reads only a fixed list of
repository files. It records current HEAD and current bytes separately, so an uncommitted
change is not misrepresented as committed source. A matching cursor saves transport
only after fresh reads. Signature validity and native result remain unchecked/UNKNOWN.

```
python3 scripts/outbox-task.py --budget 8192
python3 scripts/test_outbox_task.py
scripts/check-delivery.sh
```

The packet lists the editable owner, preserved witnesses, explicit verification commands,
unknowns and stopping boundaries. Obtaining context never runs these commands. The two
Git rev-parse calls are read-only queries; this interface is not a zero-subprocess interface.
IPC ACK is not durable storage or completed kernel enforcement.

Next: use this packet to reproduce one actual IPC-A1 defect or strengthen a discriminating
test. Absence of a defect is not a reason to rewrite the implementation. Further contract
packets and a generated component map follow only after this pilot is useful.

## PR #1 review: AMEND at f08ce526d5ab5a7d3af3acaf9d5767094e8605c8

Base: 083d3f439e854a38b4251fefd8850be85bba2cf9. All reported GitHub checks succeeded;
the PR had no recorded agent review. CI alone did not establish the normalization claim.

Four concrete regressions fail on assertions against the exact PR checker:

- A Rust literal changes from `"http://x"` to `"http:// x"` and check still exits 0.
- A Python literal changes from `"a b"` to `"a  b"` and check still exits 0.
- A raw Rust literal changes whitespace and check still exits 0.
- A Rust literal containing `}` prematurely ends body extraction; removing the following
  assertion leaves the witness hash unchanged.

The local repair keeps literals out of whitespace normalization and masks literal braces
before extracting Rust bodies. Python token text preserves literals and indentation
structure without ast.unparse. Seventeen fixture tests pass, including the four new
regressions; the original head fails all four. This remains a source checker, not a full
Rust parser, macro expansion proof or helper-closure verifier.

The corrected hashing changes existing witness hashes. The owner manifest and its
signature have NOT been rewritten. The existing root check must now refuse until the
owner explicitly reviews and re-pins the tree under ADR-0023. Do not merge this PR using
the earlier green result. A new head needs fresh CI and review after re-pinning.

Signing action, for the owner after review:

```
python3 scripts/witness-pin.py sign --key <owner-private-key>
python3 scripts/witness-pin.py check
```

Authorship: Codex AI assistant prepared the local repair and pilot after operator
authorization. No independent review, new owner signature or merge is claimed.
