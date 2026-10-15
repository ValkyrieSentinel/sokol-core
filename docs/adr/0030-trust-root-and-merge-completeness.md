# ADR-0030. The next base is authorized by the current owner

Status: implementation candidate; bootstrap requires owner acceptance.
Date: 2026-10-15. Extends ADR-0023 and ADR-0028.

The current base verifies a candidate's signatures, but previously did not bind
its signer file. A first merge could add a future owner key under unchanged old
pins; a later merge could use that key. Required PR checks also allowed unsigned
new rows which main's `--every-pin` rejected only after the merge.

`trust_root_v1` in the owner manifest binds exact bytes and executable modes of
the candidate signer file, checker and base workflow. Missing fixture workflows
are recorded as absent; symlinks, non-regular and oversized inputs are refused.
The field is mandatory. Legacy build/closure fields remain frozen for the base
checker which must authorize the bootstrap. Only the owner signs this field;
the provisional manifest cannot authorize a trust transition.

The trusted checker executes outside the candidate using its explicit `--root`
option. It never replaces the future checker before hashing it. The required
base gate demands `--every-pin` on the candidate merge tree. Proposals are still
intent; accepted new rows must carry an owner or provisional signature.

Owner rotation uses overlap: enroll the new key under the old trusted owner's
signature; after that transition is base, remove the old key using a currently
trusted key. New agent-key enrollment precedes rows signed only by that key.
Root rotation is not self-authorization by the proposed key.

The old base cannot enforce a new rule it has never implemented. Its existing
owner pin of `witness-gate.yml` protects this one-time bootstrap. Local and
hosted candidate checks do not replace that owner signature. The ordinary CI
step retains a legacy-checker adapter for this transition; the required future
base workflow has no adapter and only executes its own explicit-root checker.

Verification: `scripts/test_trust_root.py` covers owner/agent injection,
namespace/removal edits, authorized overlapping rotation, candidate checker
replacement, missing/symlink inputs and downgrade of the mandatory field.
`scripts/test_gate_provenance.py` exercises the actual workflow step with a
hostile candidate and isolated standard-library imports. Existing provisional
and promotion controls remain in `scripts/test_contract_tool.py`.
