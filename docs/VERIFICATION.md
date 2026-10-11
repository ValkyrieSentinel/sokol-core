# Bounded proofs and executable challenges

`common` keeps Kani harnesses beside its byte parsers under `#[cfg(kani)]`.
The executable inventory is [proof-challenges.json](../scripts/proof-challenges.json): each
entry names a harness, its assertion and a deliberate implementation fault.

```sh
python3 scripts/proof-task.py context
python3 scripts/proof-task.py run
python3 scripts/proof-task.py run --challenge genesis
python3 scripts/proof-task.py verify /tmp/sokol-proof-run-EXAMPLE/report.json --replay
```

Run on Linux with CI's Kani version (currently 0.68.0). The local CI kani step
and CI's required `kani` job run the same calibration. Scope includes its runner, catalog,
input-copy helper and regressions; an unrelated documentation change does not rerun it.

A run proves the complete compiler-discovered harness inventory once, then applies each
fault separately in a hash-checked private copy. The focused command runs only the named
harness and marks its inventory scope accordingly; it never covers the whole catalog. The original implementation must pass its named assertions. Each fault must produce a completed Kani failure **at the named assertion**;
missing harnesses, compile errors, resource exhaustion, unreachable named assertions,
indeterminate checks, unwind failures and unrelated failures cannot substitute for that counterexample.

The output directory contains the unsigned report, Kani JSON, tool versions and logs with
concrete playback candidates when Kani can emit them. CI publishes it as `proof-calibration`. Matching an imported
report establishes input correspondence only: execution stays `UNKNOWN`. `--replay` ignores
imported commands and result claims and runs the local method again. Changed inputs or the
declared configuration yield `STALE`. Generated playback candidates are not executed tests.

To extend a method, add its harness and a catalog challenge, stage them, then run calibration.
A harness without a challenge fails the inventory check; a weakened assertion that no longer
rejects the fault leaves that method uncalibrated. This is sensitivity to the listed faults,
not a proof that the specification or challenge set is complete. The catalog is unsigned;
owner acceptance and invariant signatures remain separate.

Bounds come from the harness itself. The JSON validator covers at most eight bytes from a
ten-character alphabet; audit inputs range over their Rust types. Calibration refuses more
than 16 challenges, ambiguous anchors, patches over 4 KiB, exports/logs over 2 MiB, or more
than 8,192 checks per harness; execution has a total 1,800-second budget. Input-copy bounds
are shared with `contract-task.py`. These limits do not bound compiler disk use or peak RSS;
external tools and omitted environment inputs are not authenticated. Formal coverage of the
orchestrator, XDP logic and native-NIC production behavior remains outside these proofs.

`python3 scripts/test_proof_task.py` checks the report/refusal boundary with controlled JSON.
Real Kani execution is a separate step; matching fixture output is never a native proof.
