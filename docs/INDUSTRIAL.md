# Industrial candidate: execution plan

Base review: `86bbcf2fcea9b2a4abf4e5ff98e5fe44a86867a7`, 2026-10-15.
Operator authorized implementation of all six packages. This ledger records work;
it is not an acceptance, verification result or deployment permission.

| Package | Deliverable | Completion evidence | State |
|---|---|---|---|
| 1 | Owner-authorized trust transitions; complete merge candidates | PR #54 merged; required checks passed at `591b3ae`; follow-up binds projected Python arguments | MERGED + FOLLOW_UP |
| 2 | One bounded model entry point over existing contract/proof/exchange tools | real IPC-A1 native report: offline UNKNOWN/MATCH; replay REPLAYED_PASS/MATCH | LOCAL_VALIDATION |
| 3 | Complete installable candidate, identity, SBOM/provenance | `e222b10` Linux archive installed without Rust into an empty prefix; hostile archive controls pass; systemd compatibility pending | LOCAL_VALIDATION |
| 4 | Operational status, incident visibility, offline operator, support | four Linux status/worker tests, 70-minute partition promtool fixture, offline JS and bounded collector tests pass; native full suite pending | LOCAL_VALIDATION |
| 5 | Compatibility and long failure campaigns | different-version rollback, current mutation/fuzz evidence, 24h then 72h | PLANNED |
| 6 | Measured CI cost with preserved discrimination | latency/runner-minute baseline and all retained negative controls | PLANNED |

Changes are developed in complete reviewable PR packages. The trusted checker and
signer configuration are owner authority. The first trust bootstrap needs the
owner's signature of the final candidate; agents never impersonate it. Later
provisional additions retain their separate existing key and authority.

Packages 2–4 are combined into one substantial follow-up PR to avoid repeated
owner-signature and hosted-CI cycles. The commits remain separate. A changed
build script and the execution-argument projection need a fresh owner signature
before that PR is eligible; the bootstrap signature is not reused as acceptance.

The offline operator regression needs Node (test-only, never a node runtime
dependency). The local Linux lab uses Ubuntu's Node package; hosted runner tools
are recorded with the run. A missing Node is a failure, not a skipped assertion.

Physical NIC/router qualification, incident responder, accepted SLO/RPO/RTO,
support horizon and public RC acceptance remain explicit decisions/evidence.
VM success does not qualify hardware. A launched long campaign is RUNNING until
it has completed; a tool without a reproduced counterexample is not calibrated.
