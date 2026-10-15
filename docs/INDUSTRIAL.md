# Industrial candidate: execution plan

Base review: `86bbcf2fcea9b2a4abf4e5ff98e5fe44a86867a7`, 2026-10-15.
Operator authorized implementation of all six packages. This ledger records work;
it is not an acceptance, verification result or deployment permission.

| Package | Deliverable | Completion evidence | State |
|---|---|---|---|
| 1 | Owner-authorized trust transitions; complete merge candidates | delayed-key injection refused, overlapping rotation admitted, strict base gate | IN_PROGRESS |
| 2 | One bounded model entry point over existing contract/proof/exchange tools | fresh context, native replay and negative control, independent trust selection | PLANNED |
| 3 | Complete installable candidate, identity, SBOM/provenance | clean-host install from archive, package-only rehearsal, digest/absence refusals | PLANNED |
| 4 | Operational status, incident visibility, offline operator, support | persistent partition, worker failure, offline UI, privacy/budget controls | PLANNED |
| 5 | Compatibility and long failure campaigns | different-version rollback, current mutation/fuzz evidence, 24h then 72h | PLANNED |
| 6 | Measured CI cost with preserved discrimination | latency/runner-minute baseline and all retained negative controls | PLANNED |

Changes are developed in complete reviewable PR packages. The trusted checker and
signer configuration are owner authority. The first trust bootstrap needs the
owner's signature of the final candidate; agents never impersonate it. Later
provisional additions retain their separate existing key and authority.

Physical NIC/router qualification, incident responder, accepted SLO/RPO/RTO,
support horizon and public RC acceptance remain explicit decisions/evidence.
VM success does not qualify hardware. A launched long campaign is RUNNING until
it has completed; a tool without a reproduced counterexample is not calibrated.
