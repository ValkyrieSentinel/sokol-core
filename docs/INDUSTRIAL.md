# Industrial candidate: execution plan

Base review: `86bbcf2fcea9b2a4abf4e5ff98e5fe44a86867a7`, 2026-10-15.
Operator authorized implementation of all six packages. This ledger records work;
it is not an acceptance, verification result or deployment permission.

| Package | Deliverable | Completion evidence | State |
|---|---|---|---|
| 1 | Owner-authorized trust transitions; complete merge candidates | PR #54 merged; required checks passed at `591b3ae`; follow-up binds projected Python arguments | MERGED + FOLLOW_UP |
| 2 | One bounded model entry point over existing contract/proof/exchange tools | real IPC-A1 native report: offline UNKNOWN/MATCH; replay REPLAYED_PASS/MATCH | LOCAL_VALIDATION |
| 3 | Complete installable candidate, identity, SBOM/provenance | package-only install; real `e222b10 -> 6585af6 -> e222b10` systemd/veth rehearsal, 0 failures/deviations; hosted provenance pending | LOCAL_VALIDATION |
| 4 | Operational status, incident visibility, offline operator, support | native workspace + Clippy; persistent-partition promtool negative control, offline JS and bounded collector controls | LOCAL_VALIDATION |
| 5 | Compatibility and long failure campaigns | actual different-source rollback; all 15 changed-line mutants accounted for; two calibrated native fuzz targets; full-crate sweep and 24h/72h campaigns pending | IN_PROGRESS |
| 6 | Measured CI cost with preserved discrimination | one-run baseline and fail-closed mutation input selector; hosted after-change measurement pending | IN_PROGRESS |

Changes are developed in complete reviewable PR packages. The trusted checker and
signer configuration are owner authority. The first trust bootstrap needs the
owner's signature of the final candidate; agents never impersonate it. Later
provisional additions retain their separate existing key and authority.

Packages 2–6 implementations are combined into one substantial follow-up PR to avoid repeated
owner-signature and hosted-CI cycles. The commits remain separate. A changed
build script and the execution-argument projection need a fresh owner signature
before that PR is eligible; the bootstrap signature is not reused as acceptance.

The offline operator regression needs Node (test-only, never a node runtime
dependency). The local Linux lab uses Ubuntu's Node package; hosted runner tools
are recorded with the run. A missing Node is a failure, not a skipped assertion.

The unsigned [local evidence ledger](industrial/local-evidence-2026-10-15.json)
separates immutable source, dirty verifier changes, actual executions and limits.
The hosted baseline used 3,138 job-seconds (52.3 minutes), including 347 seconds
across four mutation shards. This is one run, not p95 latency or billed minutes.
`scripts/mutants-scope.sh` skips only unchanged mutation/build inputs, before tool
installation; unknown Git comparison or new untracked inputs run mutations.
Native tests, required checks, Kani scope and the base witness gate remain intact.
`scripts/test_mutants_scope.py` exercises real Git staged/untracked states and
unknown-base refusal. Actual savings require a new hosted measurement.

On a disposable systemd VM, `scripts/campaign.py --binary ABSOLUTE_BINARY
--monitor ABSOLUTE_MONITOR --output NEW_DIRECTORY` launches 24h and then 72h,
only if the first phase passes. Invoke with root. Keep the committed source
checkout frozen for the entire experiment and put binaries/output outside
`/tmp` and `/var/tmp`, which PrivateTmp hides. The unit has 4 GiB memory, 4 GiB
temporary storage, 256 tasks, 200% CPU, 128 MiB per file and a 96.5h wall limit.
These limits change the measured environment. The seeded event trace records
choices, not a deterministic OS schedule. Existing soak assertions check active
count convergence, audits and unexpected exits; RSS growth has no accepted SLO.
LIMITED_PASS is an experiment result, not production admission. A hard unit kill
may leave RUNNING in the receipt: read the named unit's result with systemctl,
inspect namespace leftovers, and retain that uncertainty rather than declaring
success. The launcher refuses a physical host or container. Do not run other
mesh experiments concurrently; the bench's lock and preflight enforce ownership.

Responder, SLO/RPO/RTO, support horizon and the RC admission rule: ADR-0031 (the owner is
responsible; models review it per RC). Physical NIC/router qualification and an admitted RC
remain evidence still to produce.
VM success does not qualify hardware. A launched long campaign is RUNNING until
it has completed; a tool without a reproduced counterexample is not calibrated.
