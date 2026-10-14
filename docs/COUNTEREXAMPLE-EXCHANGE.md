# Portable counterexample exchange — implementation plan and pilot

Status: experimental tooling; no runtime admission or owner acceptance. The five
parts below ship together. Warrant owns record identity, signatures and decision
links; Sokol owns source/witness binding, execution and interpretation.

1. Export one complete tracked source snapshot, its owner-pinned OPERATOR-R1
   context, and a precisely derived defect snapshot in a Warrant evidence pack.
2. A recipient uses its own verifier, signer file and runner to reproduce the
   defect, check the repair and challenge the witness with a semantic mutation.
3. Record proposal and recipient observations as ordinary Warrant records with
   policy/evidence/transcript blobs and `prior` edges. Never invent a new Warrant
   runtime or treat `cmd@v1` as automatically replayed by Warrant verification.
4. Exercise tampering, wrong assertions, incomplete execution, stale inputs,
   budget refusal and isolation with executable negative controls.
5. Project evidence into a compact JSON/Markdown view for a model or specialist:
   exact claim, inputs, method, observations, provenance and unresolved limits.

The specimen uses the existing signed test
`a_command_applied_without_a_reply_has_an_unknown_outcome`. Its node fixture
applies a command and closes without replying. A single replacement makes the
operator report NOT_SENT instead of UNKNOWN. That is a **derived counterfactual**,
not a claim that a historical commit contained these exact bytes. The repaired
snapshot runs all eight OPERATOR-R1 witnesses; the defect must fail on the named
assertion, not compilation or fixture timeout. A restored run must pass again.

## Ownership and applicability

Warrant `SPEC.md` is the format authority. Use the released MIT `warrant-verify`
Rust CLI (pilot tested with 0.9.0), not a copied signing implementation. Recipient
configuration selects the binary by an independently supplied SHA-256. The pack
cannot select a verifier, signing key, trust anchor or executable recipe.

A valid Warrant signature authenticates the record against the stated key; actor
binding requires the recipient's own trust configuration. Demo actors are test
identities, not model identities. A fresh process is independent execution, not
evidence that two independent models reviewed the claim.

`verify` validates Warrant records and automatically re-executes `ski@v1`; it does
not execute these native `cmd@v1` checks. Imported reports remain recorded claims
until the recipient replays them. Novelty is not relevance. All records here are
proposals under an experimental reproduction policy, not settlement or deployment
authority. No owner key is used and no existing witness is edited or re-pinned.

## Execution boundary

The Linux worker requires bubblewrap and a working user systemd manager with
cgroup-v2 memory/PID limits. It refuses when that profile cannot run. Candidate
code sees only read-only source, the selected Rust toolchain, public Cargo
registry dependencies and system libraries, plus bounded scratch filesystems.
No network, home, host control sockets, signing key or verifier binary is mounted.
Compilation and test execution run inside the same isolation. Time, output,
memory, scratch space and process count have separate limits.
Both source variants are mounted read-only throughout compilation and tests;
each observed phase also carries its measured source snapshot. A different source
digest is SOURCE_MISMATCH, even when its output claims the expected result.

This isolates host capabilities; it does not establish arbitrary program truth,
absence of kernel/runtime vulnerabilities, relevance beyond the pinned assertion,
or production NIC behavior. The local runner and OS remain trusted. Cargo
dependencies/toolchain are external inputs whose identities belong in the report.
ASSERTION_RED classifies the named libtest assertion output; it is native test
evidence, not a formal proof of arbitrary source semantics.

Ubuntu 24.04 may restrict unprivileged user namespaces. An administrator can
install a narrow AppArmor profile allowing `userns` for `/usr/bin/bwrap`; do not
disable AppArmor or run the worker as root. See bubblewrap's documented model:
https://github.com/containers/bubblewrap#sandbox-security.

## Completion criteria

An exported pack must be inspectable offline without its producer checkout. A
fresh recipient run must observe the named assertion-red defect and all repaired
witnesses green; a second run produces a separate linked observation. Mutated
inputs, forged reports and tool failures must not become a reproduced result.
The lightweight regression suite and a real Linux isolated rehearsal must pass,
followed by local CI before one PR. Artifacts are retained outside the checkout;
no binary or generated evidence pack is committed.

## Reproduce and exchange

Install the released verifier with `cargo install --locked --version 0.9.0
warrant-verify`. Obtain the binary digest locally; never accept a digest or trust
configuration merely because the producer included it. Fetch the locked Sokol
dependencies before disconnecting the worker (`cargo fetch --locked`).

```sh
# Linux, in a staged Sokol checkout; artifacts and DEMO keys go outside it.
SOKOL_WARRANT_BIN=/absolute/path/to/warrant-rs \
  scripts/rehearse-counterexample-exchange.sh
```

That rehearsal runs the real isolation controls, exports a proposal, records a
recipient observation and then a fresh answer to that observation. It leaves the
two portable packs, raw reports, and JSON/Markdown projections in the printed
temporary directory. Copy `recipient-2/` to another model; do not copy the demo
private keys. An actual model selects its own actor/key and independently pinned
verifier/signers, then invokes `counterexample-task.py replay` with a **new**
output directory. `--respond-to` names an existing observation it is answering.

The registry is a dedicated Cargo home filled for the received lockfile only
(`CARGO_HOME=/absolute/exchange-cargo cargo fetch --locked` in the received source,
then `--registry /absolute/exchange-cargo/registry`). `replay` refuses a registry that
holds any crate the received `Cargo.lock` does not name: a developer's whole registry
would make the recorded digest change with every other project built, often exceed the
input budget, and expose other projects' sources to the candidate code.

```sh
python3 scripts/counterexample-task.py inspect /absolute/received-pack \
  --warrant /absolute/warrant-rs --warrant-sha256 RECIPIENT_SELECTED_SHA256 \
  --signers /absolute/recipient-owner-signers
python3 scripts/counterexample-task.py replay /absolute/received-pack \
  --warrant /absolute/warrant-rs --warrant-sha256 RECIPIENT_SELECTED_SHA256 \
  --signers /absolute/recipient-owner-signers --actor YOUR_ACTOR --key /absolute/YOUR_KEY \
  --toolchain /absolute/rust-toolchain --registry /absolute/public-cargo-registry \
  --output /absolute/new-observation-pack
```

`inspect` and `view` do not compile or execute native checks. `replay` returns 0
for the locally reproduced specimen, 1 for a completed non-reproduction/build
error, and 3 for refusal (unsupported profile, missing isolation, resource/input
failure). The signed reply preserves the actual completed observations; a
refused operation does not pretend to have a test verdict. The JSON view exposes
method/toolchain/registry hashes, budgets, transcript addresses and any recorded
disagreement; at most four observations are projected, with an explicit total
and partial flag. Neither agreement nor disagreement resolves a settlement.
Native check reasons use the worker's actual exit status and exact captured output
blob. A structured resource refusal is recorded as prose plus evidence with no
`cmd@v1` pass/fail claim. Missing/ambiguous output or a contradictory exit is refused.

The runner records the complete selected toolchain and public registry digest,
the four local method files, Warrant binary and kernel. System compiler/libraries
remain host-profile inputs rather than a byte-complete reproducible-build claim.
No artifact binary is admitted into Sokol's live node or sent over its mesh.

Checks: `scripts/test_counterexample_task.py` covers interpretation and hostile
packs against the real released Warrant CLI when `SOKOL_WARRANT_BIN` is set. Both
hosted CI and `local-ci.sh` set it; a bare run explicitly skips that integration.
`scripts/check-counterexample-isolation.py` exercises the actual Linux capability,
memory, deadline and output fences. The longer two-process rehearsal is separate
from normal CI so every push need not compile three isolated snapshots twice.
EXCHANGE-P1 is an unsigned contract proposal; acceptance/re-pin is the owner's act.
