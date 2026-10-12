# Signed witnesses: letting agents change code while the owner pins what it must keep

**Status:** working paper, 2026-10-12. Every number below is reproducible from this repository
at the commit that contains this file; the commands are in §8. Code spans in this text (test
names, metrics, flags, paths, ADR numbers) are checked by `scripts/check-claims.sh` in CI, so a
renamed test or a removed path turns this paper red.

## 1. The problem

Most of the code in this repository is now written by AI agents. They are fast, and they are
judged by CI. A green check is the wrong judge for one specific reason: the cheapest way for an
agent to make a red test green is often to make the test say less. A comment that explained
why the code is the way it is goes stale the same way. Neither leaves a trace that a reader can
check.

The question this paper answers is narrow: **can a repository let agents change anything, and
still guarantee that a stated set of properties holds unless its owner, personally, accepts a
weaker one?** Not "is the code correct", and not "did a human review it".

## 2. The mechanism

Five pieces, each in this repository:

1. **Invariant rows instead of comments.** `docs/INVARIANTS.md` is a table of properties, each
   with the tests that witness it. No row is written by hand: each is generated from
   `docs/contracts/<ID>.shadow.json` (ADR-0024), which also keeps the row's decision history:
   why it was introduced or changed, as a counterexample, a measurement or a requirement.
2. **Owner-pinned witnesses** (ADR-0023). `docs/witness-manifest.json` pins, for every row,
   its statement, its witnesses and a normalized hash of each witness. The owner signs the
   manifest with an SSH key (`ssh-keygen -Y sign`, namespace `sokol-witness`) that agents do not
   hold. A change to a pinned statement, a dropped witness or a changed witness body is refused
   until the owner signs again. Comments and formatting do not count; any other byte does.
3. **Closures and execution.** A witness is pinned together with its attributes and every
   test-only item it reaches by name (helpers, constants, `impl`s, the module that compiles
   it, Python import-time code), and the build configuration that decides how tests run
   (Cargo targets, `.cargo/config`, `build.rs`). CI must also show that every pinned witness
   ran and passed (`--executed`).
4. **A gate the change cannot edit.** The check runs from the base branch, not from the
   change: `.github/workflows/witness-gate.yml` runs on `pull_request_target`, its untrusted
   job builds and tests the change and hands over logs only, and its trusted job checks the
   change's tree and those logs with `main`'s checker and signers, executing nothing of the
   change. `witness-gate (base)` is a required check of the protected branch.
5. **Change through proposals.** `scripts/contract.py propose` records an unsigned intent with
   its reason; `accept` applies it only if the contract is still the one it was
   made against, appends the decision, regenerates the table, and is completed by the owner's
   signature. On `main` nothing may stand unpinned (`--every-pin`).

The result is a ledger: for each property, what it says, which tests carry it, and the dated
reasons it changed. The ADRs record design decisions; the contracts record the accepted
boundaries those decisions produced.

## 3. The method that fed it: counterexample rounds

The gate guards what is pinned; something has to find what should be. Six rounds of
counterexample hunting were run over two days by agents (several in parallel, each in its own
clone in a lab VM), with fixed rules:

- a finding names the contract sentence it violates; without one it is a *candidate*;
- it comes with a test that fails **on its assertion** on the current code (a compile error or
  a panic in setup proves nothing);
- the fix is red-first, then every mutant of the changed lines must be caught
  (`scripts/mutants-diff.sh`, cargo-mutants on the diff; an exclusion needs a written reason in
  `.cargo/mutants.toml`);
- twins are searched for in the whole tree after each fix;
- a new boundary becomes a proposal; it binds only after the owner accepts and signs it.

The owner's role is exactly the last step plus decisions between options a round surfaces
(for example ADR-0025 per-peer quotas, ADR-0017 clock steps, ADR-0027 peer address binding).

## 4. Results

Starting point: a fork of a working XDP/eBPF enforcement node with a signed peer mesh, at
commit `083d3f4` (2026-10-10). End point: `bfdbb8b` (2026-10-12), 28 pull requests later.

| | start (`083d3f4`) | end (`bfdbb8b`) |
|---|---|---|
| invariant rows (all generated from contracts) | 32 (hand-written) | 65 |
| pinned witnesses | 0 | 207 |
| recorded decisions in contracts | 0 | 51 |
| test functions in the Rust tree | 445 | 577 |
| Kani proof harnesses | 4 | 19 |
| ADRs | 22 | 27 |
| mutation exclusions, each with a reason | 15 | 27 |

Rows by round (each step is a merge on `main`; row counts read from `docs/INVARIANTS.md`):

| Round | Area | Real defects | Rows after |
|---|---|---|---|
| 1 | replay, shutdown with audit, delivery outbox | 4 | 32 |
| 2 | Suricata adapter, block table, CrowdSec, freshness | 2 | 33 |
| 3 | state store, FlowSpec, mesh quotas, IPC replies | 9 | 41 |
| 4 | storm mode, kernel ABI, clock steps, detections | 5 | 49 |
| 5 | mesh transport, observability, replay and leases | 10, then 4 candidates (#25–#27) | 57 → 65 |
| 6 | the gate itself (§5) | 4 in the gate | — |

Among the product defects:

- a block lifted by a "shortened" claim;
- a claim born already retracted;
- an IPC reply answering another request;
- an audit head that was not durable;
- one peer able to fill the shared claim memory;
- payload bytes of earlier packets leaking through the kernel ring buffer;
- a storm mode that kept itself going on legitimate traffic;
- a pinned peer able to relay another node's handshake and take its traffic (ADR-0027).

Each is closed by a test that failed on its assertion before the fix; the rows name them.

Two side effects matter as much as the defects:

- **Mutation testing of the diff found more than 30 places where a new test was weaker than
  its name.** The repair was always a sharper witness or an exclusion with a reason; this is
  where "a green check whose label is wider than its predicate" was caught most often.
- **The gate got faster, not slower.** A quadratic Rust tokenizer was replaced by a linear one
  with byte-identical output on every source file and 20,000 random fragments; the check went
  from 8–16 s to 0.6 s for 186 witnesses with closures.

## 5. Attacking the gate

Round 6 attacked the mechanism of §2 instead of the product. Findings, all reproduced, all now
closed:

1. **The base checker had never run.** CI was meant to take the checker and the signers from
   the base commit. The checkout was one commit deep, so the base was never there and the
   step silently used the change's own checker and signers — from the first pull request on.
   A change re-signed with its own key passed. Found by a hunter reading a CI log, not by
   reading the workflow. Now the step fetches the base and fails if it cannot
   (`scripts/test_gate_provenance.py` runs the step body in a depth-1 clone).
2. **A pinned body is not a pinned witness.** `#[ignore]` above a witness, a helper the
   witness calls (`frame_of` sending an empty frame), an alias `use helper as h`, an inner
   `#![cfg(any())]` of the enclosing module, `#[cfg(not(test))]` on `mod x;`, a module-level
   `setattr` replacing a Python witness: each left the gate saying "ok". Hence closures,
   build pins and execution evidence (§2.3). ADR-0023 had listed "helpers are not pinned" and
   "whether a witness runs is the test step's job" as boundaries; together they made a pinned
   row whose evidence no longer ran.
3. **A row can be hidden.** The real row moved into an HTML comment, a weaker look-alike
   (`|MESH-A1|`, or a non-breaking hyphen) left in the table: the gate saw the real row and
   said "ok". Now a row in a comment or code block, and a table line naming an ID that is not
   a row, are refused.
4. **The change runs its own CI.** On `pull_request` the change's own workflow runs, so it can
   remove the gate step. Hence the base workflow (§2.4). A live probe (pull request #24,
   closed unmerged) removed the gate step and its provenance test from its own workflow,
   weakened a pinned witness and added a job impersonating the gate's check name. Every
   pre-existing required check went green; the real `witness-gate (base)` failed, naming the
   witness; the impersonator passed; GitHub kept the merge `BLOCKED`.

## 6. Where the author was wrong

The agent that wrote most of this (Claude) made mistakes that the process caught late, and
they belong in the result:

- It stated for two days that CI ran the base checker, without reading a CI log (§5.1).
- It twice cited a new gate flag in documentation without declaring it, and the claims check
  went red each time.
- It recommended signing a handshake's recipient and nonce against the relay attack of round
  5, and only then saw that a live two-way relay defeats it; the owner chose address binding
  instead (ADR-0027).
- Its repeated failure mode: fixing where the reviewer pointed and leaving the twin; the rule
  "search the whole tree after a fix" was added to its working notes after it recurred.

None of these reached a release; each was found by a test, a hunter or a log. That is the
claim of this paper in small: the mechanism does not make the author reliable; it makes the
author's mistakes cheap to find and expensive to hide.

## 7. Limits

- **What a signature means.** It attests that someone with the owner's key accepted the
  pinned bytes. A key without a passphrase on a machine where agents run would hold nothing.
- **Reach by name, not by the compiler.** A helper reached through a name-building macro, or
  through a trait implemented in another file without a module path, is outside the closure;
  only execution covers it. Python closures do not follow `from <local module> import`.
- **Not pinned:** the Rust toolchain file, prose outside the table, annotations of contracts.
- **The required check is matched by name.** The probe showed an impersonating job does not
  unblock a merge while the real check fails; it did not show what happens if the real check
  is absent, which the workflow being on `main` is meant to prevent.
- **Scale.** One repository, one owner, two days, agents of one family. The numbers are a
  record of this run, not a rate to expect.
- **Not a correctness claim.** A pinned witness can be weak in a way no mutant shows; the
  Kani proofs cover 19 properties of `common`, the rest is tests.

## 8. Reproducing

```
git clone https://github.com/s0fractal/sokol-core && cd sokol-core
python3 scripts/witness-pin.py check            # rows, witnesses, closures, contracts
python3 scripts/witness-pin.py closure an_authenticated_connection_survives_a_replayed_frame
python3 scripts/test_witness_pin.py             # the gate's own regressions
python3 scripts/test_gate_provenance.py         # §5.1
python3 scripts/test_contract_tool.py           # §5.3 and the proposal path
python3 scripts/contract.py list                # open proposals (none at bfdbb8b)
```

Row and witness counts per merge: walk the first-parent history of `main` and, for each commit, count the
rows of `docs/INVARIANTS.md` and the keys of `witnesses` in `docs/witness-manifest.json`.
The decision history of a row is in its contract, e.g. `docs/contracts/MESH-A2.shadow.json`.
Pull requests #1–#28 of `s0fractal/sokol-core` carry the reviews, CI runs and the probe.
