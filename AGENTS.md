# Working on Sokol-Core as an agent

Read [ARCHITECTURE.md](ARCHITECTURE.md) §3 first: almost every defect found here had one shape,
a decision that read *some* record instead of the established fact. The three rules that follow
from it bind every change:

1. **A fact has an owner and an identity.** A block is a claim with an issuer; only its issuer
   (or the operator) takes it back.
2. **Desired and applied live apart.** Counters and answers report what happened in the kernel
   or upstream, not what was meant to happen.
3. **Unknown is unknown.** A timeout, a lost answer, a failed read or a written-but-unanswered
   line is not success: retry, re-read or report degradation.

## Where things are

- Decisions: [docs/adr/](docs/adr/README.md). Status and what is next: [ROADMAP.md](ROADMAP.md).
- Boundaries with the tests that hold them: [docs/INVARIANTS.md](docs/INVARIANTS.md). A new
  boundary gets a row there naming its test.
- What is tested on what: [docs/SUPPORT.md](docs/SUPPORT.md). Operating a node:
  [docs/RUNBOOK.md](docs/RUNBOOK.md), [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).
- Retired subjects: [docs/RETIRED.md](docs/RETIRED.md). They are not precedent; reading their
  bytes from an archive tag does not re-adopt them.

## Building and testing

Linux only: `aya` does not build for macOS. On a Mac, use a Linux VM (the lab uses Lima with
`vz`, Ubuntu 24.04; `limactl shell <vm>`), install rustup there and clone the repository.

```shell
cargo test --locked --bins -p orchestrator   # unit tests; no eBPF object or bpf-linker needed
cargo test --locked -p common
cargo clippy --locked --all-targets -- -D warnings   # needs the eBPF object (below)
cargo fmt --all -- --check
scripts/check-claims.sh && scripts/check-retired.sh
```

The full `cargo test`, clippy over all targets and the XDP smoke need the eBPF object first:
`cd ebpf && cargo build --release --locked` (bpf-linker, see README).

**Run CI before pushing:** `scripts/local-ci.sh` runs the CI job on this host in the same order,
with the pins and checksums read from `ci.yml` (bpf-linker, GoBGP, cargo-deny), including the
XDP smoke, the demo and the runbook rehearsal (sudo). `--quick` stops after the Python
regressions. The smoke greps log lines and audit records; a changed message is a failed check
there, not in the unit tests. CI runs everything on x86_64 and arm64 in about 20 minutes, so
prefer fewer, complete pull requests over many small ones.

## Changing code

Each rule names what checks it, or says that only review does. `scripts/check-claims.sh` fails
on a rule here that does neither, and on a cited test, path or flag that does not exist.

- Contributions are accepted under [CLA.md](CLA.md): opening a pull request is the agreement.
  `ebpf/` and `common/` are GPL-2.0-or-later, the rest AGPL-3.0-only
  ([COPYRIGHT.md](COPYRIGHT.md)). Name third-party material and its license in the PR.
  *Review only.*
- Outside tests nothing may panic: no unwrap/expect/indexing/panic.
  *Checked by:* the crate-level clippy `deny` in `orchestrator/src/main.rs` and
  `common/src/lib.rs`, in CI's clippy step.
- A fix starts with a test that fails **on its assertion** (not on a missing import) on the
  old code. When a test guards a boundary, check it with a mutation that restores the old
  behaviour and say so in the pull request. *Checked by:* the mutation check of the changed
  lines, `scripts/mutants-diff.sh` (CI job `mutants`, [docs/MUTATION.md](docs/MUTATION.md));
  the red-first order is *review only*.
- Keep every collection bounded by a named constant; say what happens at the bound.
  *Review only.*
- A peer speaks only for itself (`p2p.rs` sender binding). *Checked by:*
  `a_peer_cannot_send_claims_in_another_nodes_name`,
  `a_snapshot_with_claims_of_other_nodes_is_refused`. This node's own decisions are
  `LocalCommand`, never mesh commands. *Checked by:* the type: `LocalCommand` has no
  `Serialize`, so it cannot be put on the wire.
- Detector and trap input reaches the node through `delivery::Outbox` in ACK mode: a line is
  delivered when the node answered it, not when it was written. *Checked by:*
  `unknown_reply_keeps_the_obligation_and_a_later_ack_retires_it` and the Stargate shadow
  contract (`.github/workflows/stargate-shadow.yml`).
- A parser of bytes the node does not control (in `common`) gets a Kani proof as well:
  [docs/VERIFICATION.md](docs/VERIFICATION.md). *Checked by:* CI's `kani` job for the proofs
  that exist; that a new parser has one is *review only*.
- Every mutant of the lines a pull request changes is caught by a test or excluded with its
  reason. *Checked by:* `scripts/mutants-diff.sh` (CI job `mutants`).
- A test of the security core should fail on the mutants of the code it covers;
  [docs/MUTATION.md](docs/MUTATION.md) has the commands, the baseline and the open survivors.
  *Checked by:* the sweep in docs/MUTATION.md, run by hand; *review only* between sweeps.
- Documentation claims only what a named test, metric, flag or path shows. *Checked by:*
  `scripts/check-claims.sh`, which checks that what is cited exists, not that it proves the
  claim.
- A retired subject stays retired. *Checked by:* `scripts/check-retired.sh` (see
  [Removing things](#removing-things)).

## Review

Each pull request is reviewed by an agent before merge, and the review's findings belong in
the pull request (a comment), tied to the head it was about: a review that leaves no record
cannot be checked or reused. Human read-through runs in parallel and may lag; it is not a
merge gate. Required checks are the CI jobs of `protect-main`.

## Removing things

Removal of a subject from the active surface follows controlled forgetting: a record in
`docs/RETIRED.md` with mode, reason, replacement and loss, bytes under an `archive/<date>` tag,
and `scripts/check-retired.sh` extended. Never retire to make a check pass.
