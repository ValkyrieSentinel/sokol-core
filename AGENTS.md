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
`cd ebpf && cargo build --release --locked` (bpf-linker, see README). CI runs everything on
x86_64 and arm64 in about 20 minutes, so prefer fewer, complete pull requests over many small
ones.

## Changing code

- Outside tests nothing may panic (crate-level deny: no unwrap/expect/indexing/panic).
- A fix starts with a test that fails **on its assertion** (not on a missing import) on the
  old code. When a test guards a boundary, check it with a mutation that restores the old
  behaviour and say so in the pull request.
- Keep every collection bounded by a named constant; say what happens at the bound.
- A peer speaks only for itself (`p2p.rs` sender binding). This node's own decisions are
  `LocalCommand`, never mesh commands.
- Detector and trap input reaches the node through `delivery::Outbox` in ACK mode: a line is
  delivered when the node answered it, not when it was written.
- Documentation claims only what a named test, metric, flag or path shows;
  `scripts/check-claims.sh` checks that what is cited exists, not that it proves the claim.

## Agent review

Every pull request gets a shadow review by a separate model session
(`.github/workflows/agent-review.yml`, `scripts/agent_review.py`, ported from Stargate). It
reads only the diff and the head export, publishes `sokol/agent-review` on the exact head
(`pass` → success, `hold`/`deny` → failure, anything else → error) and lists its findings in
the run summary. It is not a required check and certifies nothing. Its findings are evidence
for the author and the merger, recorded on the head they were about. It needs the repository
secret `CLAUDE_CODE_OAUTH_TOKEN`.

## Removing things

Removal of a subject from the active surface follows controlled forgetting: a record in
`docs/RETIRED.md` with mode, reason, replacement and loss, bytes under an `archive/<date>` tag,
and `scripts/check-retired.sh` extended. Never retire to make a check pass.
