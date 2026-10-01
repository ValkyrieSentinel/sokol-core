# Delivery acknowledgement pilot: results

Registered in `STARGATE-REGISTRY.md` at `a5ee3df`, before implementation. Baseline
`2e82e1111795114cf99cddac0bfa73205d8b5574`; final repaired Rust and socket probe `a0614ba`.

## Actual Rust behavior

Before: one signal, ACK handshake, then `OK something else\n` → pending=0, one Rejected
outcome, error=None, lost=0. EOF after `OK applied` without a newline also consumed the
signal. The old parser classified unknown replies as final errors.

After: only complete recognized terminal replies consume a signal. Unknown, malformed,
prefix-lookalike and truncated replies preserve it and use reconnect/backoff. Explicit
node refusal/error remains final. Two new regression tests fail on the original source
and pass on the repair (compiled with rustc, not inferred from a model).

`./scripts/check-delivery.sh` runs eight production-module tests and eighteen real Unix
socket cases without Cargo, Linux or XDP. It covers unknown → retry → `OK duplicate`,
no-newline EOF, down-node recovery and bounded-queue loss accounting. An unknown response
may keep retrying until recovery or the existing bounded queue evicts the item; this is
not a promise of eventual delivery, exactly-once effects or durable ACKs.

## Stargate shadow result

Three bits (`ack`, `queued`, `settled`), two event bits (`known`, `reply`), immutable world
rule `ack`. Current model refuted; declared repair certified. One-edit exhausts after 11
candidates. Safety synthesis returns a checked owned-only repair: four winning states,
one changed row, Hamming delta 2, both queued/settled rules change. It agrees with the
declared repair on all transitions from its two reachable states, but differs on five
of 32 full-domain rows. Minimal-Hamming is not a globally best implementation claim.

Eighteen actual Rust observations match the certified projection. Four semantic mutants
are rejected: consume unknown replies; accept ERR prefix-lookalikes; accept incomplete
lines; pop on transport failure. Build errors do not count as detected mutants.

The pinned Stargate harness and model are run by `.github/workflows/stargate-shadow.yml`.
It is an additional shadow CI job, not a runtime dependency or a required deployment gate.
Its stdout records exact source hashes. Ordinary Rust regressions also detect the defect;
the model adds exhaustive bounded closure and independently checked repair evidence.

## Boundaries

The operator influences both repositories. Independent demand and external maintainer
acceptance are unmeasured. Model/code equivalence, arbitrary byte streams or interleavings,
queue overflow proofs, restart durability, XDP/native NIC qualification and production
adoption are not established. This change does not alter the scope of ACK durability in
ADR-0004 or the deployment decisions in ROADMAP.md. Review, merge and release are separate
from these local results.

## Pre-merge correction and CI environment

Reviewing `main.rs` after the first run found five valid ADR-0019 retraction ACKs missing
from the strict parser. `STARGATE-AMENDMENT.md` records the extension; `a0614ba` recognizes
those exact strings, exercises real RETRACT messages and adds the eighth native test.
Stargate retains the first thirteen-case measurement and records the final eighteen-case
run in `results-v2.json`. This is not a new model or checker.

The first Linux CI stopped before XDP smoke when apt fetched a removed libevent package
(HTTP 404 on both architectures). The workflow now refreshes its package indexes before
installing smoke dependencies; no failed infrastructure run is counted as validation.

Historical pin for the run above: Stargate `1ae672f830979e2848e3ae426a2cdddc3c0b28b3`.

## Current CI integration — 2026-10-01

`.github/workflows/stargate-shadow.yml` pins the harness to Stargate
`d512620994fd1f063b2a2c68f8ce137bf9fe714f`. In addition to the delivery, trace,
queue and local receipt checks, it runs `sokol_intents.py` against the candidate's
actual delivery source. Six local socket/process-exit cases cover retained budgets,
receipt-first recovery, incomplete verification, a false ACK and cancellation.
This uses a toy SQLite receiver; production node admission and distributed restart
durability remain outside the claim.

Frozen reproduction uses Sokol `5ffaf0854158f4674a470378279a4dd4d237f9fb`.
Its `orchestrator/src/delivery.rs` SHA-256 is
`4becf82d8db9194d48be14d14684e3ea9ffd8ff598bc68205553a1327d4b7f0f`, matching
the retained-intent report. The new harness reads only that file from the Sokol
checkout; its other dependencies come from the pinned Stargate checkout. CI compares
all bytes of `examples/sokol-intents/results.json`, including component digests,
alongside the three existing frozen reports. The older receipt report remains a
historical observation and is not added to this frozen comparison.
