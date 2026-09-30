# Stargate delivery pilot: registration

Registered before the model, repair or acceptance harness. Base: Sokol-Core
`2e82e1111795114cf99cddac0bfa73205d8b5574`; Stargate `d9fc9aeed9c4417af03813295d7af2a10d525d12`.
Scope: `orchestrator/src/delivery.rs`, one queued detector signal and its acknowledgement.

## Observation before registration

A public-API probe compiled the actual Rust module with rustc, pushed one signal,
and served `OK ack\n` then `OK something else\n` on a Unix socket. `flush(1)` returned
one `Rejected` outcome, pending=0, error=None, lost=0. The node supplied no recognized
terminal acknowledgement. This is a protocol-boundary loss, discovered by code review
and reproduced before modelling, not autonomously discovered by Stargate.

## Contract and predictions

Only a complete, recognized terminal line consumes a queued signal: `OK applied`,
`OK pending`, `OK recorded`, `OK duplicate`, `OK refused <reason>`, or `ERR <reason>`.
Unknown, blank, prefix-lookalike and truncated lines are protocol/transport failures:
retain the signal, close the connection and use the existing retry/backoff path.
A recognized refusal/error remains final. An ACK is not a durability certificate.

A three-state-bit model tracks queued, settled and a world-owned acknowledgement latch;
two event bits distinguish arrival and recognition. Invariant: settlement requires
acknowledgement; the initial obligation is always either queued or settled. Initial
state has one queued signal; terminal goal settles it; live goal means a completion path
remains possible, not that the node must answer. Predictions: current behavior refutes
in one unknown-reply step; fixed behavior certifies; owned-only safety synthesis either
finds a verified repair or reports its actual boundary, never changes the ack latch.

The Rust socket harness will exercise the actual module, not a reimplementation. Its
observations will be compared to the certified projection. Controls: consume any reply,
accept an ERR prefix-lookalike, accept EOF without newline, and lose a signal on transport
error. Each must fail the corresponding contract check. No XDP or deployment is needed.

## Measurement boundaries and decision

This is a cross-language, cross-repository engineering pilot. The initiating operator
has direct influence here: independent demand, external maintainer acceptance and
production qualification are NOT established. Queue overflow, restart persistence,
multiple signals, backoff timing, authentication, kernel effects and delivery liveness
under arbitrary failures are outside this three-bit proof; concrete regressions may
cover some separately. Record every failed or inconclusive check; do not relabel a
compiler/environment failure a defect or a successful model a code proof.

Acceptance: native regressions pass, the fixed model certifies, the original observable
loss is rejected, correspondence checks and all registered mutation controls discriminate.
The pilot runs offline/shadow in CI and adds no runtime dependency or blocking authority.
Results go in a separate RESULTS.md; this registration is retained unchanged after runs.
