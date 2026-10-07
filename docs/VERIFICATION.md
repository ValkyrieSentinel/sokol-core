# Bounded proofs (Kani)

Tests check the inputs someone thought of; [mutation testing](MUTATION.md) checks that the
tests notice changes. [Kani](https://github.com/model-checking/kani) checks a property for
**every** value of a function's inputs, up to a stated bound: no panic, no arithmetic overflow,
no read out of bounds, and the assertions of the proof. The crate lints forbid `unwrap`,
indexing and panics outside tests, but not overflow; release builds wrap on overflow silently.

The proofs live beside the code under `#[cfg(kani)]` and cover the parsers of `common` that
read bytes the node does not control.

| Proof | Input | Property |
|---|---|---|
| `audit_log::proofs::a_record_header_never_admits_more_than_max_payload` | all 2^192 record headers | a parsed header admits at most `MAX_PAYLOAD` bytes, so the reader never allocates more than `MAX_PAYLOAD + CHAIN_LEN` for a record from a damaged or crafted file; it is exactly the header the writer would encode |
| `audit_log::proofs::an_encoded_header_parses_back` | every length up to `MAX_PAYLOAD`, every seq and time | the writer's header parses back to what it wrote |
| `audit_log::proofs::advancing_never_wraps` | every seq, offset and length up to `MAX_PAYLOAD` | reader and writer advance by one sequence number and exactly the record's bytes, or refuse; never a wrapped value |
| `canonical::proofs::the_strict_validator_returns_on_every_short_input` | every string of up to 8 bytes over `{ } [ ] " : , \ ␠ a` | the strict JSON validator returns without panic, overflow or out-of-bounds read, and accepts only a braced object |

**What found something.** Preparing `advancing_never_wraps` showed that a segment header naming
sequence `u64::MAX`, followed by one valid record (the chain is unkeyed, so whoever can write the
file can make one), overflowed the reader's next sequence: a panic in debug and test builds, a
silent wrap to 0 in release. The writer had the same edge. Both now refuse the record
(`a_record_at_the_last_sequence_number_is_refused_not_overflowed`,
`a_log_at_the_last_sequence_number_refuses_to_append`).

**Bounds.** The validator proof is bounded: 8 bytes over an alphabet of 10 (every structure of
object, string, escape, nesting and separator, but not every byte value). A longer input or
other bytes are covered by its tests and proptests, not by this proof. The audit proofs have no
bound beyond the types.

**Each proof fails on a broken function** (checked by hand, 2026-10-07): without the
`MAX_PAYLOAD` check (`assertion failed: len <= MAX_PAYLOAD`), with a wrapping `advance`, and with
a validator that accepts any framing.

## Running

Linux, like the unit tests ([AGENTS.md](../AGENTS.md)); the version is the one CI pins
(`KANI_VERSION` in `.github/workflows/ci.yml`):

```shell
cargo +stable install --locked kani-verifier --version 0.68.0
cargo +stable kani setup
cargo kani -p common                      # or: scripts/local-ci.sh --step kani
cargo kani -p common --harness advancing_never_wraps
```

About 10 minutes on 10 cores, most of it the validator proof. CI runs them in the `kani` job,
beside the main one. A proof that runs out of memory reports `VERIFICATION:- FAILED` with "CBMC
appears to have run out of memory": that is not a counterexample; narrow the input.

## Not covered

The node crate (`orchestrator`: block table, mesh envelope, IPC) and the XDP program. The
eBPF verifier checks the XDP program's memory safety when it loads; the node's logic is covered
by tests, the [invariants ledger](INVARIANTS.md) and mutation testing.
