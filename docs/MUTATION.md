# Mutation testing

A green suite shows that the code does what the tests ask. A surviving mutant shows a change
of the code that no test notices. Survivors in the security core are read one by one: either a
test is missing (write it, and check that it fails on that mutant), or the mutant is
equivalent (exclude it in [`.cargo/mutants.toml`](../.cargo/mutants.toml), with the reason).

## Running

Linux only, like the unit tests (see [AGENTS.md](../AGENTS.md)). `cargo-mutants` 27.1:

```shell
cargo install --locked cargo-mutants
# The node: --bins keeps the build away from the targets that embed the eBPF object.
cargo mutants -j 3 --cargo-arg=--locked --cargo-arg=--bins -p orchestrator \
  -f orchestrator/src/block_table.rs -f orchestrator/src/p2p.rs \
  -f orchestrator/src/mesh_dispatch.rs -f orchestrator/src/replay.rs \
  -f orchestrator/src/audit_witness.rs -f orchestrator/src/audit_anchor.rs
# common (no --bins: it has none)
cargo mutants -j 3 --cargo-arg=--locked -p common
# After adding tests: only the mutants that survived last time.
cargo mutants --iterate ...same arguments...
```

The node set takes about two hours on 10 cores (each mutant rebuilds and runs about 450 unit
tests); `common` about six minutes. `delivery.rs` is compiled into the adapters with
`#[path]`, which cargo-mutants does not follow; its mutants are the Stargate shadow contract's
(`.github/workflows/stargate-shadow.yml`).

A timeout counts as caught: the suite did not pass. A test that only times out is still a slow
way to fail, so a bound is checked inside the loop that could break it
(`repeated_detections_of_one_target_keep_a_handful_of_claims`).

## Every pull request: the mutants of the change

CI's `mutants` check runs `scripts/mutants-diff.sh <base>`: cargo-mutants on the lines the pull
request changes (`--in-diff`), in `orchestrator` (unit tests, `--bins`) and `common`, split into
four shards on four runners (`MUTANTS_SHARD=k/4`, cargo-mutants `--shard`); the check passes
only if every shard does. Every such
mutant must be caught, or excluded in `.cargo/mutants.toml` with the reason it is equivalent —
checked with its boundary value, not argued (two exclusions were wrong that way). A timeout
counts as caught; a failing baseline fails the job after one more run (a wall-clock test
can fail on a loaded runner; a missed mutant is never retried). Known wall-clock test still to
move to virtual time: `successful_no_effect_rounds_wait_despite_overdue_ticks` (a 0.5 s margin
between a resumed round and a restarted pause). `scripts/local-ci.sh` runs the same check
against `origin/main` (its step `mutants` runs it alone). The whole-module sweep below is still
how the code that was there before is measured.

## Baseline 2026-10-07

First sweep, before the tests it led to:

| | mutants | caught | timeout | unviable | missed |
|---|---|---|---|---|---|
| node (six files above) | 990 | 706 | 15 | 65 | 204 |
| `common` | 481 | 383 | 19 | 14 | 65 |

After the tests below and the exclusions (the node in iterate mode: only the 219 survivors
and the mutants of new code; `common` in full):

| | mutants | caught | timeout | unviable | missed |
|---|---|---|---|---|---|
| node, iterated | 264 | 111 | 4 | 15 | 134 |
| `common` | 321 | 259 | 8 | 14 | 40 |

Seven of those survivors were closed after that run, each checked against its mutant by hand
(`Claim::live_at` is test-only now; strike-order compaction; the live audit file's tail; two
more exclusions). `1 << 0` and `1 >> 0` in `config_flags` are both 1.

What the survivors showed and the tests that now kill them:

- A peer's claim outside its envelope was labelled `Held("envelope")`, and nothing checked
  that it was not enforced: a mutant enforced it under that label. The IPv6 envelope bound had
  no test (`an_out_of_envelope_claim_is_never_enforced_for_either_family`).
- Observe mode keeps own claims off the mesh (ADR-0018); nothing checked a peer receives none
  (`own_detections_reach_peers_only_when_the_node_shares_them`).
- Audit anchor (ADR-0022): one write in flight, `--anchor-secs` pacing, `MISSING` and the exit
  codes of `--verify-anchors`; witnesses (ADR-0021): exit codes of `--verify-witnesses`. The
  verdict counting was copied into both and untested in both; it is one `Summary::count` now.
- Replay (ADR-0016) did not test that an operator flush is replayed
  (`an_operator_flush_between_decisions_is_replayed`).
- `p2p::check_canonical` reads the top level only, where a message has one key; its comment
  promised a duplicate-key check of the payload. serde is what refuses a repeated field or a
  second key (`a_signed_payload_has_one_meaning`); the comment says so now.
- The peers file's prefix bounds were tested for IPv4 = 33 only.
- A rotated audit segment with bytes appended; the `CONFIG` flag bits; a strike count that
  restarts after `STRIKE_MEMORY`; reasons cut on a UTF-8 boundary; an ended peer claim at its
  exact end; a full retraction memory.
- `CanonicalParser::parse_ipv6_bytes` had no caller and was removed.

## Open survivors

Not yet read one by one; each needs a test or an exclusion with its reason:

- `block_table`: `restore` (restored/refused counters, lease bounds), `tick` (lease and
  quota edges), `take_persisted`, merging of retractions, `detector_retractions` counters,
  `oldest_pending`, `waiting_claims` lease edge.
- `mesh_dispatch::peer`: audit arms for held and refused claims, sync throttling, `valid_head`.
- `p2p`: the reader loop's error and size guards, `broadcast` feature filter, `addr_of`,
  `send_to`, `pinned_peers`, key file migration guards.
- `replay`: `MemoryLists` capacity (replay does not compare enforced against pending),
  `BLOCK_REFUSED` outcome text.
- `common::audit_log`: `append` rotation thresholds, `next_record` bounds, `read_full` on
  `Interrupted`, `check_witnesses` range edges.
