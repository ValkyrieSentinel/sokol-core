# Detector invariants

This ledger records properties of the Suricata and CrowdSec adapters, the node's
detector retraction and shared IPC outbox.
Code owns behavior; named tests are executable evidence, not a proof of deployment or
an extension of Stargate's frozen model certificates. The scope is one adapter process
unless a restart test explicitly says otherwise.

## Cooldown and admission

Owner: [Gate](../orchestrator/src/bin/sokol-suricata.rs). Time inputs are nondecreasing
`Instant`s, supplied by the single-threaded main loop, and cooldown is fixed for a Gate.

| ID | Invariant and reason | Executable evidence |
|---|---|---|
| SUR-G1 | Cooldown membership and expiry FIFO describe the same distinct addresses; each has at most `COOLDOWN_CAP` = 100,000 entries. Start empty; remove the expired prefix from both; refuse at capacity before inserting into both. Never evict an unexpired address to admit another. | `gate_cooldown_memory_has_a_hard_bound_without_eviction`, `gate_generated_history_preserves_cooldown_and_bounded_unique_memory` |
| SUR-G2 | Successful admissions of one source IP are separated by at least cooldown. A capacity or rate refusal creates neither a new cooldown nor an admitted-rate slot. Only successful admission inserts an expiry tuple and increments the quota. | `gate_capacity_refusal_keeps_live_cooldowns_and_releases_only_expired_slots`, `gate_rate_refusal_does_not_start_cooldown_and_zero_policies_are_defined`, generated history above |
| SUR-G3 | Expiry inspection is an ordered prefix, with no full-set scan on each hot-cache refusal. Each admitted tuple is appended once and popped at most once. Thus total expiry pops cannot exceed prior successful admissions; each attempt adds at most one stopping head inspection. | Code structure plus mixed renewal/refusal history in `gate_generated_history_preserves_cooldown_and_bounded_unique_memory`; this is accounting, not a timing benchmark. |
| SUR-G4 | Every `Gate::admit` attempt either admits or routes exactly one refusal reason to its saturating counter: cooldown first, then rate, then capacity. Admission increments no refusal counter; refusing creates no new cooldown or rate slot. Before any category saturates, attempted count equals admissions plus the three refusal counts. | `every_gate_refusal_has_one_counted_policy_reason`, `gate_refusal_counters_saturate_independently`; per-step accounting over 10,000 attempts in `gate_generated_history_preserves_cooldown_and_bounded_unique_memory` |

A single call can expire the entire 100,000-entry FIFO. Hash operations and allocations
have no hard latency bound, allocated capacity may exceed live entries, and this is not
an RSS bound. Rate uses fixed one-second windows starting/resetting on eligible attempts;
its setting is not a sliding-window guarantee or an IPC send/retry ceiling. Zero cooldown
allows immediate renewal; zero rate admits nothing. Policy admission is before outbox
framing validation and delivery, so it does not establish that an alert was queued or ACKed.
Capacity refusal increments a saturating counter and is reported in aggregated warnings.
Such alerts are skipped: no retry obligation is created, and checkpointing may advance past them.
Cooldown- and rate-refused attempts also increment saturating counters and use the same aggregation.
These categories identify the first failing policy, not all constraints an attempt violates.
For example, a new address at full rate and full capacity counts only as rate refusal.
Cooldown starts at policy admission, so even a later never-written expiry leaves it active.
This intentionally throttles admission during outages; fresh same-source alerts can be
suppressed until it ends. That suppression is not ACK evidence or guaranteed delivery.

Regression input: 100,000 different IPv4 addresses at one `Instant`, 24-hour cooldown,
and a rate quota above the fixture size, then one more different address. The previous threshold-and-retain
implementation accepted the extra address because none had expired. The real-cap test
failed at that admission assertion before the fix. This does not assert a production outage.

## Admission diagnostics

| ID | Invariant and enforcement point | Executable evidence |
|---|---|---|
| SUR-D1 | Decisions to report cooldown, rate and capacity refusals are separated by at least one monotonic second; each report generates at most one line per category. Fixed-size reporting state retains the difference between cumulative and reported counters, including across empty/error polls. For each category, generated report totals plus pending deltas equal its cumulative counter before saturation. A report decision clears pending deltas; filtered or delayed writes do not change accounting. | `refusal_diagnostics_preserve_counts_and_space_emissions_across_batches`, `refusal_diagnostics_do_not_wrap_or_reemit_saturated_totals`, `rate_only_diagnostics_wait_for_the_shared_interval_and_preserve_pending_counts`; actual process count checks `RecoveryTests.test_cooldown_diagnostics_aggregate_across_batches_without_losing_counts` |

The first nonempty report may be immediate. Reports are checked outside the source-poll
match, before delivery: idle/error polls can flush earlier pending counts, but blocked
work and scheduling can delay a check. The bound concerns decision instants, not visible
line spacing: slow stderr writes can make visible lines appear closer together. Log-level
filters can suppress output; baselines advance even when WARN is disabled. This is not
a deadline or a bound on all logging. Each report generates at most three warnings, one
per category. Pre-Gate filters (severity, ignored SID, parsing and freshness) are outside
these refusal counters. They are not a complete EVE-loss or delivery-loss inventory.
Counters saturate at `u64::MAX`; additional refusals beyond saturation are not observable. Pending reports are in memory
and may be lost on process death. Neither skipped-alert count establishes delivery.

Regression input: one admitted source followed by 4096 repeats over 17 reader batches.
Before aggregation the actual process emitted 17 warnings in roughly one second, and
the emission-count assertion failed. The revised loop preserves all 4096 refusal counts
by the final check at EOF. On a slow host reports may occur during batch processing;
the unit test separately demonstrates a pending report with no new refusals at the next
one-second check. The process suite supports count preservation and a coarse report-count
bound; synthetic-time tests enforce the exact decision interval and idle flush.

A second actual-process regression sets `--max-signals-per-sec 0` and reads 513 alerts
across three batches. Before rate accounting, the adapter advanced its cursor to EOF
without any refusal diagnostic; the regression failed waiting for the missing counts.
`RecoveryTests.test_zero_rate_counts_skipped_alerts_without_ipc_or_pending_cursor` checks
all 513 rate refusals, no other refusal category, no IPC connection and a fully advanced
cursor. Rate refusal is a deliberate skip, not a queued retry or node refusal.

## Forwarding freshness

| ID | Invariant and enforcement point | Executable evidence |
|---|---|---|
| SUR-T2 | CLI parsing rejects an age interval that cannot be added to the startup local `Instant`, before source/cursor/IPC operations. Zero and normal intervals remain valid configuration; each later per-alert addition is independently checked. This does not promise representability forever for values close to the clock limit. | `cli_rejects_unrepresentable_forwarding_age_before_startup`, `cli_forwarding_age_accepts_zero_and_normal_intervals_but_rejects_bad_numbers`; actual process `RecoveryTests.test_invalid_forwarding_age_leaves_cursor_and_ipc_untouched` |
| SUR-T1 | A parsed timestamp consumes the configured age budget. Future timestamps grant at most that budget from observation. Integer conversion and local-clock addition are checked; stale/unrepresentable timestamps do not enqueue. Missing/invalid timestamps retain the untimed policy. | `forwarding_budget_ages_exactly_and_future_timestamps_cannot_enlarge_it` |
| IPC-T1 | An opt-in forwarding deadline is checked before connection/backoff work and after handshake, immediately before preparing a send/retry. Expired FIFO entries are removed in pairs and increment `expired`, never a node-answer result. Each removal spends flush work budget. Source TTL entries still render retractions and require ACK; expired entries behind an unexpired FIFO head wait until they reach the front. | `forwarding_expiry_is_counted_loss_not_an_ack_and_spends_flush_budget`, `invalid_freshness_input_does_not_evict_or_create_a_deadline`, `lost_ack_then_freshness_expiry_does_not_resend_or_undo_the_signal`, `lost_answer_keeps_expiry_and_later_retry_sends_its_retraction` |

The actual-process case `RecoveryTests.test_alert_expiring_during_handshake_is_not_forwarded`
checks both first send and lost-ACK retry, including a fresh same-source alert suppressed
by the still-active admission cooldown (verified diagnostic). After a delayed handshake, the next wire command
is a new fresh alert, never the stale one or a fabricated retraction; checkpointing advances.
Before the fix both scenarios sent the stale alert. Freshness expiry is intentional forwarding
loss. Already applied effects remain under node policy, not a local undo. It does not shorten
acknowledged block TTL, and does not bound write/scheduler/node time after the final check.

## CrowdSec configuration and pacing

Owner: [Args and signal_pause](../orchestrator/src/bin/sokol-crowdsec.rs).

| ID | Invariant and enforcement point | Executable evidence |
|---|---|---|
| CS-P1 | The parsed command pacing rate is a `NonZeroU32`. Zero is rejected by `Args::parse` before outbox construction, LAPI polling or IPC; a zero rate cannot silently become one command per second. Default 200 and positive `u32` bounds remain valid, and zero poll interval remains a separate valid policy. | `cli_rejects_zero_ipc_pacing_before_startup`, `cli_pacing_accepts_positive_u32_bounds_and_zero_poll_interval`; actual process `StreamTests.test_zero_pacing_fails_before_lapi_or_ipc_requests` |
| CS-P2 | For positive rate `r`, requested pause `n` is the smallest whole-nanosecond interval satisfying `n * r >= 1,000,000,000`. Thus `1 <= n <= 1,000,000,000`; `(n - 1) * r` is insufficient. Integer ceiling avoids a shorter fractional rounding or zero pause at large rates. | `ipc_pacing_interval_does_not_round_below_the_configured_budget`, `ipc_pacing_intervals_are_positive_minimal_integer_budgets` (rates 1–10,000 and boundary values up to `u32::MAX`). |

Baseline zero-rate regression: the real adapter contacted the fixture's LAPI, performed
`ACK`, sent `SIGNAL#71;ttl=60` and remained running; the test expected CLI exit code 2
and no requests. The adapter formerly clamped zero to one. It now refuses the invalid
configuration before either peer is used. The process test observes local fake peers;
it does not assert production-node effects. A separate arithmetic regression found that
rate 3 produced 333,333,333 ns via `f64`, so three intervals were less than one second.
That assertion failed before upward integer rounding; the revised request is 333,333,334 ns.

The pacing pause follows each completed exchange, including retractions. The first
command can be immediate; endpoint latency, poll work, backoff and scheduler delay also
contribute to spacing. CS-P2 describes a requested sleep interval, not a sliding-window
rate limiter, wall-clock deadline or throughput promise. Scheduling, FIFO/ACK retention,
source TTL and poll-error recovery keep their existing semantics. No certificate in
Stargate's frozen Boolean model claims these integer/configuration properties.

## Source, queue, acknowledgement and checkpoint

Owners: [Follower and adapter loop](../orchestrator/src/bin/sokol-suricata.rs),
[Outbox and Conn](../orchestrator/src/delivery.rs).

| ID | Invariant and enforcement point | Executable evidence |
|---|---|---|
| SUR-R1 | Complete records read before a later I/O error are returned alongside the error; unfinished bytes and their starting position survive for retry. Byte/line quotas still apply. | `a_read_error_preserves_completed_alerts_and_unfinished_bytes`, `read_errors_before_a_complete_line_preserve_the_cursor_and_retry_bytes` (fault injected through the actual buffered scanner). |
| SUR-C1 | A queued offset is usable only for the same observed content token and inode. Otherwise checkpoint position is zero in the current file. A loaded resume anchor survives failed source open/seek until successful installation. | `detected_truncation_fences_offsets_from_previous_contents`, `resume_retains_its_anchor_while_the_source_is_missing`, `failed_install_does_not_erase_the_selected_resume_anchor`; process cases below. |
| SUR-Q1 | At checkpoint time, queued positions correspond to the remaining FIFO outbox entries. Only successful push adds a position; overflow removes the oldest pair; forwarding expiry drops its request/deadline pair; after flush the loop trims positions to remaining pending length. Outbox request/deadline entries are likewise paired. | `invalid_input_cannot_evict_a_queued_signal`, `a_full_queue_drops_the_oldest_and_counts_it`; actual process restart/ACK cases below exercise cursor alignment. |
| IPC-A1 | Transport failure, unknown reply or missing terminating LF retains an unexpired obligation. A complete recognized final reply removes it; bounded overflow and an opt-in forwarding deadline are explicit, separately counted local loss paths. ACK outcome is node acceptance/refusal, not proof of durable storage or completed kernel enforcement. | `unknown_reply_keeps_the_obligation_and_a_later_ack_retires_it`, `an_unterminated_ack_does_not_retire_the_signal`, overflow test above. |

[Process regressions](../scripts/test_suricata_recovery.py) run the actual adapter against
an EVE file and an IPC server: `RecoveryTests.test_pending_same_file_survives_process_loss`,
`RecoveryTests.test_pending_old_file_cannot_skip_new_file_after_rotation`,
`RecoveryTests.test_pending_pretruncate_offset_cannot_skip_regrown_file_after_restart`, and
`RecoveryTests.test_missing_source_keeps_resume_anchor_across_wait_and_process_loss`.
Both CI architectures run this suite; it is not a simulated filesystem-outage proof.

No claim of exactly-once delivery, eventual progress, lossless overload, durable outbox,
old rotated-file recovery after process loss, or detection of truncation followed by
regrowth between observations. Cooldown, age/severity/signature/UTF-8/size filters, outbox
overflow, periodic checkpoints and bounded node event memory remain operational limits.
These identity/time/cardinality properties are checked on their Rust owners, not encoded
as a Boolean certificate claiming to cover the full adapter.

## Node retraction admission

Owner: [BlockTable::retract_detection](../orchestrator/src/block_table.rs),
[node IPC reply](../orchestrator/src/main.rs), [Outbox](../orchestrator/src/delivery.rs).

| ID | Invariant and enforcement point | Executable evidence |
|---|---|---|
| NODE-R1 | When an identified event requires lifting/shortening own detector claims, capacity is checked for every missing retraction record, owner entry and replacement claim before support removal or replay-marker insertion. Capacity refusal preserves claims, support and event memory; after capacity is freed the same explicit request remains eligible. | `a_capacity_refusal_preserves_retraction_intent_for_retry`, `a_shortening_capacity_refusal_keeps_both_event_supports`, `retraction_admission_reserves_every_needed_record`, `a_full_retractor_set_preserves_support_until_its_owner_fits` |
| NODE-R2 | Admission counts missing records, not all claims: a full global record table can update a suitable existing record. A still-held event requires no new claim/tombstone storage. | `an_existing_record_can_accept_its_owner_at_the_global_capacity`, `an_event_still_held_needs_no_new_retraction_storage`, `a_plain_lift_needs_no_free_claim_slot` |
| NODE-R3 | Capacity refusal is reported as `refused` in audit/metrics and `OK refused retraction state capacity` over IPC. The outbox classifies it as a final refusal, not a recorded lift or transport retry. | `a_retraction_capacity_refusal_is_not_an_ipc_success`, `a_retraction_capacity_refusal_is_a_final_refusal_not_a_recorded_effect` |

Baseline regressions: a full retraction map returned `lifted` while the block remained;
a full claim map returned `still_held` while consuming the event support and replay marker.
Both assertions failed on those outcomes before the fix. Tests inject the documented
cardinality limits directly into the native table's fake-map fixture, compare saved
claims/support/events before and after refusal, then free one slot and retry the same id.
The multi-claim case requires two records and refuses even when one slot is available.

The reservation holds under the node's table lock; this is admission for detector
retractions, not a transaction guarantee for all mesh/operator table operations. Refusal
updates diagnostics but creates no removal, broadcast or background retry obligation.
Kernel deletion may still fail and remain pending after an admitted retraction. Bounded
support/event memory, asynchronous persistence and mesh delivery keep their existing
limits. These tests do not certify physical NIC behavior or distributed atomic removal.

## Audit replay evidence

Owner: [replay_records / print_report](../orchestrator/src/replay.rs),
[ADR-0016](adr/0016-decision-replay.md).

| ID | Invariant and enforcement point | Executable evidence |
|---|---|---|
| REPLAY-R1 | A recorded retraction capacity refusal that the fresh replay cannot reproduce is unverified. Its speculative table is discarded; dependent decisions are insufficient until a new usable start record. It is neither a verified refusal nor a cascade of mismatches. | `an_unverified_capacity_refusal_fences_dependent_replay_until_a_fresh_start`, `a_wrong_retraction_outcome_remains_a_mismatch` |
| REPLAY-R2 | Any insufficient decision prevents CLI success even when earlier/later decisions reproduce. Actual mismatches retain exit 1; complete nonempty replay has exit 0; incomplete/empty replay has exit 2. | `a_partially_reproduced_audit_is_not_a_successful_cli_result` (real chained files and `print_report`), XDP smoke requires zero insufficient decisions |

Baseline regressions: a recorded capacity refusal replayed as `lifted`, then its retry
as `duplicate`, producing two mismatches on a table changed by speculation. A journal
with a decision before its start record and a later reproduced decision returned 0.
Both regressions compiled and failed their outcome assertions before the fix.

Claim/retraction occupancy and owner sets can depend on unlogged mesh inputs. This
classification does not establish that the refusal was correct: a faulty/fabricated
refusal can also remain unverified and yields exit 2. A new start restores replay context,
not evidence for earlier decisions. Other missing-input/mismatch handling retains its
existing scope; there is no complete mesh/resource-state reconstruction. Protected-set
refusals remain separately counted outside replay scope, even at exit 0. Chain validation
checks integrity, not authenticity against an actor able to rewrite the chain.
