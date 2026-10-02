# Detector invariants

This ledger records properties of the current Suricata adapter and shared IPC outbox.
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

A single call can expire the entire 100,000-entry FIFO. Hash operations and allocations
have no hard latency bound, allocated capacity may exceed live entries, and this is not
an RSS bound. Rate uses fixed one-second windows starting/resetting on eligible attempts;
its setting is not a sliding-window guarantee or an IPC send/retry ceiling. Zero cooldown
allows immediate renewal; zero rate admits nothing. Policy admission is before outbox
framing validation and delivery, so it does not establish that an alert was queued or ACKed.
Capacity refusal increments a saturating counter and is reported in aggregated warnings.
Such alerts are skipped: no retry obligation is created, and checkpointing may advance past them.
Cooldown-refused attempts also increment a saturating counter and use the same aggregation.
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
| SUR-D1 | Cooldown and capacity refusal warning emissions are separated by at least one monotonic second; each emission contains at most one line per category. Fixed-size reporting state retains the difference between cumulative and reported counters, including across empty/error polls. Reported deltas sum to observed refusals before counter saturation. | `refusal_diagnostics_preserve_counts_and_space_emissions_across_batches`, `refusal_diagnostics_do_not_wrap_or_reemit_saturated_totals`; actual process `RecoveryTests.test_cooldown_diagnostics_aggregate_across_batches_and_flush_at_eof` |

The first nonempty report may be immediate. Emission is checked outside the source-poll
match, before delivery: idle/error polls can flush earlier pending counts, but blocked
work and scheduling can delay a check. This is an emission-spacing bound for two warning
categories, not a deadline or a bound on all logging. Counters saturate at `u64::MAX`;
additional refusals beyond saturation are not observable. Pending reports are in memory
and may be lost on process death. Neither skipped-alert count establishes delivery.

Regression input: one admitted source followed by 4096 repeats over 17 reader batches.
Before aggregation the actual process emitted 17 warnings in roughly one second, and
the emission-count assertion failed. The revised loop preserves all 4096 refusal counts
and flushes the remaining report after reaching EOF, without a new alert.

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
