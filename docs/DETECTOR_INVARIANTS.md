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
Capacity refusal increments a saturating counter and is reported per batch. Such alerts
are skipped: no retry obligation is created, and checkpointing may advance past them.

Regression input: 100,000 different IPv4 addresses at one `Instant`, 24-hour cooldown,
and a rate quota above the fixture size, then one more different address. The previous threshold-and-retain
implementation accepted the extra address because none had expired. The real-cap test
failed at that admission assertion before the fix. This does not assert a production outage.

## Source, queue, acknowledgement and checkpoint

Owners: [Follower and adapter loop](../orchestrator/src/bin/sokol-suricata.rs),
[Outbox and Conn](../orchestrator/src/delivery.rs).

| ID | Invariant and enforcement point | Executable evidence |
|---|---|---|
| SUR-R1 | Complete records read before a later I/O error are returned alongside the error; unfinished bytes and their starting position survive for retry. Byte/line quotas still apply. | `a_read_error_preserves_completed_alerts_and_unfinished_bytes`, `read_errors_before_a_complete_line_preserve_the_cursor_and_retry_bytes` (fault injected through the actual buffered scanner). |
| SUR-C1 | A queued offset is usable only for the same observed content token and inode. Otherwise checkpoint position is zero in the current file. A loaded resume anchor survives failed source open/seek until successful installation. | `detected_truncation_fences_offsets_from_previous_contents`, `resume_retains_its_anchor_while_the_source_is_missing`, `failed_install_does_not_erase_the_selected_resume_anchor`; process cases below. |
| SUR-Q1 | At checkpoint time, queued positions correspond to the remaining FIFO outbox entries. Only successful push adds a position; overflow removes the oldest pair; after flush the loop trims positions to remaining pending length. Outbox request/deadline entries are likewise paired. | `invalid_input_cannot_evict_a_queued_signal`, `a_full_queue_drops_the_oldest_and_counts_it`; actual process restart/ACK cases below exercise cursor alignment. |
| IPC-A1 | Transport failure, unknown reply or missing terminating LF retains the current obligation. A complete recognized final reply removes it; bounded overflow is an explicit, counted loss path. ACK outcome is node acceptance/refusal, not proof of durable storage or completed kernel enforcement. | `unknown_reply_keeps_the_obligation_and_a_later_ack_retires_it`, `an_unterminated_ack_does_not_retire_the_signal`, overflow test above. |

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
