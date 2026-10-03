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
| REPLAY-R3 | In current detector writer layouts, `Reason` is opaque data: it cannot override leading `IP`/`TTL`/`Why`/`Protected` or appended `Claim`/`At`/`Event`/`Ttl`. The complete reason bytes are retained. | `reason_fields_cannot_hide_a_wrong_detector_ttl`, `a_real_source_ttl_survives_reason_decoys`, `free_text_reason_is_not_a_field_namespace`, `generated_reasons_preserve_fields_and_bytes`, chained-file CLI cases |
| REPLAY-R4 | Signal-socket `DB_LOG` text has a fixed `CLIENT_LOG` outer tag and cannot supply node lifecycle/decision/loss records. | `client_logs_cannot_supply_replay_authority` (real writer/reader/CLI), XDP smoke client ACK/dump/fresh-replay checks |
| REPLAY-R5 | Explicit loss markers fence dependent replay until a usable start. Any marker prevents CLI 0, including a tail/pre-context gap; known mismatches retain 1. | `explicit_audit_gaps_fence_dependent_decisions`, `a_gap_alone_prevents_a_successful_cli_result` (real chained files) |
| AUDIT-R1 | Oversized records are known losses, not successful appends. Before following data or sync, `AUDIT_LOST` accounts for them even on a still-writable log. | `oversized_audit_records_are_counted_and_marked_before_following_data_or_flush` (real asynchronous writer, chained file, metrics and CLI) |
| AUDIT-R2 | Queue loss is emitted before following data and every sync path: explicit Flush, idle timeout, disconnected final sync. A failed notice retains its sampled count; that record cannot bypass the notice. Cross-producer drop publication and send are not atomic. | `a_flush_records_real_queue_overflow_without_a_following_record`, `idle_sync_records_real_queue_overflow_without_a_following_record`, `disconnected_final_sync_records_real_queue_overflow`, `a_failed_loss_notice_retains_its_count_until_recovery` (actual Full channels, writer loop and unavailable-path recovery) |

Baseline regressions: a recorded capacity refusal replayed as `lifted`, then its retry
as `duplicate`, producing two mismatches on a table changed by speculation. A journal
with a decision before its start record and a later reproduced decision returned 0.
Both regressions compiled and failed their outcome assertions before the fix.

Claim/retraction occupancy and owner sets can depend on unlogged mesh inputs. This
classification does not establish that the refusal was correct: a faulty/fabricated
refusal can also remain unverified and yields exit 2. A new start restores replay context,
not evidence for earlier decisions. Other missing-input/mismatch handling retains its
existing scope; there is no complete mesh/resource-state reconstruction. Protected-set
refusals remain separately counted outside replay scope, even at exit 0. Only the node's
`Protected:` field immediately after `IP:` qualifies; a marker embedded in free-text
`Reason:` cannot exempt a capacity refusal from checking (`a_protected_marker_in_free_text_cannot_exclude_a_detector_decision`, also tested through the chained-file CLI). This
protects that exception. Replay now also isolates the entire reason from parsed metadata.
Leading fields come before `Reason:`; the last `|Enforced|Claim:` (enforced block),
`|Claim:` (pending block) or `|At:` (capacity refusal) begins the node's appended fields.
Protected refusals have no appended context. Current writers append those boundaries
and validate source/event ids to exclude `|`; a matching marker inside the reason is
therefore earlier than the node's actual one. The parser retains the whole reason,
including delimiters and Unicode, rather than filtering or decoding it.

Baseline false passes: `Reason:ids: scan|Ttl:600` supplied an unrecorded source TTL;
`Reason:ids: scan|TTL:60s` overwrote the recorded TTL. Both could make a wrong `600s`
decision under a base-60 policy appear reproduced and return CLI 0. Both now remain
mismatches (exit 1); a genuine source TTL and literal decoys reproduce correctly.
Generated reasons (including control characters) cover all four writer layouts, both address families,
optional source TTL and repeated boundary/key-shaped text, comparing the whole field map.
Fixed cases also cover an empty reason, embedded newlines/NUL and a reason over 200
characters, as non-Signal writers need not apply the Signal input filter.

This is parsing for current writer layouts under the existing exact-build replay rule,
not a new general audit schema or authentication of arbitrary forged/legacy bytes.
Unsupported layouts may lack context; missing context still prevents CLI success.
Historical log bytes and node outcomes are not rewritten. REPLAY-R4 below closes
client whole-record injection for new `DB_LOG` writes; it does not authenticate old
unwrapped records or protect against an actor able to rewrite the chain.

## REPLAY-R4: client text cannot supply node records

The signal socket's `DB_LOG:<text>` calls `SentinelDb::append_client_log`, which
writes one length-framed `CLIENT_LOG|Message:<trimmed text>` record. The fixed outer
tag is ignored by decision replay: embedded `NODE_START`, decisions, `STATE_RESTORED`
and loss markers remain text. Pipes, NUL and Unicode are retained; direct API callers
can also supply internal newlines, while socket input is line-based. Existing outer
trimming, `OK recorded` and downstream telemetry are unchanged. Telemetry still
forwards client text under `DB_LOG:NODE=...`; this change separates audit records,
not the operator telemetry consumer.
The reply still acknowledges queue submission, not durable storage. Internal node
writers continue using `append` and their original tags. Trap finalisation is now
client data, still visible in monitor dumps; the TUI tier is now `CLIENT_LOG` unless
a later `TIER=` field supplies a display tier. Existing unwrapped logs are not migrated;
replay still requires the same build. This is separation at the socket entry point,
not a signature, isolation from filesystem writers or a claim that client text is true.

A real `SentinelDb`/`AuditReader` regression rejects a client-only forged start/decision
as a node run (CLI 2), verifies exact wrapped bytes, and reproduces actual decisions
across client lifecycle/loss/decision decoys. XDP smoke sends lifecycle/loss decoys
through the real ACK socket, checks the wrapper/replies, and requires the later fresh
run's replay to remain complete (CLI 0).

## REPLAY-R5: explicit audit loss invalidates dependent replay

Every top-level `AUDIT_LOST` or `AUDIT_QUEUE_OVERFLOW` marker fences the current
table until a new usable `NODE_START`. Dependent decisions are `INSUFFICIENT`, not
matches or speculative mismatches. Marker counts are reported separately from lost
record counts and unverified decisions. Counters that are zero or malformed still
fence conservatively. Any gap in the input makes CLI 2 unless a known mismatch
already requires CLI 1; this includes a tail gap, a gap before usable context, and
a later fresh run that reproduces. Fresh complete input still returns 0.

This consumes explicit markers, not proof that every loss is marked. AUDIT-R1/R2
now cover oversize rejection and terminal queue drops while the writer can persist
the notice. Failed sync/recovery can still lose a tail; a process or disk failure
may prevent the marker itself reaching disk. No detection of arbitrary missing
whole records or complete crash durability is claimed. Client-wrapped marker text
is not a gap declaration (REPLAY-R4).

Regressions exercise both marker kinds, dependent duplicates/new decisions, fresh-run
recovery, invalid counters and the real chained-file CLI, including tail/pre-context
gaps and mismatch precedence. Semantic controls must catch unwrapped client text,
ignored gaps, continued table use after a gap and gap-free CLI success at the tail.

## AUDIT-R1/R2: known loss precedes dependent records and sync

Owner: `AuditWriter::record`, `AuditWriter::sync`, `AuditWriter::run` in
[main.rs](../orchestrator/src/main.rs); [ADR-0005](adr/0005-degraded-modes.md).

An oversize rejection leaves the healthy log handle open, increments `AuditHealth.lost`
(`sokol_audit_lost_total`) and accumulates a pending `AUDIT_LOST` notice. Both record
and sync paths emit that notice before continuing, including on a log that never
needed to reopen. No truncation, split payload or silent successful append is used.
The notice covers rejected records; it does not turn them into reproduced evidence.

Queue-drop counts are sampled before each record and sync. A successfully appended
`AUDIT_QUEUE_OVERFLOW` drains the sampled count; if opening/appending its notice fails,
the count is added back, preserving concurrent new drops. Ordinary records cannot
bypass a failed notice: they are counted as additional failed records. Retrying a
notice is not itself counted as another lost user record. When the log recovers,
failed-record and sampled queue-loss notices precede subsequent data. This ordering
covers drops with a happens-before link to the later send (e.g. the same producer).
Across independent producers, `try_send(Full)` and publishing its counter are not
atomic; another record may be sent/written in that window before the notice is known.
The later marker still prevents CLI 0, but an intervening comparison may become a
mismatch rather than insufficient. No atomic ordering across producers is claimed.
Since the drop counter
has no queue position, a fence may precede records queued before the actual loss;
it conservatively discards replay context rather than assigning an exact loss time.

Every worker sync calls this same path: Flush, periodic idle sync, batch/interval sync
and the final sync after sender disconnection. `flush(true)` confirms that the barrier
processed preceding queued records, appended sampled pending loss notices and completed
sync; it does **not** mean all original records survived or replay can return 0.
Quiesce producers to include all completed submissions: a barrier does not freeze or
acknowledge concurrent later submissions. Production shutdown now joins the decision
and audit producers before final state persistence and this barrier (SHUTDOWN-S1/S2).
If a notice cannot be appended, sync returns
false and pending counts remain for retry; the retry interval stays bounded by the
existing 100 ms receive timeout rather than a zero-wait busy loop. Process termination
or persistent disk failure can still prevent a notice from being written. Failed sync
and reopen/torn-tail durability accounting remains a separate limit; this is not a
crash-complete audit guarantee.

Baseline regressions compiled and failed after behavior-preserving worker extraction:
oversize loss was zero, Flush/idle left the pending drop counter at one, disconnected
sync omitted the marker, recovery left seven queue drops unrecorded. Actual bounded
channels are filled before the actual worker starts, forcing `TrySendError::Full`
deterministically without production test hooks. The idle test captures evidence
before disconnection, so final-sync behavior cannot mask a timeout regression.
Semantic controls must reject silent oversize success, skipping loss on a healthy
handle, skipping queue accounting in sync, dropping failed notice counts and writing
ordinary records ahead of sampled pending queue loss or ending after appending a
notice without successful disconnected final sync. Existing fresh complete replay remains 0;
real synced loss notices give 2, not a complete-evidence success.


## SHUTDOWN-S1/S2: producers stop before final state and audit

Owners: [shutdown.rs](../orchestrator/src/shutdown.rs), the task registrations and
shutdown sequence in [main.rs](../orchestrator/src/main.rs).

| ID | Invariant | Executable evidence |
|---|---|---|
| SHUTDOWN-S1 | Once quiescence returns, registered listeners and accepted IPC/control children have been dropped; they cannot mutate the final table snapshot or submit records after the terminal audit submission. Child registration is closed before cancellation, including concurrent registration. | `quiesce_joins_a_stalled_producer_before_final_state_and_audit`, `child_handlers_are_joined_with_their_listener`, `a_closed_owner_refuses_late_child_registration`, `producer_quiescence_keeps_shutdown_record_last`; active/idle socket XDP shutdown smoke |
| SHUTDOWN-S2 | A cleanup-worker timeout cancels and joins the task instead of detaching it. Table mutation and its decision audit submission precede cancellable network awaits. | `a_timed_out_cleanup_worker_is_cancelled_and_joined`, `local_decision_is_audited_before_cancellable_mesh_publication` (actual registry lock held); XDP final-state/audit checks |

The task set owns the ring-buffer consumer, mesh-command consumer, telemetry processor,
traps, host-policy refresh, local listeners and their accepted children. Seed maintenance,
peer snapshot sender, P2P listener and metrics server also stop through this set. Completed
entries are reaped on registration; weak child spawners cannot retain the owner through a
reference cycle. Owner drop cancels tasks on startup errors too
(`dropping_the_owner_does_not_leave_a_child_reference_cycle`); normal shutdown additionally
joins every registered task before proceeding.

Shutdown stops the main tick, closes registration, aborts and joins producers, awaits the
FlowSpec withdrawal worker within its existing budget (abort + join on timeout), then
persists the last table and submits `NODE_SHUTDOWN` followed by the audit flush. Local
block and operator flush audit submissions precede mesh publication; host-policy replacement,
table recheck and its audit submissions share one poll after acquiring the table lock.
This avoids cancellation between the mutation and its decision audit submission; queue or
disk loss still follows AUDIT-R1/R2. The trap's companion `TRAP_HIT` follows publication
and can be cancelled after the decision record; it is not replay authority or promised
as part of the terminal decision boundary. A command already applied can lose its network publication
or ACK during shutdown, so a missing reply does not establish refusal. Adapters retain
unanswered intent under their existing retry protocol.

This is a boundary for completed local decisions, not a drain of every input: unread
socket/mesh messages and kernel ring records may be discarded without becoming decisions.
P2P transport children, including the writer and ping tasks of seed connections, can
outlive their parent; they hold no table/audit handle and cannot create local decisions
after the mesh consumer is joined. Cancelling seed maintenance does not join these children.
Axum's accepted HTTP metrics tasks can also outlive the registered server; they hold only
its read-only metrics snapshot, no table/audit handle. A host discovery `spawn_blocking` call
already running cannot be cancelled by Tokio, but it holds no table/audit handle and its
cancelled parent cannot publish its result. It can still delay runtime teardown. Cooperative
cancellation is not a hard wall-clock deadline for non-yielding code or blocking OS calls.
State writes retain their existing five-second wait and audit flush its two-second wait;
failures are reported and never imply successful durability. No SIGKILL/crash-complete,
all-packet, all-input, or successful-upstream-withdrawal guarantee is added. Under audit queue
loss the terminal record itself can be dropped and marked as loss, so its presence is not
promised by quiescence alone.

The detached-task equivalence control uses the prior `tokio::spawn`/discarded-handle pattern:
compiled tests reject surviving parent/child tasks, owner-drop leaks and a cleanup timeout
that detaches. The actual chained-audit regression additionally rejects a surviving child
receiver at final fsync. The decision regression rejects moving mesh publication back ahead
of the audit submission. Canonical Linux CI uses the actual policy, registry and kernel
smoke; the portable owner extraction uses kernel/transport/policy stand-ins for local checks.


## FLOWSPEC-S1: failed smoke readback cannot prove presence or absence

Owner: [flowspec-rib.sh](../scripts/flowspec-rib.sh), used by all ten FlowSpec
assertions in [xdp-smoke.sh](../scripts/xdp-smoke.sh).

The pinned GoBGP text CLI must exit successfully before its stdout can support an
assertion. A missing CLI or failed RPC (including matching partial stdout) returns
2 (unverified). A successful read returns 0 when the requested
presence/absence agrees with the displayed literal source prefix, otherwise 1.
The smoke's check wrapper rejects both 1 and 2; absence is requested explicitly,
never obtained by negating a presence check that can itself fail.

The regressions in `scripts/test_flowspec_smoke.py` execute the actual ten caller
commands with fallible CLI stand-ins and the actual check wrapper. Successful
present and empty responses cover both expectations; failed reads, partial output,
and a missing executable cannot pass. Prefix matching is a literal Bash operation
without a separate matcher process or here-string redirection. CI runs these
before the native XDP/BGP smoke on both Linux architectures.

This is a readback refusal invariant, not validation of all successful CLI output.
It relies on the pinned CLI's text format and successful-query completeness; empty
successful output represents an empty displayed RIB. Source-prefix matching alone
does not prove discard action, ownership/community, a coherent snapshot across
queries, or global network state. It does not change the runtime's JSON-based
reconciliation or its withdrawal guarantees.


## AUDIT-V1: unavailable verification cannot establish corruption

Owners: typed `ChainVerifyError` in [audit_log.rs](../common/src/audit_log.rs),
[monitor.rs](../orchestrator/src/bin/monitor.rs), and the three audit assertions
in [xdp-smoke.sh](../scripts/xdp-smoke.sh) through
[audit-verdict.sh](../scripts/audit-verdict.sh).

`monitor --verify` distinguishes 0 / `OK` (verified retained chain), 1 / `BROKEN`
(observed corruption, segment discontinuity or rotated trailing bytes), and
2 / `UNVERIFIED` (enumeration, open, read or metadata failure). Classification
uses structured errors rather than diagnostic-string matching. A file observed
shorter than the reader's verified offset is unverified, avoiding subtraction
underflow. Replay keeps rejecting either error before consuming any decisions.

Smoke requires both the exit code and a matching path-bound label for its explicit
intact/broken expectation. The path label binds the verdict to the invocation
argument, not an authenticated or canonical file identity. Failed execution,
inconsistent or missing output and
a verdict about another path cannot confirm either expectation. The real smoke
wrapper rejects a contradiction and an unverified result alike.

`orchestrator/tests/audit_verify.rs` executes the real monitor CLI with real
common-library fixtures: intact chain, edited hash, segment gap, rotated trailing
bytes, missing active/parent paths and actual read failures in active/rotated
files. `scripts/test_audit_smoke.py` executes the three actual caller commands
and wrapper with fallible CLI stand-ins. These tests also retain the active
torn-tail policy: `OK` covers complete readable records; an incomplete suffix
in the active file is permitted and is not rewritten by verification.

This does not establish complete audit history, recover lost records, authenticate
an externally unanchored head, or provide an atomic snapshot while files change.
Pruned older segments and the active incomplete suffix retain their existing
limits. Verification remains read-only; no writer, record format, hash algorithm
or retention policy changes.


## XDP-S1: failed tools or a broken path cannot prove a kernel drop

Owner: [xdp_probe.py](../scripts/xdp_probe.py), used by all sixteen IPv4 drop
assertions in [xdp-smoke.sh](../scripts/xdp-smoke.sh).

A successful drop assertion requires a healthy separate source on the same isolated
veth route, one unambiguous XDP attachment for the expected interface, and a successful
`bpftool` kernel test-run returning the integer XDP_DROP verdict for the requested
source/destination Ethernet/IPv4/ICMP frame. The live namespace ping must then report
exactly the requested transmissions and zero responses with its no-reply exit code,
without reported network errors.
The control route must still work and the observed program ID, ifindex and mode must
match the initial attachment. A valid XDP_PASS or live reply contradicts the requested
drop; missing tools, timeouts, failed commands (even with valid partial JSON), malformed
or ambiguous readback, inconsistent ping summaries and attachment changes are unverified.
Neither nonzero result passes the real smoke wrapper.

`scripts/test_xdp_probe.py` executes the sixteen actual caller commands with independent
source/count/fragment expectations and fallible CLI stand-ins. It independently decodes
frame fields and checks both checksums, live probe arguments and the ordering of controls,
readback and kernel execution. Refusal controls cover wrong interface, changed identity,
unsupported attachments, duplicate JSON fields, boolean/floating verdicts, failed partial
stdout, control-path failure, command errors and missing tools. Both Linux CI architectures
then run the helper with actual bpftool, kernel programs and veth traffic; optional tools
are never used to skip these assertions.

This is a controlled laboratory check. Ordinary kernel test-run returns a verdict
without delivering that frame through the network; the live probe remains separate.
See [Linux BPF_PROG_RUN](https://www.kernel.org/doc/html/latest/bpf/bpf_prog_run.html).
Test execution can update program maps/events; smoke totals include these synthetic
frames. The checks establish the observed program decision and live no-reply condition,
not causal attribution for every individual wire packet, a physical-NIC qualification
or an atomic snapshot of attachment/policy state. Equal before/after identities do
not detect a transient change that returns to the original identity. The fixture has
no concurrent attachment changes or competing routes; the checks never extend into
production authority. No kernel/producer behavior, detector policy or proof-core changes.


## FLOWSPEC-R1: acknowledged writes cannot fabricate observed RIB counts

Owner: `round` / `run_worker` in [flowspec.rs](../orchestrator/src/flowspec.rs).

A round that changes rules reads both local RIB families again before returning a
count to `sokol_flowspec_announced`. Accepted add/delete commands that have no RIB
effect cannot manufacture presence/absence. A failed post-write command, even with
valid partial stdout, or malformed JSON is an error; the worker retains its prior
successful count. An unchanged round returns its initial observation without two
extra queries. The existing ownership predicate, withdrawal-first order and
64-operation cap remain unchanged. A changed round adds at most two CLI calls;
with 5-second per-call timeouts the configured call-wait allowance is
`(2 + 64 + 2) × 5 s`, not a hard round deadline. Scheduling, process teardown and
other work remain outside it; shutdown retains its separate attempt budget.
The worker notices shutdown between rounds; the outer task timeout can cancel a
slow in-flight round before the inner withdrawal attempt begins.

Six native Rust regressions execute the production round and CLI subprocess runner
against controlled child executables: no-effect add/delete, failed/malformed
readback, successful observed changes and unchanged rounds. Five failed on the old
implementation's behavioral assertions. Local extraction executes the unchanged
FlowSpec module with audit/target-format stand-ins; canonical x86/ARM CI additionally
uses the actual audit owner and GoBGP/XDP smoke. Four compiled semantic controls
reject optimistic arithmetic, reuse of the old observation, swallowed readback
errors and treating failed CLI stdout as success.

This count is a retained observation of local owned source-prefix paths, not a
freshness guarantee, coherent snapshot across IPv4/IPv6 reads, validation of discard
actions, convergence certificate or upstream-router enforcement. The CLI-operation
audit records retain their existing meaning and bytes; a later failed read does not
rewrite a prior operation. Actual GoBGP is not alleged to acknowledge no-effect
writes; the controlled executable exposes the consumer's former unsupported inference.


## FLOWSPEC-R2: retained counts expose readback health and monotonic age

The worker publishes count, enablement, success status and read-start instant as one
locked record. A normal or shutdown round revokes success before its first await;
a failed or cancelled round cannot change the retained count or time. A completed
round replaces them together. Age begins before the successful two-family read,
including time spent waiting for GoBGP, and is evaluated at each scrape. HTTP samples
the worker directly, independent of the main loop's last published snapshot.

`failed_readback_retains_count_and_age_until_recovery` executes the production
CLI runner with a changed RIB and valid JSON plus a failing exit code, then recovers
to observed zero. `pending_and_cancelled_rounds_revoke_readback_before_waiting`
checks the state while the actual child is blocked and after cancelling the future.
`observation_age_includes_the_time_spent_reading` rejects completion-time timestamps.
`scraping_samples_the_worker_without_a_main_tick` checks the production rendering
bridge against a fixed main snapshot. `readback_age_advances_without_another_publication`
uses deterministic monotonic instants for both successful and failed observations.
`an_unverified_count_has_explicit_unknown_readback` fails behaviorally on the prior
renderer, distinguishing unknown zero from observed zero. Six compiled semantic
controls reject retained success during a pending round, fabricated zero after failure,
refreshing the timestamp on failure, completion-time timestamps, rendering the old
main tick and a frozen age. Local extraction uses the unchanged production modules
with audit/target/retraction/mesh-label stand-ins and the actual common crate;
canonical native CI uses the actual owners.

The Linux smoke uses the actual HTTP endpoint and pinned GoBGP: a wrapper forces
CLI errors, the local RIB changes independently, the previous count remains with
health zero and increasing age, and recovery re-announces the desired static rule.
Disabled and observe mode expose enabled=0, ok=0, age=-1. Recovery waits for
asynchronous upstream propagation with bounded attempts on known contradictions;
an unverified read fails immediately. All twelve actual RIB smoke call sites are
covered by the CLI-failure refusal regressions. The smoke's wait/age limits
are test conditions, not production SLOs. Parsing rejects missing, duplicate,
nonfinite or invalid samples; an HTTP error cannot satisfy an observation.

Native end-to-end CI exposed an additional consumer: the runbook rehearsal assumed
all `_ok` metrics must be 1, including a correctly disabled FlowSpec worker. The
runbook and actual rehearsal now name the same four required node health series as
the dashboard/alert. Tests execute that shell consumer: optional pending/disabled
readback is allowed; each missing, zero, malformed or duplicate mandatory series
and empty/failed HTTP are rejected. This does not change runtime MODE/authority;
FlowSpec remains separately observable under its own contract.

These gauges describe the latest round and retained local observation. They do not
supply an atomic IPv4/IPv6 RIB snapshot, a universal freshness deadline, process
liveness, convergence, action validation or upstream enforcement. A consumer must
select its own acceptable age. No new permission or detector policy is introduced.

## FLOWSPEC-R3: ownership does not establish discard or conditional-write authority

Owner: `flowspec.rs::parse_rib`, `plan`, `round` and the coherent worker-to-HTTP
bridge in `metrics.rs`. Managed scope is local ID-zero paths with the configured
standard community and exactly one full source-prefix component (IPv6 offset 0).
Ownership is independent of action: a wrong-action owned path still gets withdrawn
when unwanted; a wanted prefix missing canonical discard is re-announced. The
existing withdrawal-first order, 64-operation cap, call timeout and shutdown
attempt budget remain unchanged.

Canonical discard means exactly one extended-community attribute containing
exactly one traffic-rate action (type 128, subtype 6), uint16 AS and numeric rate
zero. Missing, nonzero, unknown, duplicate or combined actions do not satisfy this
contract. `sokol_flowspec_announced` retains its ownership count;
`sokol_flowspec_discard_rules` reports the validated subset. Counts, health and time
come from one worker snapshot. Post-write reads, failed-round retention and age
semantics follow R1/R2. CLI acceptance without an effect cannot increase the
validated count; a successful read may still observe wrong actions (ok is not
convergence).

A real GoBGP 4.9.0 experiment showed that a local add at the same source-only NLRI
replaces an existing foreign local path despite distinct ownership communities.
Before applying the operation quota, the production round excludes required
operations that collide with observed foreign local paths. Non-colliding withdrawals
and announcements still progress, including shutdown reconciliation. Peer paths are not local CLI targets;
nonzero local IDs are outside the managed scope and fence overlapping operations.
Any skipped operation leaves health revoked and retains the previous successful
counts/time, even after safe writes and a full post-write read. This prevents known
collisions, not races: CLI AddPath/DeletePath has no atomic ownership compare-and-swap.
Shared-daemon writers must serialize or use exclusive source-prefix namespaces.

Reproduction: `owned_non_discard_action_is_replaced_when_still_wanted` and
`foreign_local_path_collision_refuses_before_any_write` failed behaviorally on the
previous implementation. Six raw captures from a pinned-source local daemon cover
owned rate-limit, owned discard and foreign discard in IPv4 and IPv6; provenance
is in `orchestrator/tests/fixtures/README.md`.
`live_gobgp_round_repairs_actions_and_preserves_foreign_local_paths` executes the
production read/plan/write/re-read flow against a real daemon for both families:
repairs rate-limit 100 to discard, withdraws an unwanted wrong action, then refuses
a foreign-only collision while its full raw RIB response remains byte-identical.
It then checks unrelated withdrawal/announcement and shutdown cleanup while the
foreign path remains present. An
unset `SOKOL_GOBGP_TEST_BIN` skips that local test; canonical x86/ARM CI requires it
and emits two positive execution markers. A framework PASS after skip is no proof.

Local checks passed 26 production-module tests, including real GoBGP for both
families, and 13 Python smoke/health refusal tests. The portable Rust harness uses
actual common code with audit/target/label stand-ins; canonical Linux CI exercises
the actual owners. Ten compiling semantic mutations were rejected by assertions:
ownership treated as discard, dropping wrong-action owned paths, bypassed collision
refusal, accepting a small positive rate, accepting combined actions, publishing
ownership as discard, ignoring source offset, ignoring local ID, refusing the whole
round and applying the quota before excluding collisions. Independent Claude review
found that the first all-or-nothing collision preflight starved unrelated unblocking.
`collisions_do_not_starve_unrelated_withdrawals_or_announcements` failed on that
head and now checks more collisions than the quota, safe withdrawal/announcement,
retained health/counts/time and shutdown with an overlapping nonzero-ID path.
Existing HTTP
smoke expectations now also require the known fixture count to be canonical discard.

Limits: this is a conservative pinned-GoBGP action and local-NLRI contract, not
validation of the entire JSON schema, a best-path decision, desired-set equality,
atomic two-family snapshot, upstream enforcement, crash-complete withdrawal or
concurrent-writer isolation. No Stargate checker, frozen source/results or delivery
shadow pins change.
