# Node invariants

This ledger records properties of the node and its adapters: Suricata and CrowdSec admission,
the shared IPC outbox, detector retraction, audit replay, shutdown, XDP smoke evidence and
FlowSpec reconciliation (FLOWSPEC-R1–R13). Until the 2026-10-05 review it was named the
detector invariant ledger; the anchors are unchanged.
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
| SUR-C2 | The saved cursor is replaced durably (temporary file synced, renamed, directory synced). A cursor file that exists but cannot be read or parsed starts reading the current file from its start, never its end; a missing cursor follows `--from-start`. Re-read alerts are bounded by the forwarding age and deduplicated by event id at the node. | `a_damaged_cursor_rereads_the_log_instead_of_skipping_it` (empty, truncated and non-JSON cursors; mutation "damaged = missing" fails it). |
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

## Node detection: one step, refusals change nothing

Owner: `BlockTable::detect` in [block_table.rs](../orchestrator/src/block_table.rs), the single
implementation called by the node (`enforce_block_local`) and by audit replay (ADR-0016).

| ID | Invariant and enforcement point | Executable evidence |
|---|---|---|
| NODE-D1 | A detection checks its event id, adds or merges the claim, then records the event, under one table lock. A resend of an event acted on within EVENT_MEMORY is a duplicate. A refused detection (here: the known-claims cap) records no event and counts no strike: a resend after capacity frees is decided afresh, and the next block of that target gets the TTL of its first strike. | `a_detection_refused_at_capacity_leaves_no_event_and_no_strike` (mutations "remember the event first" and "count the strike first" each fail it). |

## Audit witnesses (ADR-0021)

Owners: `check_witnesses` in [audit_log.rs](../common/src/audit_log.rs),
[audit_witness.rs](../orchestrator/src/audit_witness.rs), the `AuditHead` arm of
[mesh_dispatch.rs](../orchestrator/src/mesh_dispatch.rs), `PeerRegistry::broadcast`.

| ID | Invariant and enforcement point | Executable evidence |
|---|---|---|
| AUDIT-W1 | A head witnessed for "after N records" is compared with this log's record N-1 after both chains verify. A different chain value is a contradiction even when the rewritten chain verifies on its own; fewer records than witnessed is missing; a pruned record is unknown, never confirmed. | `a_witnessed_head_exposes_a_recomputed_rewrite_that_the_chain_alone_accepts`, `a_peers_witness_confirms_the_log_and_exposes_a_recomputed_rewrite` (mutation "compare without the head" fails both). |
| AUDIT-W2 | Only a fsynced head is offered. A peer adds at most one witness record per WITNESS_MIN_INTERVAL to this log, and a head that is not 64 lowercase hex is not recorded; both refusals are counted. | `a_peers_audit_head_is_witnessed_once_per_interval` (mutation "no interval" fails it). |
| AUDIT-W3 | `AuditHead` goes only to peers whose handshake announced `audit-head`; a handshake without `features` parses (older nodes). Other commands go to every peer as before. | `feature_commands_reach_only_peers_that_announced_the_feature`, `a_handshake_without_features_still_parses` (mutation "send to all" fails the first). |

Not claimed: protection against rewriting every witness's log as well, the truth of a
recorded decision, the unwitnessed tail (up to one interval plus fsync), pruned segments, or
an anchor outside the operator's mesh.

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
64-operation cap remain unchanged. An error-free changed fixed-target round adds at most two CLI calls;
with 5-second per-call timeouts the configured call-wait allowance is
`(2 + 64 + 2) × 5 s`, not a hard round deadline. Scheduling, process teardown and
other work remain outside it; shutdown retains its separate attempt budget.
FLOWSPEC-R8 below accounts separately for live-intent cancellation refreshes.
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
bridge in `metrics.rs`. Managed scope is local paths reported as ID-zero with the configured
standard community and exactly one full source-prefix component (IPv6 offset 0).
Ownership is independent of action: a wrong-action owned path still gets withdrawn
when unwanted; a wanted prefix missing canonical discard is re-announced. The
existing withdrawal-first order, 64-operation cap, call timeout and shutdown
attempt budget remain unchanged.

Canonical discard means exactly one extended-community attribute containing
exactly one traffic-rate action (type 128, subtype 6), uint16 AS and numeric rate
zero, with no type-25 IPv6-specific extended-community attribute. Missing, nonzero,
unknown, duplicate or combined actions do not satisfy this
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
reported nonzero local IDs are outside the managed scope and fence overlapping operations.
The pinned CLI's NewDestination does not copy the actual identifier into its JSON
path, so its `LocalID: 0` does not establish actual ID-zero identity. This exclusion
only works when a nonzero ID is reported. Reserve the ownership community for one
writer: a hidden nonzero-ID path reusing our tag may be counted as owned while the
ID-zero CLI withdrawal leaves it present. Health is not withdrawal convergence.
Any skipped operation leaves health revoked and retains the previous successful
counts/time, even after safe writes and a full post-write read. This prevents known
collisions, not races: CLI AddPath/DeletePath has no atomic ownership compare-and-swap.
Shared-daemon writers must serialize or use exclusive source-prefix namespaces.

Reproduction: `owned_non_discard_action_is_replaced_when_still_wanted` and
`foreign_only_collision_performs_no_write` failed behaviorally on the
previous implementation. Six raw captures from a pinned-source local daemon cover
owned rate-limit, owned discard and foreign discard in IPv4 and IPv6; provenance
is in `orchestrator/tests/fixtures/README.md`.
`live_gobgp_round_repairs_actions_and_preserves_foreign_local_paths` executes the
production read/plan/write/re-read flow against a real daemon for both families:
repairs rate-limit 100 to discard, withdraws an unwanted wrong action, then refuses
a foreign-only collision while its full raw RIB response remains byte-identical.
It then checks unrelated withdrawal/announcement and shutdown cleanup while the
foreign path remains present. It also replaces traffic-rate zero combined with
a type-25 IPv6 redirect for both families. An
unset `SOKOL_GOBGP_TEST_BIN` skips that local test; canonical x86/ARM CI requires it
and requires two positive execution markers in the Test step. A framework PASS
after skip is no proof. The same marker predicate refuses a deliberately skipped
local live-test invocation; pipefail also preserves a failed cargo status through tee.

Local checks passed 26 production-module tests, including real GoBGP for both
families, and 13 Python smoke/health refusal tests. The portable Rust harness uses
actual common code with audit/target/label stand-ins; canonical Linux CI exercises
the actual owners. Eleven compiling semantic mutations were rejected by assertions:
ownership treated as discard, dropping wrong-action owned paths, bypassed collision
refusal, accepting a small positive rate, accepting combined actions, publishing
ownership as discard, ignoring source offset, ignoring local ID, refusing the whole
round, applying the quota before excluding collisions, and ignoring a separate
IPv6-specific extended-community action. Independent Claude review
found that the first all-or-nothing collision preflight starved unrelated unblocking.
`collisions_do_not_starve_unrelated_withdrawals_or_announcements` failed on that
head and now checks more collisions than the quota, safe withdrawal/announcement,
retained health/counts/time and shutdown with an overlapping nonzero-ID path.
A separate IPv6 redirect regression failed on the accepted initial amendment
head and now refuses that combination for both family captures. Existing HTTP
smoke expectations now also require the known fixture count to be canonical discard.

Limits: this is a conservative pinned-GoBGP action and local-NLRI contract, not
validation of the entire JSON schema, a best-path decision, desired-set equality,
atomic two-family snapshot, upstream enforcement, crash-complete withdrawal or
concurrent-writer isolation. No Stargate checker, frozen source/results or delivery
shadow pins change.

## FLOWSPEC-R4: an unusable read cannot establish absence or write authority

Owner: `flowspec.rs::parse_rib`, consumed by the existing `round`/`checked_round`.
The pinned GoBGP 4.9.0 emits an empty JSON object for an empty RIB in both families.
Previously, exit-zero empty/whitespace stdout and JSON null became an empty RIB;
malformed destination values were silently skipped. Mistyped identity fields could
classify an unknown origin as local, authorize withdrawal or hide a collision.

A read now requires strict UTF-8/JSON with an object root and an array of path
objects per destination. After a valid nonempty peer-address excludes a peer path, each local path
has an attributes array and a nonempty NLRI component array. Attribute/component types, standard community values, any present
peer-address/LocalID, and source prefix/offset must be usable for classification.
Absent peer-address/LocalID remain compatible with the pinned local captures.
The pinned producer’s `communities: null` means an empty list, not an unknown
ownership tag. Other malformed local classification data rejects the entire read,
rather than silently omitting paths. A genuine empty object remains a successful empty observation.
Unknown or malformed action payloads do not certify discard; otherwise classifiable
owned paths retain R3 repair/withdrawal behavior. This is not full-schema validation.

`empty_output_cannot_publish_zero_before_or_after_writes` checks rejected initial
and post-write reads through the production CLI runner, retention of count/discard
count/time and revoked health. `malformed_path_collections_cannot_hide_a_local_collision`
rejects omitted collisions. `malformed_ownership_fields_cannot_authorize_withdrawal`
rejects mistyped origin, local ID, community and source data. All three tests failed
on assertions against the previous implementation before the parser change.
The existing parser regression also rejects invalid UTF-8 in an unrelated string
and accepts whitespace surrounding a real empty object.

The existing live GoBGP test retains a real foreign path and corrupts only its
family's CLI read through a controlled wrapper, with exit zero. Empty/whitespace,
null and malformed collections cannot forward any write; the daemon's full raw RIB
remains byte-identical and prior counts/time are retained with health zero. This is
fault injection at the CLI boundary, not a claim that GoBGP normally emits corrupt
JSON. Canonical x86/ARM CI requires positive execution markers for these refusals
and the existing action/collision checks in each family; a skipped test is no proof.

Local checks passed 32 production-module Rust tests including the actual daemon
for IPv4/IPv6, 13 Python smoke/health refusal tests, and Clippy. The portable Rust
harness retains audit/target/label stand-ins and actual common code; native CI
uses the actual owners. Eleven compiling semantic controls were rejected on test
assertions: normalizing missing output, skipping malformed destination collections,
accepting unknown peer identity, defaulting malformed LocalID to zero, skipping
malformed community/source data, defaulting malformed source offset and lossy
UTF-8 decoding, rejecting a legitimate null community, validating irrelevant remote
metadata, and treating an empty community as an ownership tag.

Independent Claude review held the initial candidate because pinned GoBGP accepts
a zero-length COMMUNITIES attribute and marshals it as null. An actual isolated
daemon confirmed this for both families through gRPC AddPath and CLI readback;
new raw captures record it without changing the original action captures.
`captured_empty_communities_do_not_establish_ownership` checks both captures.
`empty_community_is_foreign_and_does_not_block_other_withdrawals` failed on the
held candidate, then checks that valid null/empty community data remains foreign
while unrelated owned withdrawal progresses. Missing communities on a local type-8
attribute remain unknown and rejected; the pinned producer always emits the field.
`remote_metadata_does_not_block_local_reconciliation` also failed behaviorally on
the held parser using an existing peer path. It confirms
that known peer metadata cannot stall local withdrawal or become a local target.
These are producer-compatibility and consumer-boundary regressions, not a new
full-schema validator.

An invalid initial read permits no writes. An invalid post-write read does not
undo accepted CLI operations; it withholds a new observation. R1/R2 stale-count
and age semantics remain. This does not establish desired-set equality, atomic
IPv4/IPv6 reads, upstream enforcement or protection from concurrent writers.
GoBGP may accept foreign local metadata outside this parser's contract (for example
an IPv6 source offset above 128). Such local data stops the whole read/reconciliation,
including unblocking and shutdown attempts, until removed; peer metadata is excluded.
No checker, frozen fixtures/results or delivery-shadow pins change.

## FLOWSPEC-R5: read success is distinct from achieving the sampled target

An actual pinned GoBGP 4.9.0 experiment in
[the measurement record](measurements/2026-10-03-flowspec-convergence/README.md)
confirms that an ID-zero CLI withdrawal can exit zero without removing a same-tag
identifier-7 path. Both API and raw CLI observations are retained with a runnable
injector/runner. Deliberately reusing the CLI writer's community violates the normal
ownership assumption; it demonstrates the boundary, not a production incident.
R1's retained observation already avoids phantom disappearance. A completed read
can be healthy while the sampled target has not been reached.

`Readback` now includes a round-convergence bit, published with the observed counts
and read-start time. It is true exactly when owned == canonical-discard == the
round's wanted snapshot as prefix sets. Cardinality equality is insufficient.
Pending rounds revoke it before await; failure/cancellation cannot retain a true
bit. The renderer also requires enabled, readback success and an observation time.
Counts/time retain R1/R2 semantics. No new CLI call, operation, retry policy, quota,
shutdown budget or production permission is introduced.

`completed_reads_do_not_make_no_effect_writes_converged` checks acknowledged but
ineffective adds/deletes and equal-count wrong-prefix results through the production
CLI runner and worker-to-HTTP bridge. `round_convergence_tracks_prefix_sets_and_canonical_actions`
checks successful effect, unchanged/empty targets, wrong actions, repairs and
unwanted noncanonical paths. Initial versions of both regressions used the base API and metric lookups only,
and failed against the base on metric assertions, without compilation/import errors.
The later stale-main-snapshot mirror uses the new field and cannot compile against
the unchanged base; its semantic mutation is checked against the candidate. Existing pending/cancelled and
failed-readback controls additionally check revocation through the public view.
`convergence_requires_a_completed_enabled_observation` guards renderer inputs.

The real-daemon test delegates reads to GoBGP but uses controlled exit-zero no-op
write acknowledgements, recording and asserting each attempted add/delete per case.
For IPv4 and IPv6, healthy observations of missing desired
rules, retained unwanted rules and equal-count wrong prefixes remain non-converged.
Actual writes then restore the target and convergence, while the foreign path's
full raw response remains byte-identical after cleanup. Six direct-stdout positive
markers are required in canonical x86/ARM CI: existing action/refusal checks plus
round-convergence checks for each family. A skipped test is no proof. Native CI
uses the actual owners; local extraction retains audit/target/label stand-ins and
actual common code. Local checks passed 35 production-module tests and 14 Python
smoke/health refusal tests. Nine compiled Rust semantic mutants were rejected:
cardinality substituted for prefix equality, ownership substituted for action,
unwanted noncanonical paths ignored, unconditional CLI success/failure convergence,
retaining convergence during pending work, reusing the main tick, ignoring renderer
health and reusing the initial observation after writes. A tenth control bypassed
the actual HTTP consumer's convergence predicate and failed on its expected assertion.
The exact CI marker predicate accepts all six positive markers, refuses missing
family-specific convergence/refusal markers and rejects framework PASS after skip;
pipefail preserves nonzero cargo exit status through tee.

The HTTP smoke consumer adds a separate convergence expectation; a healthy read
alone remains a valid observation. Its live static-rule and recovery checkpoints
now require convergence, while failed/disabled checks require no false convergence.
Missing, duplicate, invalid or contradictory convergence samples are unverified.

Limits: this is equality with the target sampled for the completed round, not the
latest intent (which may have changed during/after its CLI calls), current freshness,
actual ID-zero identity, atomic family reads, exclusive/best-path selection,
downstream router enforcement or eventual progress. A consumer chooses an acceptable
age. Unverified/disabled zero does not establish a divergent RIB. Existing audit
records still acknowledge CLI operations, not observed postconditions. No new model,
checker, frozen evidence or delivery-shadow pin is needed for this bounded predicate.

## FLOWSPEC-R6: superseded intent interrupts pending reconciliation

Historical R6 implementation and evidence (#136); R7 below supersedes whole-round
intent cancellation. At base `3d078ed`, the worker awaited a whole sampled-target round before looking
for new intent or shutdown. Three regressions, initially using only the base API,
failed on actual obsolete CLI commands after compilation: a revoked target still
received an add, a restored target still received a delete, and shutdown still
allowed an add before cleanup. Controlled child reads paused before planning;
changing the desired set or shutdown then releasing the read exposed each write.

At #136, the worker selected shutdown and actual intent changes before polling the pending
round, drops that round and starts fresh reconciliation or the existing shutdown
cleanup. `update_wanted` compares full prefix sets before notifying the channel.
Identical main ticks do not cancel slow reads. A pre-existing shutdown flag or closed
intent/shutdown publisher starts cleanup instead of spinning or retaining old intent.
No operation or permission is added. Per-call timeout, withdrawal-first planning,
per-round quota, R1–R5 observations and the ten-second shutdown budget remain.

`superseded_read_cannot_announce_a_revoked_target` and
`superseded_read_cannot_withdraw_a_restored_target` cover the mirror cases through
actual child processes and the production worker.
`shutdown_interrupts_a_paused_round_before_obsolete_announcement` checks cleanup
starts while the old read is paused.
`identical_intent_ticks_do_not_interrupt_a_slow_round` checks the actual publication
helper, unchanged notifications and same-count/different-prefix changes.
`already_requested_shutdown_and_closed_publishers_start_cleanup` checks the
already-true flag and both closed-channel cases.

`live_gobgp_worker_preempts_intent_and_recovers_unknown_writes` executes the worker
against actual GoBGP 4.9.0 for both families. Controlled wrappers pause an initial
read or withhold a response after real GoBGP already applied an add/delete. The
test independently observes the committed effect before cancellation; a fresh
worker read then leads to the required opposite operation. Shutdown is checked
both during a read and after an accepted add. Each case checks successful recovery
and foreign raw RIB preservation. Canonical x86/ARM CI requires eight family-specific
positive markers, including both new preemption markers; a skipped test is no proof.
The full orchestrator smoke additionally holds one read for two seconds and requires
the original child to complete across unchanged main ticks, followed by verified
HTTP convergence. This binds publication deduplication to the actual main consumer.

Seven compiled semantic mutants were rejected on assertions: ignoring intent or
shutdown during a pending round, missing a pre-existing shutdown, notifying every
identical tick, deduplicating by cardinality, retaining the old target and restarting
old work after shutdown. Marker controls accept all eight positive markers and reject
removal of each family-specific marker, framework success after actual live-test
skip, and loss of a failed test's exit through tee. Local extraction passed all 41
production-module tests with actual common code and declared audit/target/label
stand-ins. Full final-head native x86/ARM CI and independent static review remain
separate required gates before merge.

Limits: the select boundary is cooperative; publication and CLI invocation are not
atomic. A command already accepted by GoBGP can take effect even when its local
future/child is cancelled. Cancellation is not rollback or evidence of no effect.
RIB readback, not arithmetic or a cancelled reply, determines the next plan.
That read is an observation, not a fence for a remote RPC still in flight: a request
sent by a direct/exec CLI can land after it. Shutdown can observe an empty RIB and
return success before a late add; it does not guarantee no rules after worker exit.
Kill-on-drop kills the direct subprocess, not its descendants. Wrappers must exec
the CLI; a non-exec child can land a late effect after a fresh read. The live wrapper
withholds its reply only after its real GoBGP subprocess has already completed.
A cancelled accepted command can have no CLI-acknowledgement audit record; these
records are not a complete effect history. Ongoing intent churn with slow GoBGP can
prevent every write as well as completed observations. Progress needs a stable
window; even normally fast calls with a large backlog and per-tick changes can
keep observation health revoked throughout an attack. Production shutdown sends
true (possibly repeatedly); at #136 a false notification also interrupted a round.
The window must allow the necessary calls; the 64-operation quota is per
round, not a rate budget across restarts. Cleanup is a bounded attempt, not guaranteed
withdrawal. Sampled-round convergence still does not prove latest intent, actual
path IDs, best-path selection or upstream enforcement. Checker, frozen captures,
results and delivery-shadow pins remain unchanged; ordinary regressions suffice
for this concrete worker scheduling contract.


## FLOWSPEC-R7: changing intent preserves useful reconciliation work

At base `163a802`, actual desired-set changes cancelled even a pending read or
still-valid operation. The new base-API regression
`changing_intent_keeps_the_pending_read_and_samples_latest_before_planning` failed
on an assertion: twelve publications launched twelve initial reads instead of one.
The mirror R6 no-obsolete-add/delete tests retain their refusal checks; their old
requirement to restart an initial read is replaced by retaining it and sampling the
latest target after both family reads. Shutdown still interrupts the initial read.

Fixed-target cleanup and live-intent work share `reconcile`: ownership/action
classification, collision exclusion, withdrawal-first planning, the 64-operation
quota and post-write readback stay in one implementation. Live rounds sample intent
after the initial two-family read. Every queued command checks current membership
before invocation. While its CLI future is pending, unrelated changes retain that
same future; an add whose prefix is revoked or a delete whose prefix is restored
cancels the command and requires a fresh RIB read before any replacement plan.
Initial and post-write reads survive desired-set changes. A completed observation
still compares with the round's sampled target, never with an invented latest-intent
postcondition. A changed target triggers another round immediately. True shutdown
or closed publishers still preempt all normal work; false shutdown notifications
leave the pending future intact.

`live_gobgp_worker_retains_useful_reads_and_valid_writes_under_intent_changes`
checks six controlled cases per family against actual GoBGP 4.9.0: retained initial
read, compatible add and delete replies, revoked queued add, restored queued delete,
and retained post-write read. Twelve publications alternate another prefix while
work is held. Exact call logs and original-child completion reject restart/duplicate
commands; the first retained read must directly plan the latest target without an
extra read. Queued mirror cases refuse obsolete commands even after a compatible
first command completes. Readback and an independent real CLI verify the final
owned and canonical-discard sets; shutdown removes owned paths and foreign raw RIB
bytes remain unchanged. Existing real R6 accepted-unknown-write reversals and shutdown
cases remain. At #137, canonical x86/ARM CI required ten family-specific positive markers.
The full orchestrator smoke also changes the actual block table during a second
held read, witnesses main publication through its following block-count snapshot,
and checks original-child completion, new discard propagation upstream,
HTTP convergence, operator-control ACK and subsequent withdrawal. The sensor-event
socket does not accept `UNBAN_IP`; revocation uses the actual operator socket.
Existing refusal controls include both
new upstream assertions; CLI failure/partial stdout cannot pass them.

The post-write publication regression separately verifies that a changed latest
intent does not alter the sampled-target comparison, and requests immediate
replanning. False shutdown notifications are included during the held-read churn.
Both the useful-read regression and an isolated compatible-write case fail on base
`163a802` after compilation. Six compiled semantic controls reject cancelling a
compatible command, retaining an invalidated pending write, launching an obsolete
queued write, sampling before the initial RIB read, ignoring pending shutdown and
comparing post-write RIB with latest rather than sampled intent. Marker controls
accept all ten positives and reject each missing marker, actual optional-test skip
and loss of a failing test exit through tee. Local extraction passes 44 Rust tests;
14 Python tests cover refusal at actual smoke call sites.

Local extraction uses actual production FlowSpec/metrics/common code with declared
audit/target/label stand-ins; full native Linux x86/ARM owners, XDP smoke, demo,
systemd runbook, independent exact-head static review and pinned Stargate shadow
remain separate gates before merge. No checker/model/frozen capture or pin changes.

Limits: compatible work can complete across changes; this is not unconditional
progress or eventual convergence under arbitrary churn. Changing the same prefix
can still invalidate every write; CLI failures, collisions and backlog still matter.
Completed counts/time can advance while immediate replanning has already revoked
health. Watch notifications can coalesce, so no intermediate-intent history or
atomic publication/CLI authorization is claimed. Cancellation is not rollback;
a fresh read is not a fence for a late remote RPC, and empty cleanup does not prove
absence after exit. Direct-child kill, sampled convergence, incomplete CLI-ACK audit
and bounded cleanup retain the R6 limits. No new authority or enforcement guarantee.

## FLOWSPEC-R8: a superseded prefix keeps the remaining original queue

At base `e1d2cfe` (#137), cancelling the first pending command abandoned the entire
plan. The base-API regression
`a_superseded_command_does_not_abandon_stable_queued_work` compiled and failed its
assertion: revoke and restore the held first prefix during recovery readback, and
the worker tries that first prefix again without reaching a stable second prefix.

Reconciliation now retains the finite initial withdrawal-first plan (at most 64
distinct NLRIs). An obsolete queued command has never started and is skipped.
Cancelling a pending command has an unknown effect: refresh both RIB families
before continuing. Each remaining command checks current membership, whether its
effect is still needed, and fresh foreign-local collision classification. Satisfied
work is skipped; a new collision cannot overwrite the foreign path, while other
queued work can continue. An unreadable refresh stops all subsequent writes and
preserves previous successful observation counts/time with health revoked.
Replacement commands belong to the next plan, after final readback. Supersession
forces that plan even when current intent equals the original sampled set (ABA).
No new persistent scheduling state, actor authority or additional planned writes.

The actual GoBGP 4.9.0 worker test
`live_gobgp_worker_keeps_stable_cohort_after_supersession` checks six cases in each
family: stable add, stable delete, stable add after cancelled delete, fresh foreign
collision, already-satisfied queued work and failed refresh despite valid stdout.
The held first call has not reached RPC in these cases; existing R6 tests separately
cover accepted unknown writes. Independent actual CLI readback, exact command logs
and raw foreign-family RIB comparisons check progress and refusals. The fixture
removes the intentionally held first prefix through a separate CLI before shutdown;
that is test cleanup, not evidence of worker withdrawal for that prefix.
A separate regression requires immediate retry after ABA. Local extraction passes
47 production FlowSpec/metrics tests with declared audit/target/label stand-ins.
Compiled controls must reject early abandonment, stale read reuse, ignoring fresh
collisions, duplicate satisfied commands and omission of the ABA retry. At #138, canonical
CI required twelve family-specific positive markers and rejects optional-test skip.
Full native Linux x86/ARM owners, 31 production smoke assertions, demo/runbook,
independent exact-head static review and unchanged pinned Stargate shadow remain
separate gates before merge. Existing 14 Python refusal checks remain.

Limits: this is consideration of the remaining original plan under readable RIB
and successful other CLI calls, not unconditional fairness or convergence. At #138, errors
still aborted the queue; continuously failing prefixes or backlog beyond the quota
can starve work. Each cancellation adds two reads; up to 64 cancellations give a
coarse `(2 + 64 + 128 + 2) × 5 s = 980 s` call bound. It is not a rate or latency
budget; shutdown still preempts the worker independently of main. Non-atomic RIB
reads, serialized-writer assumptions, sampled-target publication, coalesced watch
notifications, remote late RPC effects, direct-child kill, incomplete CLI-ACK audit
and bounded cleanup retain R6/R7 limits. No checker/model/frozen capture/pin change.

## FLOWSPEC-R9: isolate failed writes after readable recovery

At base `298f808` (#138), a failed first CLI write aborts the plan; every later
retry can fail on that same prefix without giving stable queued work a turn.
`a_failed_command_does_not_abandon_stable_queued_work` compiled and failed its
public-worker assertion on that base. The head tests both nonzero exit and actual
five-second call timeout (the wrapper execs the sleeping direct child).

The shared `reconcile` keeps the original withdrawal-first plan, still capped at
64 distinct NLRIs. A failed call may have been accepted remotely: refresh both RIB
families before considering the next command, then use the same current-membership,
needed-effect and foreign-local checks as cancellation recovery. A failed or malformed
refresh aborts all subsequent writes. Never retry the failed prefix inside this
plan. When reads succeed, return only the first write diagnostic, a count of failed
calls (at most 64) and the terminal collision count. A failed recovery
or final read returns its own read error immediately. Even if the final read sees the complete
sampled target, any failed call leaves the round in error. No completed publication,
no replacement counts/time and no health/convergence; only a subsequent fully
successful round can publish recovery. Failed CLI replies do not submit success ACK
audit records. Fixed-target cleanup shares this behavior but retains its ten-second
outer attempt budget and cannot claim complete withdrawal after exit.

`live_gobgp_failed_commands_preserve_safe_queued_work_and_refusals` runs eleven
cases per family on actual GoBGP 4.9: no-effect add/delete, accepted-but-error
add/delete, fixed-target cleanup deletion, fresh collision, already-satisfied queued
work, valid stdout with failed refresh status, malformed refresh, and obsolete
queued add/delete. It holds the first recovery read after the error, changes real
RIB or intent there, and awaits the actual live/fixed round result. Exact CLI logs
require the original failed write once, two family reads before any next command,
and no obsolete/duplicate/colliding write. Independent actual RIB owned/discard sets
check effects; failed-round result and readback verify retained count/action-count/time
with health and convergence revoked, even when accepted errors achieved the target.
A separate real-CLI successful round publishes recovery. Cleanup removes owned paths;
raw foreign-family bytes match the foreign-only snapshot afterward. Native CI uses
actual worker/database owners; local extraction declares audit/target/label stand-ins.
The worker fixture retains one shared audit owner for its baseline and running
worker: reopening the log before its writer exits is refused by the native lock.

Local extraction passes 49 production FlowSpec/metrics tests. Compiled controls must
reject aborting the queue, omitting recovery reads, ignoring fresh collision or
satisfied/obsolete predicates, hiding the failed-call result and ignoring read
failure. Canonical CI requires fourteen family-specific positive markers, with
missing-marker, actual optional-test skip and failing-exit-through-tee controls.
Full native x86/ARM build/tests/Clippy, 31 production smoke assertions, 14 Python
refusal checks, XDP smoke, three-node demo and systemd runbook, independent exact-head
static review and unchanged pinned Stargate shadow remain gates before merge.

Limits: progress only for remaining work in the finite original plan, provided
reads are valid and remaining CLI calls can finish. Invalid reads still abort;
backlog outside the quota, no-effect successful commands, slow calls and concurrent
writers retain their limits. At most 64 combined failures/cancellations add 128 reads:
`(2 + 64 + 128 + 2) × 5 s = 980 s` is a coarse call-wait allowance for live or fixed
rounds with errors, not a deadline/rate limit. Scheduling/teardown are outside it;
shutdown preempts normal work and bounds cleanup independently. Failed rounds use
existing outer scheduling, not immediate internal retries; watch activity can still
accelerate them. No new authority, atomic authorization, RPC fence, complete effect
audit, unconditional fairness/convergence or proof-core/model/pin change.


## FLOWSPEC-R10: pace failed rounds without delaying shutdown

At base `078a630` (#139), the public worker's interval retains overdue ticks and
intent notifications can immediately begin another failed round. The log's
“retrying every second” therefore did not specify the actual behavior.
`failed_rounds_wait_despite_intent_churn` and
`failed_rounds_wait_despite_overdue_ticks` compile against that base and fail on
actual child-call counts, not imports. The real GoBGP regression also fails its
no-early-calls assertion on the base.

After any failed normal round, `run_worker` now waits at least one second from
completion before permitting another normal reconciliation. The same sleep future
survives intent churn and false stop notifications, so neither can shorten or
restart the deadline. No CLI call is started during the pause. The next round
samples current intent through the existing live path; it never resumes a saved
failed target. Successful rounds and immediate supersession replanning retain
existing scheduling. Any true shutdown or closed shutdown/intent publisher wins
the biased pause select and begins cleanup, without awaiting the retry deadline.
Cleanup retains its separate ten-second budget and existing 500-ms error pauses.
Health/convergence stay revoked and the last completed counts/time survive the
pause. Logging reports the minimum pause accurately.

The public-worker fixtures hold an actual failing read, optionally accumulate a
1.2-second overdue tick, then keep publishing intent and false shutdown updates.
They require one call during the early window, a retry after at least 900 ms
(the one-second policy allows 100 ms observation tolerance), and progress within
1.6 seconds while notifications continue. They abort their deliberately failing
worker afterward; cleanup is checked independently with real GoBGP.
`live_gobgp_retry_pause_keeps_latest_intent_and_preempts_for_cleanup` uses actual
GoBGP 4.9, one shared native audit owner, and four cases per IPv4/IPv6 family:
overdue ticks plus intent churn, true shutdown, closed shutdown publisher and
closed intent publisher. It requires no early calls, recovery to the latest owned
discard set without an obsolete add, previous failed-round counts/time, and real
owned-rule withdrawal in less than 750 ms for all three stop cases. Foreign-only
family bytes must remain unchanged. The first failing child marker precedes its
exit; timing windows are runtime regression evidence with tolerance, not an
exact real-time theorem. Scheduler load can lengthen waits; the implementation
uses Tokio's monotonic sleep, not a bound on scheduling latency.

Local extraction exercises 52 actual FlowSpec/metrics tests with actual common
and audit-writer code; target parsing and mesh labels remain declared stand-ins.
Compiled controls reject missing/shortened pauses, intent bypass, treating false
notifications as shutdown, non-preemptible waiting and ignored publisher closure.
Canonical CI requires sixteen family-specific positive markers; all previous
native x86/ARM, 31 production smoke assertions, 14 Python refusal checks, XDP,
demo/runbook, independent exact-head review and frozen Stargate gates remain.

Limits: this is a failed-round retry floor, not a global CLI rate limit, fairness
or convergence guarantee. Each failed round can still issue the bounded original
plan plus recovery reads. No new backoff policy, write authority, remote RPC
fence, complete effect audit, checker/model/capture/pin or cleanup guarantee.


## FLOWSPEC-R11: rotate finite quota opportunities across rounds

Base `594e585` (#140) sorts every new plan and truncates at 64. When those first
64 prefixes keep failing or acknowledge writes without changing the RIB, a 65th
eligible prefix never gets a command. Five `quota_rotation_serves_*` public-worker
regressions compile on that base and fail the actual tail-service assertion:
announce/withdrawal, each with successful no-effect or failed CLI replies.

The worker retains two `Option<IpNet>` ordering boundaries, one per operation
class. Every new plan still derives from fresh two-family RIB reads and sampled
intent, excluding known foreign-local collisions before quota. Sort each class,
rotate to the first prefix greater than its cursor (wrapping at the end), and
apply the same combined quota of 64 with strict withdrawal priority. Advance the
relevant cursor only when a specific queued candidate is considered, before any
cancellable work or skip predicate. Failed recovery, final reads and cancelled
calls do not reset it or skip an unvisited suffix. Invalid initial reads advance
nothing. No per-prefix failure cache or queued target survives the round; the
cursor grants no authorization and asserts no effect. Every command still checks
current membership, needed effect and fresh foreign-local collisions. The worker
shares its cursor with fixed-target shutdown retries. Public one-shot `plan` preserves sorted behavior. The standalone round helpers
start with fresh cursors and are gated by `#[cfg(test)]`: production callers
cannot accidentally choose a round path that discards persistent cursor state.

For an unchanged finite eligible class with positive available quota and rounds
that reach its candidates, circular ordering gives each prefix an opportunity.
The 65-prefix complete-plan case reaches its tail first in round two. This is
conditional service, not unconditional fairness, success or a wall-clock bound:
announcements get no slots while at least 64 eligible withdrawals persist;
invalid reads, churn, restart, no-effect/slow calls and competing writers retain
their limits. State resets on worker restart. Fixed-target cleanup retains its
10-second budget, which may expire before useful progress. R10's failed-normal-
round pause and all readback/ACK/ownership limits remain unchanged.

`rotating_plans_preserve_quota_priority_and_wrap_stale_cursors` checks both
classes over quota, strict withdrawal priority, removed-cursor wrapping and
one-shot compatibility. `a_failed_recovery_advances_only_the_considered_prefix`
uses actual child processes to reject jumping over an unvisited plan after a
malformed recovery and to require no movement after invalid initial reads.
The four normal public-worker fixtures independently verify the 65th command and its
RIB effect, then abort their deliberately stuck workers; they make no cleanup
claim. `quota_rotation_serves_cleanup_within_its_existing_budget` starts the
actual worker with shutdown already true, requires tail service through fixed
cleanup retries, then independently clears the deliberately stuck fixture RIB
and requires the worker to finish. It checks cursor retention and bounded exit
after controlled fault removal, not guaranteed cleanup under persistent failure.

`live_gobgp_quota_rotation_serves_tails_and_revalidates_new_plans` runs eight cases
per actual GoBGP 4.9 family: no-effect/failed add and delete, fixed-target failed
delete, fresh foreign tail and obsolete tail add/delete. Two awaited rounds share
one cursor and native audit owner. Exact logs require 64 distinct commands per
round and the tail first in the second normal plan, or no tail command after a
foreign/intent change. Independent owned/discard sets verify effects; failures
retain the previous completed counts/time, and partial successful rounds never
certify convergence. The real CLI separately removes fixture-owned rules; raw
foreign-only family bytes must match. This does not claim that the deliberately
blocked worker's bounded cleanup can always withdraw them.

Local extraction runs 60 actual FlowSpec/metrics tests with actual common and
audit-writer code and declared target/mesh-label stand-ins. Compiled controls
must reject reset cursors, missing rotation, jumping unvisited work, reversed
class priority and ignored authority predicates. CI requires eighteen positive
family markers, with missing-marker/skip/tee controls, full native x86/ARM owners,
31 production smoke assertions, 14 Python refusal checks, XDP, demo/runbook,
independent exact-head review and unchanged pinned Stargate gates before merge.
No checker/model/frozen capture/pin, durable authority or new concurrency fence.

## FLOWSPEC: verification notes, R12 and R13 (moved from ADR-0008)

Moved verbatim from ADR-0008 on 2026-10-05 so the ADR states the decision and this ledger
holds the boundaries (review 2026-10-05, W2.2). Ukrainian as written.

- FLOWSPEC-R3 перевіряє rate-limit → discard, прибирання непотрібної неправильної
  дії й відмову при чужій локальній колізії на справжньому GoBGP 4.9.0, IPv4 та IPv6.
  `SOKOL_GOBGP_TEST_BIN` обов’язковий у canonical CI на x86 та ARM; локальний skip
  не є підтвердженням виконання. Деталі й межі — у розділі FLOWSPEC-R3 вище.

- FLOWSPEC-R4 додає регресії для missing/null stdout, структури шляхів і полів
  ownership. Справжній GoBGP з чужим локальним шляхом та контрольоване спотворення
  тільки CLI read перевіряють відмову без записів для обох сімейств. Canonical CI
  вимагає окремий позитивний marker цієї перевірки в кожному сімействі.

FLOWSPEC-R6 (#136) додав переривання pending round при зміні wanted чи shutdown
і publication тільки змінених prefix sets. FLOWSPEC-R7 уточнює межу переривання:
RIB reads зберігаються, перед плануванням читається актуальний desired set, а
кожна queued/pending команда дозволена лише за актуальним membership її prefix.
Несуперечливі зміни зберігають той самий CLI future; недоречна команда скасовується,
перед наступним планом заново читається RIB. Post-write read також завершується;
convergence стосується sampled target; наступний раунд за зміненим intent починається
після 1 s паузи FLOWSPEC-R12.
FLOWSPEC-R8 зберігає решту початкової черги після скасування pending команди:
перед продовженням читає обидва RIB, перевіряє актуальний membership, потребу в
дії та нові чужі локальні колізії. Уже недоречна queued команда, яка ще не
починалась, просто пропускається. Заміну для скасованого prefix планує наступний
раунд; він потрібний і при поверненні desired set до початкового (ABA).
Непридатне свіже читання зупиняє подальші записи й зберігає попередні counts/time
із health 0. Це прогрес тільки в межах початкової черги до 64 різних prefixes
за придатних читань та успішних інших команд. Помилки CLI, backlog за квотою та
конкурентні writers лишаються межами; загальної гарантії справедливості немає.
До 64 скасувань можуть додати 128 read calls: груба верхня оцінка
`(2 + 64 + 128 + 2) × 5 s = 980 s` на live round, а не цільова latency.
Worker окремий від main tick, shutdown перериває цей раунд.
Shutdown true, already-true flag і закриття publisher переривають normal work та
починають наявну десятисекундну спробу cleanup; false не скасовує роботу.
Це не atomic revocation, rollback чи fence для remote RPC, який може застосуватися
після нового читання навіть при direct/exec CLI. Порожній cleanup read перед пізнім
add не гарантує відсутності правил після виходу. Wrappers мають `exec` CLI, бо
kill-on-drop завершує прямий child, не process tree. Скасована відповідь прийнятої
команди може не залишити ACK-аудиту. Збереження корисних calls не гарантує eventual
convergence при безперервній зміні того самого prefix; counts/time можуть
зберігатись при початку наступного раунду з health 0. Квота 64 є per-round,
не лімітом частоти між раундами. Ownership, policy і повноваження ті самі.


FLOWSPEC-R9 продовжує початкову чергу й після помилки окремого CLI запису:
відмова, timeout чи помилка запуску не означають відсутності ефекту. Перед
наступною командою worker заново читає обидва RIB і перевіряє актуальний membership,
потребу в дії та чужі локальні колізії. Непридатне recovery-читання зупиняє записи.
Навіть коли наступні команди успішні або відмовлена команда вже мала ефект,
раунд повертає помилку: попередні counts/time зберігаються, health/convergence — 0.
Лише наступний успішний раунд публікує відновлення. За придатних читань діагностика
містить першу помилку запису, кількість невдалих команд і пропущених колізій; невдалий запис не отримує ACK-аудиту.
Непридатне recovery або final read повертає власну помилку читання одразу.
Той самий шлях використовується у cleanup, але його бюджет лишається 10 секунд.
До 64 сумарних скасувань або помилок дають до 128 додаткових read calls;
оцінка 980 секунд стосується також fixed-target раунду з помилками, а не його
cleanup deadline. Квота, withdrawal-first, політика й повноваження не змінені.
Це прогрес решти поточного плану за придатних читань, не загальна справедливість:
непридатні reads, довгі calls, backlog за квотою та конкурентні writers лишаються
межами. FLOWSPEC-R10 витримує щонайменше секунду після завершення невдалого
normal round, перш ніж знову дозволити reconciliation. Накопичені timer ticks,
зміни наміру й false shutdown notifications не скорочують і не перезапускають
паузу. Наступний раунд бере актуальний desired set. True shutdown або закриття
будь-якого publisher перериває паузу й одразу починає окремий bounded cleanup;
його 10-секундний бюджет і власні 500-мс error pauses не змінені. До FLOWSPEC-R12 успішні раунди
й перепланування supersession не отримували цієї затримки. Це мінімальна пауза
між невдалим normal round і наступним, не ліміт calls/second: одна черга все ще
може містити 64 записи та їх recovery reads. Remote RPC може мати пізній ефект;
читання не є rollback чи fence, CLI-ACK audit не є повною історією ефектів.


FLOWSPEC-R11 ротує prefixes усередині withdrawal та announce між раундами.
Два worker-local курсори тримають останній розглянутий prefix кожного класу;
після нього новий відсортований набір обходиться по колу. Вони не кешують RIB,
дозвіл чи результат дії. Worker зберігає їх після успіху, помилки й supersession
та використовує у bounded cleanup. Курсор рухається при розгляді конкретного
запису перед cancellable роботою; рання відмова readback не перескакує нерозглянуту
решту плану. Непридатне початкове читання не змінює курсори. При restart вони
скидаються; жодна нова черга не використовується без придатних RIB reads.
Квота 64, withdrawal-first і всі перевірки актуального membership, потреби та
чужих колізій лишаються. Публічний one-shot `plan` зберігає відсортований початок.
Це умовна можливість спроби для скінченного стабільного набору всередині класу,
не гарантія ефекту: якщо withdrawals постійно займають всю квоту, announces
чекають. Непридатні reads, нескінченна зміна наборів, повільні calls і restart
можуть перешкодити прогресу; cleanup має той самий 10-секундний бюджет.

### FLOWSPEC-R12 — витрати роботи й спостережений поступ

Worker більше не накопичує interval ticks: після кожного завершеного normal round
витримує одну монотонну паузу 1 s. Успіх CLI, відсутність ефекту, помилка та
supersession споживають той самий дозвіл на раунд. Зміни wanted і false shutdown
не скорочують і не перезапускають паузу; наступне читання знову бере актуальний
intent. Перша спроба не затримується. True shutdown та закриття будь-якого publisher
одразу переривають normal work/паузу й починають cleanup. Cleanup зберігає власний
deadline 10 s та cursor; після кожного непорожнього успішного раунду або помилки
чекає 500 ms усередині deadline. Підтверджений порожній owned RIB завершує його
без паузи. Так no-effect success не перетворюється на гарячий цикл. Ціна цього
обмеження — менше withdrawal batches за ті самі 10 s, ніж при негайних повторах
успішних раундів; залишкові правила потребують окремої перевірки RIB.

Операційна ціна лишається конкретною: до 64 кандидатів за раунд, ліміти CLI calls
і наведені вище read/recovery allowances. Це не універсальна ATP-валюта, не
глобальний calls/second чи memory bound, не довічна квота daemon і не стійкий
до restart облік. Worker-local паузи не обмежують іншого writer. Shutdown cleanup
має незалежний дозвіл; припинення child process не відкликає прийнятого RPC.

`sokol_flowspec_round_progress`: `1` — між initial/final reads раунду спостережено
строге зменшення набору невиконаних вимог до sampled wanted без нових; `0` — такого
поступу не спостережено; `-1` — немає придатного завершеного виміру. Вимоги
розрізняють видалення owned prefix поза wanted та встановлення canonical discard
для wanted prefix. Порівнюються ідентичності й типи дій, а не лише counts:
перестановка однакової кількості prefixes або менша кількість із новою помилкою
не є поступом. Pending/failure/cancellation відкликають значення до першого await;
повні initial/final reads одного раунду визначають вимір. Ефект не приписується
командам цього раунду: пізній раніший RPC або інший writer також можуть зменшити
розбіжності. Failed CLI навіть після
реального ефекту не публікує нового виміру. Уже досягнута ціль може мати progress 0
і convergence 1. Інший sampled target, міжраундовий поступ, latest intent, причини
застою, неминуче завершення та upstream enforcement цим не встановлюються.
Перевіряйте health, convergence і age разом; універсального stall-порога немає.

Перенесено дисципліну бюджету Sigma-Glyph (додатна ціна дії, перевірка допустимості
перед дією, окрема причина завершення) і Black-Heart (накопичені витрати при resume,
resource exhaustion не є semantic refutation, null measurement не є нулем).
Це незалежна реалізація для мережевих спроб: на відміну від незарядженої невдалої
редукції, мережеві помилки також витрачають роботу. Lean-теореми Sigma-Glyph про
терми й ATP не доводять властивостей цього Rust worker. Джерела перенесення:
Sigma-Glyph `f46a7460b4ca2731899a61725cb5cc15ff0bac46`, `impl/sigma_glyph.py`;
Black-Heart `63649b8`, `glyph.py`, `scoped_admission.py`, `library_interaction.py`.

Перевірки: `successful_no_effect_rounds_wait_despite_intent_churn`,
`successful_no_effect_rounds_wait_despite_overdue_ticks`,
`superseded_success_shares_the_work_pause`,
`successful_no_effect_cleanup_waits_and_then_recovers`,
`round_progress_requires_strict_identity_and_action_improvement`,
`progress_distinguishes_unmeasured_from_zero_and_requires_health` і
`live_gobgp_work_budget_paces_success_and_cleanup_with_truthful_progress`.
Перші чотири виконувані регресії компілюються на base `c62437f` і падають на
кількості ранніх спроб. Live test використовує pinned GoBGP 4.9.0 для обох сімейств:
no-effect add/delete, supersession, справжнє відновлення, cleanup, true shutdown та
обидва закриті publishers; foreign paths перевіряються окремо. Раннє завершення
cleanup у stop-сценаріях є результатом контрольованого усунення no-effect fault,
не гарантією виконання під постійною відмовою. CI вимагає positive marker кожної
сім'ї, повні native x86/ARM jobs і незмінені frozen Stargate checks.

### FLOWSPEC-R13 — початковий намір після відновлення

Main створює FlowSpec watch-channel зі snapshot `BlockTable::active_ips()` під
тим самим lock, до spawn worker. Static configuration та state restore вже
застосовані. Попереднє початкове `{}` вигадувало відсутність блоків: worker міг
прочитати RIB і відкликати ще потрібні owned правила до першого main tick,
а пізніша публікація знову їх анонсувала. Це scheduling-dependent вікно відтворено
на фактичному worker і GoBGP 4.9.0 без main-loop публікацій.

Джерело залишається застосованим набором, як у наступних tick publications:
не всі durable claims і не число успішних restore. Відхилені політикою,
прострочені та pending kernel-map additions не анонсуються. Дійсно порожній
applied set усе ще відкликає старі owned правила. Чужі локальні paths, shutdown,
observe-mode заборона worker, quota/cursors та pacing не змінюються.

Snapshot не є атомарною угодою між BlockTable, RIB і upstream. Зміни після його
створення потрапляють у звичайну публікацію; цей крок не робить її миттєвою.
Не гарантується відсутність усіх можливих флапів, новий durable intent, успішне
state restore чи upstream enforcement. Failed restore лишає наявну DEGRADED
семантику: старт із тим applied set, який вузол реально має.

Регресії `startup_worker_keeps_restored_blocks_and_announces_static_before_any_tick`,
`startup_worker_with_no_applied_blocks_withdraws_stale_owned_rules` та
`live_gobgp_startup_preserves_applied_restoration_before_any_tick` використовують
фактичні BlockTable serialization/restore, production channel initializer і worker;
лише kernel-map operations у unit tests замінені. Live test перевіряє обидві
сім'ї, retained/static, refused/expired/unapplied/stale, порожній applied set,
наступний intent, cleanup та незмінний foreign RIB. CI вимагає обидва positive
markers. Production XDP smoke додатково перезапускає справжній вузол із тим самим
state file, перевіряє XDP/RIB/HTTP і записує worker CLI calls, щоб delete/re-add
не приховався за пізнішим успіхом; fresh-state stale cleanup лишається окремим.
