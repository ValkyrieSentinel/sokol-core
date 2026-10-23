# How long each layer keeps blocking after a block ends (2026-10-15)

Lab VM: aarch64, 10 vCPU, kernel 6.8, XDP `generic`; 3 nodes in network namespaces; node 1
announces FlowSpec to a GoBGP 4.9.0 pair (node and upstream) as in `scripts/xdp-smoke.sh`. A fresh
attacker address per round pings every node every 10 ms; every time is counted from node 1's
audit record of the end decision. Base `9387b10`; the fixes below are in the same change.

```
sudo bench/mesh.sh unblock   <orchestrator> <monitor> 3 20     # run1.txt
sudo bench/mesh.sh relapse   <orchestrator> <monitor> 3 10     # relapse-*.txt (RELAPSE_WAY=retract|unban)
sudo bench/mesh.sh bulkflush <orchestrator> <monitor> 3 3000   # bulkflush-*.txt
```

| end (record) | node 1 XDP | peers' XDP | node's RIB | upstream RIB |
|---|---|---|---|---|
| detector RETRACT | 0 / 5 / 11 / 13 ms | 1 / 6 / 10 / 12 ms | 854 / 975 / 1060 / 1072 ms | 858 / 981 / 1066 / 1079 ms |
| operator UNBAN | 0 / 5 / 11 / 11 ms | 0 / 5 / 10 / 12 ms | 867 / 986 / 1067 / 2007 ms | 865 / 991 / 1074 / 1949 ms |
| operator FLUSH | 0 / 6 / 10 / 10 ms | 1 / 6 / 11 / 12 ms | 844 / 961 / 2012 / 2026 ms | 848 / 966 / 2018 / 2032 ms |
| lease expiry | 0 / 5 / 11 / 12 ms | 33 / 43 / 51 / 59 ms | 61 / 389 / 950 / 959 ms | 68 / 395 / 956 / 964 ms |

(min / median / p95 / max, 20 rounds, 40 peer observations.) Expiry itself is recorded 23–966 ms
after the signed end: the 1 s tick. A stalled GoBGP (SIGSTOP 7 s) withdraws 85–109 ms after it
resumes; a node killed between lift and withdraw removes the rule 174–187 ms after its restart; a
flush of 1000 blocks leaves the peers clear in ~1 s and the node's RIB in 21.8 s (64 withdrawals
per round). No run left a layer blocking 20 s after an end.

## Defects found and fixed here

- **A retraction answered `OK lifted` came back after a crash** (`relapse-base-retract.txt`: 10 of
  10 rounds blocked again after SIGKILL and restart; with FlowSpec on, the rule was still announced
  20 s after the restart). The answer came before the state was on disk, and the detector's outbox
  takes `OK lifted` as final, so ADR-0004's "detectors resend" premise failed. The retraction now
  waits for disk like an operator decision (R26-04); `relapse-fix-retract.txt`: 0 of 10.
- **A large retraction was one frame peers refuse** (`bulkflush-base.txt`: past ~1,900 own claims
  the Retract exceeded the transport limit; peers dropped the connection and the retraction with
  it). Retractions are now packed like snapshots (`bulkflush-fs-fix.txt`).

## Bounds the code guarantees

- **Local XDP after a retraction, unban or flush:** the kernel entry is deleted in the table step
  that records the end; a failed delete is retried every 1 s tick (at most 256 targets per tick,
  oldest first) and shown as pending.
- **Local XDP at expiry:** the end on the table's clock plus one tick period and the tick's duration.
- **FlowSpec in the node's RIB:** about ⌈n/64⌉ reconciliation rounds after the next tick; a round is
  the 1 s pause plus its reads and writes, each call bounded by the 5 s call timeout. Requires the
  worker to run (after a crash: once the node restarts) and GoBGP to answer.
- **Peers:** a delivered Retract within network time; a lost one within two digest periods (30 s)
  plus the snapshot, while digests get through; a lost connection after the reconnect back-off.
  Hard cap in every case: the peer's own end of the claim (its lease cap, ADR-0003).

## Closed candidate

A node that restored its state with a clock behind true time and was later stepped forward (the
RTC-less case of ADR-0017) kept restored own claims past their signed end by the clock error;
peers dropped them at the signed end. Capping a restored end at now plus its full duration does
not close it — with the clock behind, now plus the duration is past the true end. The state file
now carries its write time, and a restored end is capped at now plus what it had left at that
write: both differences are on one clock, so the clock's error drops out and the overshoot is at
most the downtime (ADR-0017, amendment of 2026-10-15).
`a_restore_under_a_clock_behind_does_not_outlast_the_signed_end` reproduces the defect and now
passes.
