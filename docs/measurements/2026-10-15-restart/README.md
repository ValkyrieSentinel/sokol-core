# Recovery after a crash (2026-10-15)

Lab VM: aarch64, 10 vCPU, kernel 6.8, XDP `generic`; nodes in network namespaces. Main
`511014a` plus the `restart` mode of `bench/mesh.sh`.

```
sudo bench/mesh.sh restart <orchestrator> <monitor> 3 10                    # restart-3.txt
sudo bench/mesh.sh restart <orchestrator> <monitor> 10 10                   # restart-10.txt
sudo RESTART_CONTROL=1 bench/mesh.sh restart <orchestrator> <monitor> 3 3   # restart-control.txt
```

Each round: a detector block on node 1 is on disk; the attacker pings node 1 every 10 ms;
node 1 is SIGKILLed and started again at once (no systemd `RestartSec`). Limits fixed before
the first run: X1 control socket answers <= 10 s, X2 the block holds again <= 10 s and the
attacker gets no reply in the last second of the probe, X3 all peers back <= 30 s.

| Run | Control answers | Attacker's last reply | All peers back | X1–X3 |
|---|---|---|---|---|
| 3 nodes, 10 rounds | 116–163 ms | 36–80 ms | 121–1118 ms | PASS |
| 10 nodes, 10 rounds | 115–133 ms | 36–54 ms | 1054–1110 ms | PASS |
| control (block lifted before the kill), 3 rounds | 115–154 ms | 2114–3111 ms | 119–1115 ms | X2 FAIL, as intended |

The attacker's window is the time from the kill until the new process enforces the restored
block. The ~1 s peer steps are the dialer's reconnect. With the unit's `RestartSec=2s` add
2 s to every column. Used by ADR-0031 (RTO).
