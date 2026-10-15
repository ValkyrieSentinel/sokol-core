# Replay floors across a restart (2026-10-15)

Lab VM: aarch64, 10 vCPU, kernel 6.8, XDP `generic`; 3 nodes in network namespaces. Base
`3f8a5e8` with the change of ADR-0029.

```
sudo bench/mesh.sh floors <orchestrator> <monitor> 3
```

```
# full mesh after 1s: 3/3 nodes see 2 peers
# node 1 saved floors (sender:ms): 2:1792023874805 3:1792023875821; now 1792023879870
PASS F1 node 1's state file holds a current floor for nodes 2 and 3
PASS F2 after the restart node 2's new decision reaches node 1 (3 blocks)
# node 1 floors after the restart: 2:1792023885079 3:1792023884274
PASS F3 every floor is carried on, none lowered
```

Control: the same run with the registry not handed to the state writer (`REPLAY_FLOORS` unset in
`main`) gives `FAIL F1 floors in node 1's state: none` and `FAIL F3`; F2 passes either way (the
floors cost honest peers nothing).

Not measured here: an on-path replay of a captured frame. The unit witness
`saved_floors_refuse_what_the_previous_process_accepted_after_the_start` covers the refusal on
the registry the node runs.
