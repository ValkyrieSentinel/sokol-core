# Sokol-Core 🛡️

> **Status:** Pilot / Active Testing

A high-performance network security and traffic filtering system running at the Linux kernel level. Built entirely in **Rust** (eBPF/XDP kernel program and user-space daemon).

The program intercepts and drops garbage (attacks, malicious traffic) right at the network interface card before it even reaches the OS. Blocks, trap hits and kernel drop events are recorded in an append-only, hash-chained audit log.

---

## Requirements

- **OS:** Linux kernel 5.15+ (with an XDP-compatible NIC driver)
- **Toolchain:** 
  - Rust Nightly (needed for building eBPF target `bpfel-unknown-none`)
  - [`bpf-linker`](https://github.com/aya-rs/bpf-linker) (links the eBPF object)
  - A C compiler (`gcc` or `clang`; `pqcrypto-dilithium` builds C sources)

---

## Build & Run

Clone the repository:

```shell
git clone https://github.com/ValkyrieSentinel/sokol-core.git
cd sokol-core
```

Build the eBPF program first. The orchestrator embeds the compiled object
(`target/bpfel-unknown-none/<profile>/ebpf-probe`), so this step must come before the Rust build:

```shell
cd ebpf && cargo +nightly build --release && cd ..
```

Build the orchestrator and tools:

```shell
cargo +nightly build --release
```

Run the tests and the XDP smoke test (Linux, root: creates a veth pair in a network namespace):

```shell
cargo +nightly test --release
sudo scripts/xdp-smoke.sh target/release/orchestrator
```

Run as root for a quick test (for production use the systemd unit below, which runs unprivileged):

```shell
sudo ./target/release/orchestrator
```

## XDP modes and NIC drivers

`--xdp-mode` chooses how the filter attaches:

- `native` — runs in the NIC driver before any socket buffer is allocated. This is the mode that
  sustains line-rate drops. Attach fails if the driver has no XDP support.
- `generic` — runs after the kernel built an skb. Works on any interface but costs roughly as
  much per packet as iptables; use it for testing or unsupported NICs.
- `auto` (default) — the kernel uses native if the driver supports it, otherwise generic.

Check what you got:

```shell
ip -d link show dev eth0 | grep -o 'xdp[a-z]*'   # "xdp" = native, "xdpgeneric" = generic
ethtool -i eth0 | grep driver                    # driver name
```

Drivers with native XDP include `mlx5_core`, `mlx4_en`, `i40e`, `ice`, `ixgbe`, `igb`/`igc`
(recent kernels), `bnxt_en`, `nfp`, `ena`, `virtio_net`, `veth`, `tun`. Some need a driver-specific
setting: `virtio_net` needs enough queues (`ethtool -L eth0 combined <n>`), `ena` needs an MTU
at or below its XDP limit, and several drivers refuse XDP with jumbo frames or LRO enabled
(`ethtool -K eth0 lro off`). Start the service with `--xdp-mode native` in production so a
driver problem fails loudly instead of silently falling back to generic mode.

`sokol_blocks_active{family=...}` and `sokol_blocks_capacity` (65 536 per family) show map
usage; crossing 80% is logged and recorded in the audit log.

## Mesh peers

Nodes accept mesh commands (e.g. `BlockIp`) only from peers whose public key is pinned in a
peers file. Without `--peers-file` the mesh rejects every peer.

Each node keeps its identity key in `--key-file` (default `/var/lib/sokol/node.key`, created
with mode `0600` on first start). Print a node's public key:

```shell
sudo ./target/release/orchestrator --print-public-key
```

Collect the keys into a peers file on every node:

```json
[
  { "node_id": 2, "public_key": "<hex from node 2>" },
  { "node_id": 3, "public_key": "<hex from node 3>" }
]
```

```shell
sudo ./target/release/orchestrator -i eth0 --node-id 1 --peers-file /etc/sokol/peers.json --seed-peer 10.0.0.2:7946
```

To rotate a node's key without downtime:

1. Generate the new key: `orchestrator --key-file /var/lib/sokol/node.key.new --print-public-key`.
2. On every peer, list both keys for that node — `{"node_id": 1, "public_keys": ["<old>", "<new>"]}` —
   and apply it with `printf 'RELOAD_PEERS\n' | nc -U /run/sokol/control.sock`.
3. Move `node.key.new` over `node.key` and restart that node.
4. Remove the old key from every peers file and send `RELOAD_PEERS` again. Open connections that
   still sign with the removed key are closed on their next message.

A peers file that fails to parse is rejected and the previous trust stays in force.

### Encrypt the mesh with WireGuard

The mesh protocol authenticates but does not encrypt. Run it inside a WireGuard tunnel between
the nodes (see `deploy/wireguard-mesh.conf.example`) and bind the P2P listener to the tunnel
address only, e.g. `--p2p-bind 10.99.0.1:7946 --seed-peer 10.99.0.2:7946`. The smoke test runs
two nodes this way. Add every peer's tunnel address to `--never-block`.

### Cluster telemetry

Every 5 s each node sends its peers a signed load report (packets and drops per second, active
blocks, and whether drops exceed `--attack-drops-per-sec`, default 1000). A node may only report
about itself. Nodes silent for 15 s drop out of the view. The cluster status is:

| nodes under attack                          | `sokol_cluster_status` |
|---------------------------------------------|------------------------|
| no reports                                  | 0 unknown              |
| none                                        | 1 stable               |
| some, at most `--storm-threshold` (0.5)     | 2 local incident       |
| more than `--storm-threshold`               | 3 distributed storm    |

A storm engages a latch at once (logged and audited); the latch disengages only after 30 s
without a storm, so a flickering storm is one event. Reports travel only between directly
connected peers, so connect the nodes as a full mesh (`--seed-peer` to every other node).

Envelopes are signed over sender, timestamp, nonce and payload; they are rejected outside a
±30 s clock window (keep nodes NTP-synced) and accepted at most once. Mesh traffic is
authenticated but not encrypted.

## Signals from detectors (Suricata)

Sokol enforces decisions made by detectors you already run. `sokol-suricata` follows Suricata's
EVE log and sends each alert at or above `--max-severity` (default 2) to the node as a signal:

```shell
sokol-suricata --eve /var/log/suricata/eve.json --ipc-socket /run/sokol/sokol.sock
```

The node blocks the offending address in XDP, shares the block with its mesh peers and records the
rule in the audit log (`suricata: sid:<id> <signature>`). If the alert fired on this node's own
outbound traffic, the remote destination is blocked instead; the never-block policy still applies.
The same address is not re-sent within `--cooldown-secs` (60), signals are capped at
`--max-signals-per-sec` (50), and noisy rules can be skipped with `--ignore-sid`. The adapter only
needs to read the EVE log and write to the IPC socket (group `sokol-ipc`).

### CrowdSec

`sokol-crowdsec` is a CrowdSec bouncer: it polls the Local API decision stream and turns `ban`
decisions on single addresses into signals.

```shell
cscli bouncers add sokol                         # prints the API key
SOKOL_CROWDSEC_KEY=<key> sokol-crowdsec --lapi-url http://127.0.0.1:8080 --ipc-socket /run/sokol/sokol.sock
```

Only local decisions (origins `crowdsec` and `cscli`) are forwarded by default; community lists
(`CAPI`, `lists`) can hold tens of thousands of addresses and are added with `--origins` only if the
mesh should carry them. Range decisions are forwarded as prefixes. Decisions deleted in
CrowdSec end on Sokol's own TTL; lift one early with `UNBAN_IP` on the control socket.

### FastNetMon

FastNetMon reports the *victim* of a volumetric attack (an address inside the protected network),
and flood sources are usually spoofed, so a report does not block anything. Instead
`sokol-fastnetmon-notify`, set as FastNetMon's notify script, marks the node under attack in its
mesh telemetry until FastNetMon sends `unban` (or `--attack-report-ttl-secs`, default 600, passes).
That feeds the cluster status and the distributed-storm latch; `sokol_external_attacks_active`
shows active reports.

```shell
# /etc/fastnetmon.conf
notify_script_path = /usr/local/bin/sokol-fastnetmon-notify   # SOKOL_IPC_SOCKET selects the node socket
```

Other detectors can use the same line protocol on the IPC socket:
`SIGNAL:<source>|<src ip>|<dst ip or ->|<reason>`.

## Local control socket and protected addresses

`/run/sokol.sock` accepts `DROP_IMMEDIATE:<ip>` from local tools such as `trident_trap`.
It is root-only (`0600`) unless `--ipc-group <group>` is given, in which case members of that
group may write to it (`0660`).

Blocks from traps, the control socket and the mesh expire: the first lasts `--block-ttl`
seconds (default 900), each repeat within 24 hours doubles it up to `--block-ttl-max` (default
86400). `--block-ttl 0` makes them permanent. `--block` addresses are always permanent, and a mesh
`UnblockIp` cannot lift them.

Blocks can be single addresses or CIDR prefixes (`--block 198.51.100.0/24`, `BAN_IP:198.51.100.0/24`
on the control socket, `SIGNAL:<source>|<prefix>|-|<reason>`, CrowdSec range decisions, mesh and
Flowspec). A prefix is refused if it is wider than `--min-block-prefix-v4` (default 16) or
`--min-block-prefix-v6` (default 48), or if it contains or lies inside any protected address or range
below — a detector mistake must not cut the node off.

Some addresses are never blocked, whether the request comes from `--block`, the control
socket, a trap or the mesh: loopback, multicast, IPv6 link-local, every address of this node,
its default gateways and its `--seed-peer`s. Add operator and bastion networks explicitly:

```shell
sudo ./target/release/orchestrator -i eth0 --never-block 203.0.113.0/24 --never-block 2001:db8:ad::/48
```

## Web dashboards

`sokol-operator` (default `127.0.0.1:3000`, override with `SOKOL_OPERATOR_BIND`) requires a
token on every API call. Set `SOKOL_OPERATOR_TOKEN` (16+ characters), or read the one-time
token it prints at startup; the dashboard asks for it and keeps it in an `HttpOnly`,
`SameSite=Strict` cookie. Ban/unban/flush buttons go to the node's control socket
(`--control-socket`, announced in its heartbeat): operator bans are permanent until lifted,
"Flush" lifts the operator's bans and all dynamic blocks, `--block` addresses stay, and protected
addresses are refused. The operator needs access to that socket (`--control-group`, e.g.
`sokol-ops`). XDP toggle and shield mode are reported as unsupported.

`sokol-client` (`127.0.0.1:3001`) attaches its own XDP program to `SOKOL_IFACE`, so do not run it
on an interface the orchestrator already uses. It refuses to start without `SOKOL_CLIENT_TOKEN`
(16+ characters). Only the IPv4 blacklist is backed by an eBPF map.

## Trident trap

`trident_trap` listens on decoy ports and asks the orchestrator to block every source that
connects, so run it on a decoy host or only on ports with no real service.

- `SOKOL_TRAP_PORTS` — comma-separated ports (default `22,80,443,3306,6379,8443`; `2222`, the
  operator SSH port, is refused)
- `SOKOL_JAIL_ADDR` — optional external interactive jail for SSH attackers; without it an
  embedded mock jail answers. It must not be the operator SSH port.

At most 256 trap connections are handled at once; binary floods get a slow 32 B/s drip for up
to 30 s instead of a burst.

## Running as a service

`deploy/sokol-orchestrator.service` runs the orchestrator as user `sokol` with only
`CAP_NET_ADMIN`, `CAP_BPF` and `CAP_PERFMON` (the smoke test checks that this set works and that
dropping `CAP_PERFMON` does not), `ProtectSystem=strict` and related hardening
(`systemd-analyze security`: 3.7 "OK"). State lives in `/var/lib/sokol`, the control socket in
`/run/sokol/sokol.sock` for members of `sokol-ipc`; point `trident_trap` at it with
`SOKOL_IPC_SOCKET=/run/sokol/sokol.sock` (it also needs `CAP_NET_BIND_SERVICE` for ports below
1024). SIGTERM shuts down gracefully and flushes the audit log.

## Audit log

Blocks, unblocks, trap hits and sampled kernel drop events go to `--db-path`
(`/var/lib/sokol/audit.log`), an append-only log whose records are chained with BLAKE3. It
rotates at `--audit-max-bytes` (default 100 MiB) into `audit.log.<first sequence number>`,
keeping `--audit-keep` segments (default 10); each segment starts where the previous one ended,
so the chain stays verifiable across files:

```shell
./target/release/monitor --verify /var/lib/sokol/audit.log
# OK /var/lib/sokol/audit.log: 4 file(s), records 1200..5210, head 3f9c...
```

A missing, reordered or edited segment makes it print `BROKEN` and exit 1. Someone with write
access could rebuild the whole chain; to detect that, record the printed head somewhere the node
cannot write (another host, a ticket, a timestamping service).

Records are fsynced at most 100 ms after the last successful sync (or every 64 records), however
steady the stream of events. One writer per log: a second process opening the same `--db-path`
is refused (`<db-path>.lock`).

If the log cannot be written (disk full, I/O error), **enforcement continues**: blocking never
waits for the audit. The node reports itself degraded instead: `sokol_audit_healthy 0`,
`MODE=DEGRADED` in its heartbeat to the dashboard, `sokol_audit_write_errors_total`,
`sokol_audit_lost_total` and `sokol_audit_last_sync_age_seconds`. It keeps reopening the log (which
drops a torn record) and, once it can write again, records how many records were lost
(`AUDIT_LOST|Records:<n>`), so the gap is visible in the chain itself.

## BGP Flowspec (upstream drops)

With `--flowspec-gobgp /usr/local/bin/gobgp` every active block is announced as an RFC 8955
Flowspec rule `match source <ip>/32 then discard` through a local
[GoBGP](https://github.com/osrg/gobgp) daemon, so routers that accept Flowspec drop the traffic
before it reaches this node's link. Expired or lifted blocks are withdrawn, and all of the node's
rules are withdrawn when it shuts down.

Every rule carries the node's ownership community (`--flowspec-community`, default
`64512:<node-id>`; give each node that shares a gobgpd its own). Every second a separate worker
reads gobgpd's RIB and makes this node's rules, and only those, equal to its active blocks (at
most 64 changes per round). So rules left behind by a crashed run are withdrawn by the next one,
rules a restarted gobgpd lost are announced again, a gobgp call that timed out (it is killed) is
settled by the next read, and other systems' rules or rules learned from peers are never
touched. A slow or hung gobgpd never delays the main loop. `sokol_flowspec_announced` is the
number of the node's rules last seen in the RIB.

Run gobgpd with a neighbor for each upstream router and the `ipv4-flowspec` / `ipv6-flowspec`
address families enabled, then point the orchestrator at its API:

```shell
sudo ./target/release/orchestrator -i eth0 --flowspec-gobgp /usr/local/bin/gobgp \
    --flowspec-gobgp-arg=-p --flowspec-gobgp-arg=50051
```

Only accept this on sessions where the upstream operator agreed to take Flowspec from you and
filters it to your own address space; the smoke test checks the whole path between two gobgpd
instances.

## Metrics

`--metrics-bind 127.0.0.1:9469` serves Prometheus metrics at `/metrics`:
`sokol_xdp_rx_packets_total`, `sokol_xdp_rx_bytes_total`,
`sokol_xdp_dropped_packets_total{reason=...}` (e.g. `blocklist`, `invalid_tcp_flags`, `fragment_blocked`), `sokol_xdp_events_suppressed_total`,
`sokol_blocks_active`, `sokol_p2p_active_peers`, `sokol_audit_queue_overflow_total`,
`sokol_flowspec_announced`, `sokol_cluster_status`, `sokol_cluster_nodes`,
`sokol_cluster_nodes_under_attack`, `sokol_cluster_storm_engaged`.

Kernel drop events reach user space at most 64 times per second per CPU (trap-port events only
for connection attempts); the rest are counted in `sokol_xdp_events_suppressed_total`.

## Demo

`demo/demo.sh` runs the whole story on one Linux machine: three nodes meshed with pinned keys, an
attacker, a rogue node, Suricata on node 1 and the operator dashboard on http://127.0.0.1:3000.

```shell
sudo demo/demo.sh target/release            # pauses before each step
sudo DEMO_AUTO=1 demo/demo.sh target/release
```

1. The attacker scans node 1; Suricata alerts and all three nodes drop the attacker (the demo prints
   the time from scan to block on each node).
2. A rogue node with its own valid key orders a block; the others reject it.
3. A flood on node 2 is dropped in XDP and node 1 reports a distributed storm.
4. A signal against the operator's address is refused by the never-block policy.
5. The blocks expire on their TTL and every node's audit chain verifies.

Each step checks its outcome, and CI runs the demo on every change.

## Measurements

`bench/` reproduces the numbers in the project's evaluation (Linux, root; timings come from the
nodes' own audit logs, read with `monitor --dump`):

```shell
sudo bench/local.sh latency target/release/orchestrator 20      # signal -> first dropped packet
sudo bench/local.sh fill    target/release/orchestrator 65536   # map capacity, rate, memory, expiry
sudo bench/mesh.sh propagation target/release/orchestrator target/release/monitor 10 20
sudo bench/mesh.sh propagation target/release/orchestrator target/release/monitor 5 20 delay 100ms 20ms loss 5%
sudo bench/mesh.sh partition   target/release/orchestrator target/release/monitor 4 45
```

These run on virtual interfaces in one kernel (generic XDP). They measure the control path and
the mesh, not line-rate packet processing on a physical NIC.

# Project Structure

`ebpf/` — kernel space code (Rust XDP program).

`orchestrator/` — main user-space daemon managing maps and logic.

`common/src/audit_log.rs` — append-only audit log (BLAKE3 hash chain, torn-write recovery), written by the orchestrator and read by `monitor`.

`common/` — shared data structures and protocol definitions.

# License

Copyright © Sokol-Core Contributors. All rights reserved.
Unauthorized copying, distribution, or use of this code is strictly prohibited without permission from the author.
