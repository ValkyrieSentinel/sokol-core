# Sokol-Core 🛡️

> **Status:** Pilot / Active Testing

A network traffic filter running at the Linux kernel level (XDP). Built entirely in **Rust** (eBPF/XDP kernel program and user-space daemon).

It drops traffic from addresses that a detector (Suricata, CrowdSec, FastNetMon), the operator, a static list or a trusted mesh peer has blocked, before the kernel network stack sees it. It does not decide by itself what an attack is. Besides those blocks the filter drops only by fixed packet rules: malformed headers, invalid TCP flag combinations and, if enabled, IPv4 fragments. A SYN to the trap port is passed and reported as an event, which a detector can turn into a block. Blocks, trap hits and kernel drop events are recorded in an append-only, hash-chained audit log.

Design and its reasons: [ARCHITECTURE.md](ARCHITECTURE.md) (Ukrainian). Normative decisions
(authority, leases, persistence, degraded modes, protocol versioning, ...):
[docs/adr/](docs/adr/README.md).
Operating a node: [docs/RUNBOOK.md](docs/RUNBOOK.md) (install, health, incidents, keys, rollback,
support bundle). What it is tested on: [docs/SUPPORT.md](docs/SUPPORT.md).

---

## Requirements

- **OS:** Linux kernel 5.15+ (with an XDP-compatible NIC driver)
- **Toolchain:** 
  - Rust Nightly (needed for building eBPF target `bpfel-unknown-none`)
  - [`bpf-linker`](https://github.com/aya-rs/bpf-linker) (links the eBPF object)
  - A C compiler (`gcc` or `clang`; `blake3` builds its SIMD code with it)

---

## Build & Run

Clone the repository:

```shell
git clone https://github.com/ValkyrieSentinel/sokol-core.git
cd sokol-core
```

The Rust toolchain is pinned in `rust-toolchain.toml` (a dated nightly; the eBPF build needs
`build-std`), so plain `cargo` picks it up. `cargo +nightly` would bypass the pin. CI verifies the
checksums of bpf-linker and GoBGP, pins its actions by commit, and uploads the binaries with a
`MANIFEST.txt` (toolchain, tool versions, lockfile hashes) and `SHA256SUMS` for every run.

Build the eBPF program first. The orchestrator embeds the compiled object
(`target/bpfel-unknown-none/<profile>/ebpf-probe`), so this step must come before the Rust build:

```shell
cd ebpf && cargo build --release --locked && cd ..
```

Build the orchestrator and tools:

```shell
cargo build --release --locked
```

Run the tests and the XDP smoke test (Linux, root: creates a veth pair in a network namespace):

```shell
cargo test --release --locked
sudo scripts/xdp-smoke.sh target/release/orchestrator
```

Run as root for a quick test (for production use the systemd unit below, which runs unprivileged):

```shell
sudo ./target/release/orchestrator
```

## XDP modes and NIC drivers

`--xdp-mode` chooses how the filter attaches:

- `native` — runs in the NIC driver before any socket buffer is allocated. This is the fast
  path. Its rate on a physical NIC has not been measured yet (`bench/nic.sh` is the method; see
  docs/SUPPORT.md). Attach fails if the driver has no XDP support.
- `generic` — runs after the kernel built an skb. Works on any interface but pays for the skb on
  every packet, dropped or not; use it for testing or unsupported NICs.
- `auto` (default) — the kernel uses native if the driver supports it, otherwise generic.

Check what you got:

```shell
ip -d link show dev eth0 | grep -o 'xdp[a-z]*'   # "xdp" = native, "xdpgeneric" = generic
ethtool -i eth0 | grep driver                    # driver name
```

Drivers with native XDP in the upstream kernel (a list from the kernel, not from our tests; only
`veth` is tested here) include `mlx5_core`, `mlx4_en`, `i40e`, `ice`, `ixgbe`, `igb`/`igc`
(recent kernels), `bnxt_en`, `nfp`, `ena`, `virtio_net`, `veth`, `tun`. Some need a driver-specific
setting: `virtio_net` needs enough queues (`ethtool -L eth0 combined <n>`) and refuses XDP when
the host offloads GRO (Apple Virtualization does), `ena` needs an MTU
at or below its XDP limit, and several drivers refuse XDP with jumbo frames or LRO enabled
(`ethtool -K eth0 lro off`). Start the service with `--xdp-mode native` in production so a
driver problem fails loudly instead of silently falling back to generic mode.

`sokol_blocks_active{family=...}` and `sokol_blocks_capacity` (65 536 per family) show map
usage; crossing 80% is logged and recorded in the audit log.

## Mesh peers

Nodes accept mesh commands (e.g. `BlockIp`) only from peers whose public key is pinned in a
peers file. Without `--peers-file` the mesh rejects every peer. Identities are ML-DSA-65
(FIPS 204) keys; every mesh message is signed with one (mesh protocol v2).

Each node keeps its identity key in `--key-file` (default `/var/lib/sokol/node.key`, created
with mode `0600` on first start). Print a node's public key:

```shell
sudo ./target/release/orchestrator --print-public-key
```

Collect the keys into a peers file on every node:

```json
[
  { "node_id": 2, "public_key": "mldsa65:<hex from node 2>" },
  { "node_id": 3, "public_key": "mldsa65:<hex from node 3>" }
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

### Upgrading a mesh from protocol v1 (Dilithium3) to v2 (ML-DSA)

v1 and v2 nodes cannot verify each other, so a mesh is upgraded in one window; every node keeps
enforcing its own decisions (and its operator bans) the whole time, only mesh sharing pauses.

1. Upgrade the binary on every node and restart it. At startup a v1 key file (raw Dilithium3,
   5952 bytes) is kept as `node.key.dilithium3.retired` (or `.retired.1`, ... if that name is
   taken; an existing backup is never overwritten) and a new ML-DSA identity is created;
   the log prints its public key. `--print-public-key` prints it too.
2. Put the new `mldsa65:` keys into every peers file and send `RELOAD_PEERS`. Until then a peer
   listed with only an old (unprefixed) key is not trusted; startup and `RELOAD_PEERS` name it
   instead of failing.
3. Peers reconnect and resynchronise by themselves (digests every 15 s).

A v1 peer that connects to a v2 node is refused with "peer speaks the pre-versioned mesh
protocol (v1 ...): upgrade the peer" in the log. Rolling back means restoring the retired key
file and the old peers file together with the old binary.

Each frame starts with `SKM` and the wire version, and the handshake carries the range of
versions each side speaks: a peer with no common version is refused with both ranges in the log.
Only v2 exists so far, so every frame is written as v2; when a v3 is added, the writer has to
use the version negotiated per connection so that such an upgrade can go node by node.

### Encrypt the mesh with WireGuard

The mesh protocol authenticates but does not encrypt. Run it inside a WireGuard tunnel between
the nodes (see `deploy/wireguard-mesh.conf.example`) and bind the P2P listener to the tunnel
address only, e.g. `--p2p-bind 10.99.0.1:7946 --seed-peer 10.99.0.2:7946`. The smoke test runs
two nodes this way. Add every peer's tunnel address to `--never-block`. Its WireGuard endpoint
(the public address in `Endpoint =`) is protected automatically: the node reads
`wg show all endpoints` every 2 s. XDP runs on the physical interface, where a peer's packets
carry its endpoint address: blocking that address, by a detector's mistake or a peer's claim,
would cut the tunnel and the mesh with it.

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

While the latch is engaged, `--storm-mode strict` (the default) tightens XDP on this node: packets
whose headers do not parse are dropped instead of passed to the stack (`malformed_header`), and
IPv4 fragments are dropped. When the latch disengages, exactly the flags the operator configured
(e.g. `--drop-ipv4-fragments`) are restored. Both transitions are audited (`DEFENSE_MODE|Strict`,
`DEFENSE_MODE|Normal`) and shown as `sokol_defense_strict`. `--storm-mode observe` only logs the
storm. Only a node's own latch switches its mode: a peer's EngageDefense/DisengageDefense is
refused.

Envelopes are signed over sender, timestamp, nonce and payload; they are rejected outside a
±30 s clock window (keep nodes NTP-synced) and accepted at most once. Mesh traffic is
authenticated but not encrypted.

## Signals from detectors (Suricata)

Sokol enforces decisions made by detectors you already run. `sokol-suricata` follows Suricata's
EVE log and sends each alert at or above `--max-severity` (default 2) to the node as a signal:

```shell
sokol-suricata --eve /var/log/suricata/eve.json --ipc-socket /run/sokol/sokol.sock \
    --cursor-file /var/lib/sokol/suricata.cursor
```

With `--cursor-file` the adapter saves the oldest unanswered position for restart.
A loaded cursor remains selected while the EVE path is missing or cannot be opened;
waiting checkpoints preserve it. After opening succeeds, the adapter checks that actual
file's inode and length, resuming the same file or reading a replacement/shortened file
from zero. A saved cursor takes precedence over `--from-start`. With no saved cursor,
the existing initial-read behavior remains.
Recovery opens only the current EVE path: queued alerts in rotated-away files are not
recovered after process loss. During live rotation it drains unread bytes from the old
open file before switching to the new one. Pending positions carry an in-memory content
identity: after a detected truncation, even on the same inode, old-content work pins the
current file's recovery cursor to zero. Once that work leaves the queue, the cursor advances
within the current contents. The saved inode/position format is unchanged. This does not
recover pre-truncation bytes after process loss. Inode and length still cannot detect
truncation followed by regrowth beyond the saved position between observations.
Timestamped alerts older than `--max-alert-age-secs` (default 600) are skipped. For a
remaining freshness budget, the adapter also keeps a monotonic forwarding deadline,
checked before connecting and again after the ACK handshake, on initial send and retries.
The measured age consumes that budget; future timestamps cannot grant more than the
configured interval from observation. An age interval that cannot be represented on the
local monotonic clock is rejected at CLI parsing, before opening EVE, loading the cursor
or using IPC. Each later deadline addition is still checked; an unrepresentable per-alert
deadline is logged and skipped. Missing or unparseable timestamps retain the legacy untimed policy.
Zero age budget or an exactly exhausted budget is skipped before policy admission.
An expired queued alert is removed as **counted local policy loss**, not a node ACK:
`queued alerts expired before forwarding` reports it, and its queued cursor is released.
After a lost ACK the signal may already have applied; local expiry neither retries it
nor undoes the node's effects. Suricata does not emit an expiry RETRACT because the node
can select the destination instead of the source and the adapter does not know that target.
Cooldown starts at policy admission and remains active even if the queued alert expires
without a write. Fresh same-source alerts can therefore be suppressed until cooldown
ends; refusals are counted as `alerts skipped: source cooldown active`.
Cooldown, rate-limit and full-cache warnings aggregate across batches. Report decisions
are spaced at least one monotonic second apart, with at most one line per category per report.
Pending counts are also checked on idle/error polls. Slow work can delay reporting;
slow stderr writes can make visible lines appear closer together. Log-level filters
may suppress output; reporting baselines advance even when WARN is disabled. Counts
saturate at `u64::MAX`, and pending diagnostics do not survive process loss. Other log
categories are unaffected. These counters cover Gate policy refusals only; parsing,
severity/signature/freshness filtering and outbox losses have their own boundaries.
This preserves the admission throttle during outages; it does not promise delivery of
an active attack's first alert. Successful acknowledged blocks retain the node's normal TTL/escalation policy; freshness
is a forwarding limit, not a block TTL. Time after the final check (write, scheduling,
node processing) has no deadline guarantee. Replayed alerts retain their event IDs for
duplicate recognition.

The reader processes at most **1 MiB of bytes or 256 completed lines per poll**, counting
invalid lines too, then yields to delivery and the existing once-per-second checkpoint check. It retains at
most **1 MiB of unfinished line data**, including the final LF. A larger record (even valid JSON) is logged and
skipped through its LF; the next record is read normally. Invalid UTF-8 completed lines
are also logged and skipped. These are fixed operational quotas, not measured throughput
or wall-clock deadlines, and the line-data cap is not a whole-process memory limit.
Delivery and the checkpoint check still run between batches, but a budget-exhausted poll
is followed immediately by the next iteration. The 50 ms idle pause
applies only when a poll does not exhaust a budget (or returns an error).
A read error after complete records returns those records together with the error:
the adapter logs the failure and still processes the completed prefix. Unfinished bytes
and the open reader remain for the next attempt, and the error yields through the idle
pause rather than a busy retry. The checkpoint remains at the start of unfinished data
or the oldest queued alert. Metadata/open errors before scanning still return no records.


The node blocks the offending address in XDP, shares the block with its mesh peers and records the
rule in the audit log (`suricata: sid:<id> <signature>`). If the alert fired on this node's own
outbound traffic, the remote destination is blocked instead; the never-block policy still applies.
The same source address is not admitted again within `--cooldown-secs` (60), and
`--max-signals-per-sec` (50) caps policy admissions per fixed one-second window, not IPC
retries or paced delivery. Adjacent windows can admit a burst across their boundary.
Rate-refused alerts are counted as `alerts skipped: policy rate limit reached`; they
are skipped without a queued retry, so their source cursor may advance. Zero rate skips
all alerts that reach this policy. Each refused attempt has one reason, in precedence
order: cooldown, rate, capacity. The reason identifies the first failing policy,
not every limit reached and not a node-delivery outcome.
Cooldown memory retains at most **100,000 distinct addresses**. Expired entries leave in
admission order; a full cache skips new addresses without evicting an unexpired cooldown.
Capacity refusals use the aggregated warnings described above. Those alerts are deliberately
skipped, not queued for retry, and the source cursor may advance past them. This is a cardinality bound,
not a process RSS or latency guarantee. Noisy rules can be skipped with `--ignore-sid`.
The adapter only needs to read the EVE log and write to the IPC socket (group `sokol-ipc`).
The [detector invariant ledger](docs/DETECTOR_INVARIANTS.md) maps these boundaries and
source/queue/ACK/cursor properties to code and executable counterexamples.

### CrowdSec

`sokol-crowdsec` is a CrowdSec bouncer: it polls the Local API decision stream and turns `ban`
decisions on single addresses into signals.

```shell
cscli bouncers add sokol                         # prints the API key
SOKOL_CROWDSEC_KEY=<key> sokol-crowdsec --lapi-url http://127.0.0.1:8080 --ipc-socket /run/sokol/sokol.sock
```

Only local decisions (origins `crowdsec` and `cscli`) are forwarded by default; community lists
(`CAPI`, `lists`) can hold tens of thousands of addresses and are added with `--origins` only if the
mesh should carry them. Range decisions are forwarded as prefixes.

API polling and IPC pacing use separate clocks in one sequential loop. Delivery
yields between commands when the next poll is due, so a healthy backlog does not
have to drain before new decisions and retractions are fetched. FIFO order and
ACK retention remain intact; fetched retractions join the existing queue.
`--poll-secs` measures the wait after a poll and queue insertion finish, while
`--max-signals-per-sec` paces each completed IPC command (signals and retractions).
This rate must be a positive `u32` (default 200); zero is a CLI error before any LAPI
or IPC request. Previously zero silently became one command per second. Suricata's
separate zero-admission policy is unchanged. The pacing interval is the smallest whole
nanosecond duration no shorter than `1 / rate`, rounded upward with integer arithmetic;
large rates retain at least a one-nanosecond requested pause. This defines the local
sleep budget, not a sliding-window command quota or measured throughput. During backoff
the loop waits up to 50 ms, or until a poll is due, before checking retry readiness. A zero poll
interval permits one delivery attempt per poll to avoid starving the sender.

This is cooperative scheduling: an in-flight HTTP request, one IPC exchange or
its pacing sleep can delay the next poll. It does not provide a strict wall-clock
poll period or prioritize retractions ahead of earlier queued commands.

The adapter validates the decision-stream envelope before queueing any commands. The
root must be an object; `new` and `deleted`, when present and non-null, must be arrays
of objects. Missing/null/empty sections remain valid (the [upstream response model](https://github.com/crowdsecurity/crowdsec/blob/master/pkg/models/decisions_stream_response.go)
makes these fields optional). Any HTTP, body-read, JSON or envelope error requests
`startup=true` again on the next poll; only a usable batch returns to delta mode.
This [full-stream request](https://docs.crowdsec.net/docs/local_api/bouncers/)
recovers active decisions and whatever expired records the server still retains
([upstream controller at e3f795d](https://github.com/crowdsecurity/crowdsec/blob/e3f795da3d064a172d475436e51275ceb13c8ff5/pkg/apiserver/controllers/v1/decisions.go)).
The local outbox is retained throughout. Full replay can repeat event ids and
increase response size/queue pressure; node deduplication and overflow limits
still apply. Purged records, semantically skipped entries and unreported server
errors cannot be recovered this way. Envelope checking remains shape validation.

Timed CrowdSec signals retain a monotonic expiry anchored before the HTTP request.
Each delivery attempt recalculates the remaining TTL after the ACK handshake;
expired events send their `RETRACT#id` even if an earlier signal's answer was lost.
The retraction stays queued until a recognized answer. Positive durations require
an event id; explicit invalid/non-positive durations are skipped and counted,
rather than falling back to node escalation. Only a missing `duration` key retains the legacy node policy; an explicit
`null` is invalid. This changes the expired-duration fallback in ADR-0019.

Retries retain the same event id: while the node remembers it, a repeated SIGNAL
returns `OK duplicate` and does not shorten the TTL of an already accepted signal.
Its later expiry RETRACT is the separate request to remove that event's support.

Durations and remaining TTLs are rounded up to whole seconds. The local anchor
conservatively includes the HTTP round-trip; it is not an authoritative server
expiry. Time spent after preparing the wire (write, node processing, scheduling)
can still extend the effective end. The node's permanent-block policy, bounded
event memory, queue overflow and adapter process loss retain their existing limits.

A decision's CrowdSec `duration` is the block's TTL, capped by `--block-ttl-max`; the node does
not escalate it again (CrowdSec already did). A decision deleted in CrowdSec
(`cscli decisions delete`) is taken back on the node and, through the mesh, on its peers. The
block ends only if nothing else holds it: an alert from Suricata on the same address keeps it
for as long as that alert justifies (ADR-0019). `UNBAN_IP` on the control socket still lifts
everything about an address at once.

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
`SIGNAL:<source>|<src ip>|<dst ip or ->|<reason>`. A detector that can name its events sends
`SIGNAL#<event id>:<source>|...` (id: 1-64 of `A-Z a-z 0-9 . _ -`, unique per source); the node
acts on each (source, id) once within 24 h and answers a resend with `OK duplicate`, so a retry
after a lost reply or an adapter restart adds no strike. `sokol-crowdsec` sends the LAPI decision
id, `sokol-suricata` a hash of the EVE line.

A detector with its own decision lifecycle can also send (ADR-0019):
- `SIGNAL#<id>;ttl=<seconds>:...` — the block lasts that long, within `--block-ttl-max`, instead
  of the node's escalation;
- `RETRACT#<id>:<source>|<target>` — takes the event back. The reply says what it did:
  - `OK lifted`: nothing else held the block;
  - `OK shortened`: the block now ends when the remaining reasons do;
  - `OK still held by other reasons`;
  - `OK nothing held`;
  - `OK recorded before its signal`: the late signal then adds nothing;
  - `OK duplicate`;
  - `OK refused retraction state capacity`: the necessary claim or retraction record
    storage is full. Supports, claims and replay markers stay unchanged; a later explicit
    retry can succeed after capacity is available. This is a final refusal for the current
    outbox request, not an automatic retry or a promise of eventual removal.

  Events without an id, such as `DROP_IMMEDIATE` or the trap, cannot be taken back.
  `sokol_detector_retractions_total{result}` counts the answers.

## Local control socket and protected addresses

`/run/sokol.sock` accepts `DROP_IMMEDIATE:<ip>` from local tools such as `trident_trap`.
A client that first sends the line `ACK` gets one reply per command: `OK applied`, `OK pending`
(recorded; the node retries the kernel write), `OK recorded` (reports, logs), `OK duplicate`
(an event id already acted on), `OK refused <why>`
or `ERR <why>`. `OK applied` means the block is in the kernel; it is written to `--state-file`
within about a second (a crash before that loses it on this node; operator decisions, in contrast,
wait up to 2 s for the write before the control socket answers, and say `WARNING: not yet durable`
if it has not finished; a graceful shutdown writes the last state).
`sokol-suricata` and `sokol-crowdsec` use it: a signal stays in their bounded
queue until the node has answered it, so alerts and decisions that arrive while the node is down
or restarting are delivered when it is back (refusals and errors are final, not retried).
It is root-only (`0600`) unless `--ipc-group <group>` is given, in which case members of that
group may write to it (`0660`).

### Block decisions and who may take them back

Every block is a *claim*: one immutable decision with its issuer (node), kind, target, times and
reason; its identity is the hash of its bytes. An address is dropped while at least one claim on
it stands.

| Kind | Made by | Expires | Lifted by | Shared over the mesh |
|---|---|---|---|---|
| static | `--block` | never | the configuration only (`UNBAN_IP` refuses) | no |
| operator | `BAN_IP` on the control socket | never | `UNBAN_IP` / dashboard | no |
| detector | traps, IPC, `SIGNAL`, adapters, the mesh | yes | its issuer, or the local operator | yes |

A detector claim made here lasts `--block-ttl` seconds (default 900), each repeat within 24 hours
doubles it up to `--block-ttl-max` (default 86400); `--block-ttl 0` makes them permanent. A peer's
claim keeps its own expiry but is enforced here for at most `--block-ttl-max`.

- Only the node that issued a claim can retract it over the mesh; a peer cannot lift another
  node's block, including this node's own detections.
- `UNBAN_IP` and `FLUSH_BANS` lift the *claims* standing at that moment, by id, on this node. A
  peer's copy of a lifted claim never reinstates it, however long it lives or however often the
  mesh reconnects; a new detection is a new claim and blocks again. Lifting this node's own
  detections also retracts them mesh-wide; other nodes' claims are lifted here only.
- This node's own claims and lifts are kept in `--state-file` (default `<db-path>.blocks.json`) and
  restored on start, re-checked against the never-block policy. Peers' claims come back through
  the mesh. A separate writer thread owns the file, so a slow or hung disk never holds up expiry
  or the heartbeat; the node turns DEGRADED if a change waits more than 5 s
  (`sokol_state_pending_seconds`). A state file that cannot be read or parsed is kept as
  `<state-file>.corrupt` and the node stays DEGRADED (`sokol_state_restore_ok 0`) until the
  operator sends `ACCEPT_STATE_LOSS` on the control socket.
- The kernel map follows the claims. A map write or delete that fails (e.g. the map is full) stays
  pending, is retried every second and is shown as `sokol_blocks_pending`; `sokol_blocks_active`
  counts only entries the kernel holds.
- What a peer can impose here is bounded (ADR-7). A peer's claims enforced at once are capped
  (`--peer-max-active`, default 16384; more wait for a free slot), each for at most
  `--peer-max-ttl` (default `--block-ttl-max`) from when it starts. A prefix wider than /24
  (IPv4) or /64 (IPv6) is enforced only once `--quorum` distinct nodes (default 2, this node's own
  claim included) claim it, so one compromised peer cannot cut off a network. Per peer, the peers
  file can tighten this: `"envelope": {"max_active": 1000, "max_ttl_secs": 3600,
  "min_prefix_v4": 32, "min_prefix_v6": 128}` (unknown fields are refused; `RELOAD_PEERS` applies
  changes). Held claims are audited as `MESH_BLOCK_HELD` with the reason, and are still shared,
  so the mesh state converges whatever each node enforces.
- Every 15 s each node sends a digest of its own claims; a peer whose view of them differs asks
  for them (SyncRequest), so a node that missed messages (a partition, a full send queue)
  converges without waiting for a reconnect. A node speaks only for itself: a snapshot carrying
  another node's claim closes the connection, so one peer cannot forge quorum votes. Connect the
  nodes as a full mesh. A node removed from the peers file loses its claims' effect on
  `RELOAD_PEERS`. All nodes of a mesh must run this protocol version.

Blocks can be single addresses or CIDR prefixes (`--block 198.51.100.0/24`, `BAN_IP:198.51.100.0/24`
on the control socket, `SIGNAL:<source>|<prefix>|-|<reason>`, CrowdSec range decisions, mesh and
Flowspec). A prefix is refused if it is wider than `--min-block-prefix-v4` (default 16) or
`--min-block-prefix-v6` (default 48), or if it contains or lies inside any protected address or range
below — a detector mistake must not cut the node off.

The node re-reads its addresses and default gateways every 2 s: an address that moves onto
this host is released at once if it was blocked, and refused afterwards
(`sokol_protected_refresh_ok` shows the reads work).

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
"Flush" lifts the operator's bans and all dynamic blocks in one command on the node
(`FLUSH_ALL`), `--block` addresses stay, and protected addresses are refused. The dashboard does
not keep its own copy of the bans: it reads them from each node (`LIST_BANS`) every 5 s and after
every action, so a restarted dashboard or another operator's change shows the node's real state.
A node without a heartbeat for 15 s is shown as STALE. The operator needs access to that socket (`--control-group`, e.g.
`sokol-ops`). The dashboard takes node heartbeats on `/run/sokol_telemetry.sock` (mode 0660, group
`SOKOL_TELEMETRY_GROUP` if set) only from the uids in `SOKOL_NODE_UIDS` (default: root and its own
uid). A node is bound to the uid that first announced it: heartbeats for it from another uid are
ignored, and a control socket is used only if the process serving it runs as that uid, so a
local process cannot re-point the operator's commands to a socket of its own. XDP toggle and shield mode are reported as unsupported.

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
number of the node's source-prefix rules last seen in the local RIB. After a round
changes rules, the worker reads both families again before publishing that count;
a successful CLI write alone cannot update it. Failed readback retains the last
successful observation, which may be stale. Read it together with:

- `sokol_flowspec_enabled`: 1 when the worker is configured; 0 when disabled or in observe mode.
- `sokol_flowspec_readback_ok`: 1 after the latest round completed successfully;
  0 at startup, during a round, after failure or cancellation. This is not convergence.
- `sokol_flowspec_readback_age_seconds`: monotonic age since the start of the last
  successful two-family read; -1 before any successful observation. It continues
  to grow after failure and is computed when scraped, independently of the main tick.

These four values are sampled together from the worker for each HTTP response.
A consumer chooses its acceptable age; health alone gives no freshness guarantee.
The two RIB families are read sequentially, not as an atomic network snapshot.
This count does not validate the discard
action or prove that an upstream router applied it. `FLOWSPEC_ANNOUNCE`/`WITHDRAW`
audit records acknowledge successful CLI operations, not the subsequent observation.

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
`sokol_xdp_dropped_packets_total{reason=...}` (`blocklist` for every blocked source, `malformed_header`, `invalid_tcp_flags`, `fragment_blocked`), `sokol_xdp_events_suppressed_total`,
`sokol_blocks_active`, `sokol_p2p_active_peers`, `sokol_audit_queue_overflow_total`,
`sokol_flowspec_announced`, `sokol_flowspec_enabled`, `sokol_flowspec_readback_ok`,
`sokol_flowspec_readback_age_seconds`, `sokol_cluster_status`, `sokol_cluster_nodes`,
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
sudo bench/mesh.sh reaction    target/release/orchestrator target/release/monitor 3 10   # traffic stops/returns, per node
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
