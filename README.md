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
sudo ./target/release/orchestrator -i eth0 --node-id 1 --peers-file /etc/sokol/peers.json --seed-peer 10.0.0.2:8080
```

Envelopes are signed over sender, timestamp, nonce and payload; they are rejected outside a
±30 s clock window (keep nodes NTP-synced) and accepted at most once. Mesh traffic is
authenticated but not encrypted.

## Local control socket and protected addresses

`/run/sokol.sock` accepts `DROP_IMMEDIATE:<ip>` from local tools such as `trident_trap`.
It is root-only (`0600`) unless `--ipc-group <group>` is given, in which case members of that
group may write to it (`0660`).

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
`SameSite=Strict` cookie. Node control actions report failure until the orchestrator serves
per-node control sockets.

`sokol-client` (`127.0.0.1:3001`) attaches its own XDP program to `SOKOL_IFACE`, so do not run it
on an interface the orchestrator already uses. It refuses to start without `SOKOL_CLIENT_TOKEN`
(16+ characters). Only the IPv4 blacklist is backed by an eBPF map.

## Trident trap

`trident_trap` listens on decoy ports and asks the orchestrator to block every source that
connects, so run it on a decoy host or only on ports with no real service.

- `SOKOL_TRAP_PORTS` — comma-separated ports (default `22,80,443,3306,6379,8443`; `8080` is the
  orchestrator's P2P port and `2222` the operator SSH port, which is refused)
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

# Project Structure

`ebpf/` — kernel space code (Rust XDP program).

`orchestrator/` — main user-space daemon managing maps and logic.

`common/src/audit_log.rs` — append-only audit log (BLAKE3 hash chain, torn-write recovery), written by the orchestrator and read by `monitor`.

`common/` — shared data structures and protocol definitions.

# License

Copyright © Sokol-Core Contributors. All rights reserved.
Unauthorized copying, distribution, or use of this code is strictly prohibited without permission from the author.
