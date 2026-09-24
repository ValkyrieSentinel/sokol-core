# Sokol-Core 🛡️

> **Status:** Pilot / Active Testing

A high-performance network security and traffic filtering system running at the Linux kernel level. Built with **Rust** (eBPF/XDP) and **Zig**.

The program intercepts and drops garbage (attacks, malicious traffic) right at the network interface card before it even reaches the OS. For internal states and logs, it uses a custom high-speed database written in Zig (`sntl_db`).

---

## Requirements

- **OS:** Linux kernel 5.15+ (with an XDP-compatible NIC driver)
- **Toolchain:** 
  - Rust Nightly (needed for building eBPF target `bpfel-unknown-none`)
  - [`bpf-linker`](https://github.com/aya-rs/bpf-linker) (links the eBPF object)
  - Zig compiler (v0.14+; `sntl_db/build.zig` uses the 0.14 build API)
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

Build the orchestrator and tools (this also builds the Zig `sntl_db` library via `orchestrator/build.rs`):

```shell
cargo +nightly build --release
```

Run the tests and the XDP smoke test (Linux, root: creates a veth pair in a network namespace):

```shell
cargo +nightly test --release
sudo scripts/xdp-smoke.sh target/release/orchestrator
```

Run (must be run with sudo, as root privileges are required to work with XDP maps and network interfaces):

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

# Project Structure

`ebpf/` — kernel space code (Rust XDP program).

`orchestrator/` — main user-space daemon managing maps and logic.

`sntl_db/` — fast Zig database for events and metrics.

`common/` — shared data structures and protocol definitions.

# License

Copyright © Sokol-Core Contributors. All rights reserved.
Unauthorized copying, distribution, or use of this code is strictly prohibited without permission from the author.
