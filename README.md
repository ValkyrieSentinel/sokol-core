# Sokol-Core 🛡️

> **Status:** lab-qualified, no release. Not yet measured on a target NIC in native mode and not
> run in a field pilot ([ROADMAP](ROADMAP.md), P4).

A network traffic filter running at the Linux kernel level (XDP). Built entirely in **Rust** (eBPF/XDP kernel program and user-space daemon).

It drops traffic from addresses that a detector (Suricata, CrowdSec, FastNetMon), the operator, a static list or a trusted mesh peer has blocked, before the kernel network stack sees it. It does not decide by itself what an attack is. Besides those blocks the filter drops only by fixed packet rules: malformed headers, invalid TCP flag combinations and, if enabled, IPv4 fragments. A SYN to the trap port is passed and reported as an event, which a detector can turn into a block. Blocks, trap hits and kernel drop events are recorded in an append-only, hash-chained audit log.

Design and its reasons: [ARCHITECTURE.md](ARCHITECTURE.md) (Ukrainian). Normative decisions
(authority, leases, persistence, degraded modes, protocol versioning, ...):
[docs/adr/](docs/adr/README.md).
Operating a node: [docs/RUNBOOK.md](docs/RUNBOOK.md) (install, health, incidents, keys, rollback,
support bundle). What it is tested on: [docs/SUPPORT.md](docs/SUPPORT.md).
Working on the code as an agent (or a new contributor): [AGENTS.md](AGENTS.md).

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

## Integrations and operation

Configuration beyond the build is in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md):

- [Mesh peers](docs/INTEGRATIONS.md#mesh-peers)
- [Signals from detectors (Suricata)](docs/INTEGRATIONS.md#signals-from-detectors-suricata)
- [Local control socket and protected addresses](docs/INTEGRATIONS.md#local-control-socket-and-protected-addresses)
- [Web dashboards](docs/INTEGRATIONS.md#web-dashboards)
- [Trident trap](docs/INTEGRATIONS.md#trident-trap)
- [Running as a service](docs/INTEGRATIONS.md#running-as-a-service)
- [Audit log](docs/INTEGRATIONS.md#audit-log)
- [BGP Flowspec (upstream drops)](docs/INTEGRATIONS.md#bgp-flowspec-upstream-drops)
- [Metrics](docs/INTEGRATIONS.md#metrics)

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

See [LICENSE](LICENSE): copyright © 2026 Ольга Скороход (ValkyrieSentinel), all rights reserved.
The source is published for viewing and educational purposes; copying, modifying, compiling or
using it needs the author's prior written permission.
