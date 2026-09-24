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

# Project Structure

`ebpf/` — kernel space code (Rust XDP program).

`orchestrator/` — main user-space daemon managing maps and logic.

`sntl_db/` — fast Zig database for events and metrics.

`common/` — shared data structures and protocol definitions.

# License

Copyright © Sokol-Core Contributors. All rights reserved.
Unauthorized copying, distribution, or use of this code is strictly prohibited without permission from the author.
