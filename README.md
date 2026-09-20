# Sokol-Core 🛡️

> **Status:** Pilot / Active Testing

A high-performance network security and traffic filtering system running at the Linux kernel level. Built with **Rust** (eBPF/XDP) and **Zig**.

The program intercepts and drops garbage (attacks, malicious traffic) right at the network interface card before it even reaches the OS. For internal states and logs, it uses a custom high-speed database written in Zig (`sntl_db`).

---

## Requirements

- **OS:** Linux kernel 5.15+ (with an XDP-compatible NIC driver)
- **Toolchain:** 
  - Rust Nightly (needed for building eBPF target `bpfel-unknown-none`)
  - Zig compiler (v0.11+)
  - `clang`, `llvm`

---

## Build & Run

Clone the repository:

```shell
git clone https://github.com/ValkyrieSentinel/sokol-core.git
cd sokol-core
```

Build the database in Zig (sntl_db):

```shell
cd sntl_db && zig build -O ReleaseFast && cd ..
```

Build eBPF and the orchestrator in Rust:

```shell
cargo +nightly build --release
```

Run (must be run with sudo, as root privileges are required to work with XDP maps and network interfaces):

```shell
sudo ./target/release/orchestrator
```

# Project Structure

`ebpf/` — kernel space code (Rust XDP program).

`orchestrator/` — main user-space daemon managing maps and logic.

`sntl_db/` — fast Zig database for events and metrics.

common/ — shared data structures and protocol definitions.

# License

Copyright © Sokol-Core Contributors. All rights reserved.
Unauthorized copying, distribution, or use of this code is strictly prohibited without permission from the author.
