#![cfg_attr(not(feature = "std"), no_std)]
// Release builds abort on panic (panic = "abort"), so a panic reachable from input (a peer's
// frame, an IPC line, a trap connection, a file) stops the node. Outside tests, code must not
// be able to panic: no unwrap/expect, no unchecked indexing or slicing, no panic!-family macros.
// A provably safe exception is allowed locally, with its reason.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

#[cfg(feature = "std")]
extern crate std;

pub use core::sync::atomic::AtomicU64;

pub const MAX_PAYLOAD: usize = 256;
pub const HASH_SIZE: usize = 32;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
    /// Drops per `drop_reason` code (index = code, masked to `DROP_REASON_SLOTS`).
    pub drops_by_reason: [u64; DROP_REASON_SLOTS],
    /// Ring-buffer events withheld by the per-CPU rate limit.
    pub events_suppressed: u64,
    /// Rate-limit window state (per CPU; not a counter).
    pub event_window_start_ns: u64,
    pub events_in_window: u64,
    /// Events within the rate limit that found the ring buffer full (its consumer behind).
    pub events_lost: u64,
    /// Observe mode: packets Sokol would have dropped and passed instead, total and per
    /// `drop_reason` code (the would-be `dropped_packets` / `drops_by_reason`).
    pub observed_packets: u64,
    pub observed_by_reason: [u64; DROP_REASON_SLOTS],
}

pub const DROP_REASON_SLOTS: usize = 16;
/// Entries per blocklist map (IPv4 and IPv6 each).
pub const BLOCKLIST_CAPACITY: u32 = 65_536;
/// Drop-counter slots: one per possible blocklist entry, IPv4 and IPv6 together.
pub const BLOCK_HIT_SLOTS: u32 = 2 * BLOCKLIST_CAPACITY;
/// Ring-buffer events allowed per CPU per second; the rest are only counted. Per CPU: a node
/// with P busy CPUs can emit 64 × P events/s (numerical review N03).
pub const MAX_EVENTS_PER_CPU_PER_SEC: u64 = 64;
/// The operator's real SSH port: the XDP program always passes it, and the trap never takes it.
pub const ADMIN_SSH_PORT: u16 = 2222;
/// Size of the shared event ring buffer (a power of two, as the kernel requires).
pub const EVENTS_RING_BYTES: u32 = 256 * 1024;
/// Ring space one DropEvent takes: the record plus the kernel's 8-byte header, 8-aligned.
pub const EVENT_RECORD_BYTES: usize = (abi::DROP_EVENT_SIZE + 8).div_ceil(8) * 8;

/// What the per-CPU maps and the event path cost on this machine (N03): printed at start so a
/// deployment sees the numbers that multiply with its CPU count.
pub fn resource_estimate(possible_cpus: usize, online_cpus: usize) -> [(&'static str, u64); 4] {
    let ring_records = EVENTS_RING_BYTES as u64 / EVENT_RECORD_BYTES as u64;
    let events_per_sec = MAX_EVENTS_PER_CPU_PER_SEC * online_cpus as u64;
    [
        (
            "block hit counters (bytes)",
            u64::from(BLOCK_HIT_SLOTS) * 8 * possible_cpus as u64,
        ),
        ("event ceiling (events/s)", events_per_sec),
        ("event ring (records)", ring_records),
        (
            "ring holds at the ceiling (ms)",
            ring_records * 1000 / events_per_sec.max(1),
        ),
    ]
}

impl PacketStats {
    pub const ZERO: Self = Self {
        rx_packets: 0,
        rx_bytes: 0,
        dropped_packets: 0,
        drops_by_reason: [0; DROP_REASON_SLOTS],
        events_suppressed: 0,
        event_window_start_ns: 0,
        events_in_window: 0,
        events_lost: 0,
        observed_packets: 0,
        observed_by_reason: [0; DROP_REASON_SLOTS],
    };
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DropEvent {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub pkt_len: u32,
    pub reason: u16,
    pub protocol: u8,
    pub ip_version: u8,
    pub payload_len: u16,
    pub _pad: u16,
    pub payload: [u8; MAX_PAYLOAD],
}

/// The XDP program writes `DropEvent` into the ring buffer and `PacketStats` into a per-CPU map;
/// the orchestrator reads both. These asserts are the contract between the two sides. They are
/// evaluated when this crate compiles, which happens for the BPF object and for userspace on
/// every target, so a layout change that would make the two disagree does not build.
/// (A kernel value once sat at an offset x86 tolerated and arm64 did not: ADR-0014.)
/// The numbers are the ABI: changing one is a format change and gets an ADR.
pub mod abi {
    use super::{DropEvent, PacketStats, DROP_REASON_SLOTS, MAX_PAYLOAD};
    use core::mem::{align_of, offset_of, size_of};

    pub const DROP_EVENT_SIZE: usize = 300;
    pub const PACKET_STATS_SIZE: usize = 320;

    const _: () = {
        assert!(size_of::<DropEvent>() == DROP_EVENT_SIZE);
        assert!(align_of::<DropEvent>() == 4);
        assert!(offset_of!(DropEvent, src_ip) == 0);
        assert!(offset_of!(DropEvent, dst_ip) == 16);
        assert!(offset_of!(DropEvent, pkt_len) == 32);
        assert!(offset_of!(DropEvent, reason) == 36);
        assert!(offset_of!(DropEvent, protocol) == 38);
        assert!(offset_of!(DropEvent, ip_version) == 39);
        assert!(offset_of!(DropEvent, payload_len) == 40);
        assert!(offset_of!(DropEvent, _pad) == 42);
        assert!(offset_of!(DropEvent, payload) == 44);
        // No implicit padding: every byte is a declared field (the kernel side sets them all).
        assert!(44 + MAX_PAYLOAD == DROP_EVENT_SIZE);

        assert!(size_of::<PacketStats>() == PACKET_STATS_SIZE);
        assert!(align_of::<PacketStats>() == 8);
        // Every field, so a field added or removed anywhere moves a number here.
        assert!(offset_of!(PacketStats, rx_packets) == 0);
        assert!(offset_of!(PacketStats, rx_bytes) == 8);
        assert!(offset_of!(PacketStats, dropped_packets) == 16);
        assert!(offset_of!(PacketStats, drops_by_reason) == 24);
        assert!(offset_of!(PacketStats, events_suppressed) == 24 + 8 * DROP_REASON_SLOTS);
        assert!(offset_of!(PacketStats, event_window_start_ns) == 160);
        assert!(offset_of!(PacketStats, events_in_window) == 168);
        assert!(offset_of!(PacketStats, events_lost) == 176);
        assert!(offset_of!(PacketStats, observed_packets) == 184);
        assert!(offset_of!(PacketStats, observed_by_reason) == 192);
        assert!(192 + 8 * DROP_REASON_SLOTS == PACKET_STATS_SIZE);
        assert!(super::EVENTS_RING_BYTES.is_power_of_two());
    };
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NodeTelemetry {
    pub node_id: u64,
    pub rx_packets: u64,
    pub dropped_packets: u64,
    pub anomaly_score: f64,
    pub under_attack: u8,
    pub has_attacker_ip: u8,
    pub attacker_ip: [u8; 16],
    pub _pad: [u8; 6],
}

pub mod drop_reason {
    pub const STATIC_BLOCK: u16 = 1;
    pub const FAST_PATH_HIT: u16 = 2;
    pub const SLOW_PATH_LPM_HIT: u16 = 3;
    pub const VFR_ANOMALY: u16 = 4;
    pub const MALFORMED_HEADER: u16 = 5;
    pub const TRAP_INTERCEPTED: u16 = 6;
    pub const SOCK_REDIRECTED: u16 = 7;
    pub const MANUAL_BLOCK: u16 = 8;
    pub const FRAGMENT_BLOCKED: u16 = 9;
    pub const INVALID_TCP_FLAGS: u16 = 10;

    /// Label for metrics; `None` for codes that are never recorded as drops. A label is a
    /// claim that the counter can move: only codes the XDP program passes to `drop_verdict`
    /// get one (checked against its source below). Static, operator and mesh blocks all drop
    /// as `blocklist`; a trap hit passes and is only an event; the other codes are unused.
    pub const fn name(code: u16) -> Option<&'static str> {
        match code {
            SLOW_PATH_LPM_HIT => Some("blocklist"),
            MALFORMED_HEADER => Some("malformed_header"),
            FRAGMENT_BLOCKED => Some("fragment_blocked"),
            INVALID_TCP_FLAGS => Some("invalid_tcp_flags"),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        extern crate std;
        use std::{collections::BTreeSet, string::String, vec::Vec};

        const CODES: [(&str, u16); 10] = [
            ("STATIC_BLOCK", super::STATIC_BLOCK),
            ("FAST_PATH_HIT", super::FAST_PATH_HIT),
            ("SLOW_PATH_LPM_HIT", super::SLOW_PATH_LPM_HIT),
            ("VFR_ANOMALY", super::VFR_ANOMALY),
            ("MALFORMED_HEADER", super::MALFORMED_HEADER),
            ("TRAP_INTERCEPTED", super::TRAP_INTERCEPTED),
            ("SOCK_REDIRECTED", super::SOCK_REDIRECTED),
            ("MANUAL_BLOCK", super::MANUAL_BLOCK),
            ("FRAGMENT_BLOCKED", super::FRAGMENT_BLOCKED),
            ("INVALID_TCP_FLAGS", super::INVALID_TCP_FLAGS),
        ];

        #[test]
        fn a_drop_reason_has_a_metric_label_exactly_when_the_xdp_program_drops_with_it() {
            let src = include_str!("../../ebpf/src/main.rs");
            // Every `drop_verdict(<len>, drop_reason::X)` call, however it is wrapped.
            let flat: String = src.split_whitespace().collect();
            let dropped: BTreeSet<&str> = flat
                .match_indices("drop_verdict(")
                .filter_map(|(i, _)| {
                    let call = &flat[i..flat[i..].find(')').map(|e| i + e)?];
                    let name = call.split("drop_reason::").nth(1)?;
                    Some(name.trim_end_matches(','))
                })
                .collect();
            assert!(
                !dropped.is_empty(),
                "no drop_verdict call found: the scan is broken"
            );
            let labelled: Vec<&str> = CODES
                .iter()
                .filter(|(_, c)| super::name(*c).is_some())
                .map(|(n, _)| *n)
                .collect();
            for n in &dropped {
                assert!(
                    labelled.contains(n),
                    "the XDP program drops with {n}, which has no label"
                );
            }
            for n in &labelled {
                assert!(
                    dropped.contains(n),
                    "{n} has a label but the XDP program never drops with it"
                );
            }
        }
    }
}

/// Bits of the eBPF `CONFIG` map (index 0).
pub mod config_flags {
    /// Drop every IPv4 fragment (for hosts whose policy forbids fragmentation).
    pub const DROP_IPV4_FRAGMENTS: u32 = 1 << 0;
    /// Drop packets whose headers do not parse, instead of passing them to the stack
    /// (set while a distributed storm is engaged, ADR-6).
    pub const STRICT_PARSE: u32 = 1 << 1;
    /// Pilot phase 0: never drop. Every packet Sokol would drop is passed and counted as
    /// observed (`--enforce observe`).
    pub const OBSERVE_ONLY: u32 = 1 << 2;

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Each flag is its own bit, so the node can set one without the others (mutation
        /// sweep 2026-10-07: a flag could become 0 and only the XDP smoke would notice).
        #[test]
        fn each_flag_is_one_distinct_bit() {
            let flags = [DROP_IPV4_FRAGMENTS, STRICT_PARSE, OBSERVE_ONLY];
            for (i, a) in flags.iter().enumerate() {
                assert_eq!(a.count_ones(), 1, "flag {} is one bit", i);
                for b in &flags[i + 1..] {
                    assert_eq!(a & b, 0);
                }
            }
        }
    }
}

pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    /// Flag combinations no conforming TCP stack sends; scanners use them to fingerprint hosts
    /// (NULL, XMAS, FIN and SYN-FIN scans). Every segment after the first carries ACK, so FIN,
    /// PSH or URG without ACK only appears in probes.
    #[inline(always)]
    pub const fn is_invalid(flags: u8) -> bool {
        let f = flags & (FIN | SYN | RST | PSH | ACK | URG);
        f == 0
            || f & (SYN | FIN) == (SYN | FIN)
            || f & (SYN | RST) == (SYN | RST)
            || f & (FIN | RST) == (FIN | RST)
            || (f & ACK == 0 && f & (FIN | PSH | URG) != 0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn legitimate_segments_pass() {
            for ok in [
                SYN,
                SYN | ACK,
                ACK,
                PSH | ACK,
                FIN | ACK,
                FIN | PSH | ACK,
                RST,
                RST | ACK,
                URG | ACK | PSH,
            ] {
                assert!(!is_invalid(ok), "{:#04x} is legitimate", ok);
            }
            // ECE/CWR (ECN) bits do not change validity.
            assert!(!is_invalid(SYN | 0x40 | 0x80));
        }

        #[test]
        fn scan_probes_are_invalid() {
            for bad in [
                0,
                FIN,
                FIN | PSH | URG,
                SYN | FIN,
                SYN | FIN | ACK,
                SYN | RST,
                FIN | RST | ACK,
                PSH,
                URG,
            ] {
                assert!(is_invalid(bad), "{:#04x} is a scan probe", bad);
            }
        }

        #[test]
        fn exhaustive_against_the_rule_table() {
            for flags in 0u16..=255 {
                let f = flags as u8 & 0x3F;
                let has = |b: u8| f & b != 0;
                let expected = f == 0
                    || (has(SYN) && has(FIN))
                    || (has(SYN) && has(RST))
                    || (has(FIN) && has(RST))
                    || (!has(ACK) && (has(FIN) || has(PSH) || has(URG)));
                assert_eq!(is_invalid(flags as u8), expected, "flags {:#04x}", flags);
            }
        }
    }
}

pub mod canonical;

#[cfg(feature = "std")]
pub mod audit_log;

#[cfg(test)]
mod resource_tests {
    use super::*;

    /// The figures the numerical review derived by hand (N03), as an independent oracle.
    #[test]
    fn the_resource_estimate_matches_the_review() {
        let [counters, rate, records, hold] = resource_estimate(64, 64);
        assert_eq!(counters.1, 64 * 1024 * 1024, "1 MiB per possible CPU");
        assert_eq!(rate.1, 4096);
        assert_eq!(EVENT_RECORD_BYTES, 312);
        assert_eq!(records.1, 840);
        assert_eq!(hold.1, 205);
    }
}
