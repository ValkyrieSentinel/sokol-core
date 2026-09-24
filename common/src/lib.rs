#![cfg_attr(not(feature = "std"), no_std)]

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
    pub vfr_anomalies: u64,
    pub fast_path_hits: u64,
    pub slow_path_hits: u64,
    pub redirected_packets: u64,
}

impl PacketStats {
    pub const ZERO: Self = Self {
        rx_packets: 0,
        rx_bytes: 0,
        dropped_packets: 0,
        vfr_anomalies: 0,
        fast_path_hits: 0,
        slow_path_hits: 0,
        redirected_packets: 0,
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
}

/// Bits of the eBPF `CONFIG` map (index 0).
pub mod config_flags {
    /// Drop every IPv4 fragment (for hosts whose policy forbids fragmentation).
    pub const DROP_IPV4_FRAGMENTS: u32 = 1 << 0;
}

pub mod atp;
pub mod canonical;
pub mod crypto;
pub mod dag;

#[cfg(feature = "std")]
pub mod audit_log;

#[cfg(feature = "std")]
pub mod pqc;