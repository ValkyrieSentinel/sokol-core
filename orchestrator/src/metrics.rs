//! Prometheus text exposition of the node's counters (served on `--metrics-bind`).
use std::fmt::Write;

use common::{drop_reason, DROP_REASON_SLOTS};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
    pub drops_by_reason: [u64; DROP_REASON_SLOTS],
    pub events_suppressed: u64,
    pub blocks_active: usize,
    pub p2p_peers: usize,
    pub audit_queue_overflow: u64,
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} {}", name, kind);
}

pub fn render(s: &Snapshot) -> String {
    let mut out = String::new();

    family(
        &mut out,
        "sokol_xdp_rx_packets_total",
        "counter",
        "Packets seen by the XDP program.",
    );
    let _ = writeln!(out, "sokol_xdp_rx_packets_total {}", s.rx_packets);
    family(
        &mut out,
        "sokol_xdp_rx_bytes_total",
        "counter",
        "Bytes seen by the XDP program.",
    );
    let _ = writeln!(out, "sokol_xdp_rx_bytes_total {}", s.rx_bytes);

    family(
        &mut out,
        "sokol_xdp_dropped_packets_total",
        "counter",
        "Packets dropped in XDP, by reason.",
    );
    for (code, count) in s.drops_by_reason.iter().enumerate() {
        if let Some(reason) = drop_reason::name(code as u16) {
            let _ = writeln!(
                out,
                "sokol_xdp_dropped_packets_total{{reason=\"{}\"}} {}",
                reason, count
            );
        }
    }

    family(
        &mut out,
        "sokol_xdp_events_suppressed_total",
        "counter",
        "Kernel events withheld by the per-CPU rate limit.",
    );
    let _ = writeln!(
        out,
        "sokol_xdp_events_suppressed_total {}",
        s.events_suppressed
    );
    family(
        &mut out,
        "sokol_blocks_active",
        "gauge",
        "Addresses currently blocked (static and dynamic).",
    );
    let _ = writeln!(out, "sokol_blocks_active {}", s.blocks_active);
    family(
        &mut out,
        "sokol_p2p_active_peers",
        "gauge",
        "Authenticated mesh peers connected.",
    );
    let _ = writeln!(out, "sokol_p2p_active_peers {}", s.p2p_peers);
    family(
        &mut out,
        "sokol_audit_queue_overflow_total",
        "counter",
        "Audit records lost because the write queue was full.",
    );
    let _ = writeln!(
        out,
        "sokol_audit_queue_overflow_total {}",
        s.audit_queue_overflow
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_family_with_reason_labels() {
        let mut snap = Snapshot {
            rx_packets: 10,
            rx_bytes: 1000,
            dropped_packets: 3,
            events_suppressed: 7,
            blocks_active: 2,
            p2p_peers: 1,
            audit_queue_overflow: 0,
            ..Default::default()
        };
        snap.drops_by_reason[drop_reason::SLOW_PATH_LPM_HIT as usize] = 2;
        snap.drops_by_reason[drop_reason::FRAGMENT_BLOCKED as usize] = 1;
        let text = render(&snap);

        assert!(text.contains("sokol_xdp_rx_packets_total 10\n"));
        assert!(text.contains("sokol_xdp_dropped_packets_total{reason=\"blocklist\"} 2\n"));
        assert!(text.contains("sokol_xdp_dropped_packets_total{reason=\"fragment_blocked\"} 1\n"));
        assert!(text.contains("sokol_xdp_events_suppressed_total 7\n"));
        assert!(text.contains("sokol_blocks_active 2\n"));
        assert!(text.contains("sokol_p2p_active_peers 1\n"));
        // Every sample line belongs to a declared family.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let name = line.split(['{', ' ']).next().unwrap();
            assert!(
                text.contains(&format!("# TYPE {} ", name)),
                "{} has no TYPE line",
                name
            );
        }
    }
}
