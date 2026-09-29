//! Prometheus text exposition of the node's counters (served on `--metrics-bind`).
use std::fmt::Write;

use common::{drop_reason, DROP_REASON_SLOTS};

/// What removed blocks did while in force (from the XDP hit counters).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct OutcomeStats {
    /// Blocks that dropped at least one packet.
    pub effective: u64,
    /// Blocks that dropped nothing: nothing came, or the decision was not needed.
    pub idle: u64,
    /// Blocks whose counter could not be read.
    pub unknown: u64,
    /// Packets dropped by removed blocks.
    pub hits: u64,
    /// Outcomes lost before they were collected.
    pub dropped: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub dropped_packets: u64,
    pub drops_by_reason: [u64; DROP_REASON_SLOTS],
    pub events_suppressed: u64,
    pub events_lost: u64,
    pub events_malformed: u64,
    pub blocks_active_v4: usize,
    pub blocks_active_v6: usize,
    pub blocks_capacity: usize,
    pub blocks_pending: usize,
    pub event_ids_remembered: usize,
    pub event_ids_evicted: u64,
    pub strikes_remembered: usize,
    pub strikes_evicted: u64,
    pub claims_waiting: usize,
    pub p2p_peers: usize,
    pub audit_queue_overflow: u64,
    pub defense_strict: bool,
    pub audit_healthy: bool,
    pub state_healthy: bool,
    pub state_pending_secs: f64,
    pub state_restore_ok: bool,
    pub protected_refresh_ok: bool,
    pub blocks_pending_oldest_secs: f64,
    pub mesh_handshakes_refused: u64,
    pub mesh_handshake_timeouts: u64,
    pub mesh_frames_delayed: u64,
    pub mesh_sync_requests_throttled: u64,
    pub mesh_dropped_urgent: u64,
    /// Envelopes refused, in `p2p::EnvelopeError::LABELS` order.
    pub mesh_rejected: [u64; 5],
    pub clock_steps: u64,
    pub clock_last_step_ms: i64,
    pub mesh_dropped_bulk: u64,
    pub ipc_lines_delayed: u64,
    pub tick_secs: f64,
    pub xdp_native: bool,
    pub outcomes: OutcomeStats,
    pub tick_max_secs: f64,
    pub audit_write_errors: u64,
    pub audit_lost: u64,
    pub audit_sync_age_ms: u64,
    pub flowspec_announced: usize,
    pub external_attacks: usize,
    pub cluster_status: u8,
    pub cluster_nodes: usize,
    pub cluster_attacked: usize,
    pub cluster_storm_engaged: bool,
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} {}", name, kind);
}

pub fn render(s: &Snapshot) -> String {
    let mut out = String::new();
    family(
        &mut out,
        "sokol_build_info",
        "gauge",
        "Always 1; the labels name the running build (version and source commit).",
    );
    let _ = writeln!(
        out,
        "sokol_build_info{{version=\"{}\",build=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION"),
        env!("SOKOL_BUILD_ID")
    );

    family(
        &mut out,
        "sokol_xdp_mode",
        "gauge",
        "1 for the mode the XDP program runs in: native (driver) or generic (slower fallback).",
    );
    let _ = writeln!(
        out,
        "sokol_xdp_mode{{mode=\"{}\"}} 1",
        if s.xdp_native { "native" } else { "generic" }
    );
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
        "sokol_xdp_events_lost_total",
        "counter",
        "Kernel events within the rate limit that found the ring buffer full (the reader was behind).",
    );
    let _ = writeln!(out, "sokol_xdp_events_lost_total {}", s.events_lost);
    family(
        &mut out,
        "sokol_xdp_events_malformed_total",
        "counter",
        "Ring-buffer records of the wrong size, refused: the XDP program and this build disagree on the event layout.",
    );
    let _ = writeln!(
        out,
        "sokol_xdp_events_malformed_total {}",
        s.events_malformed
    );
    family(
        &mut out,
        "sokol_blocks_active",
        "gauge",
        "Addresses currently blocked (static and dynamic), per blocklist map.",
    );
    let _ = writeln!(
        out,
        "sokol_blocks_active{{family=\"ipv4\"}} {}",
        s.blocks_active_v4
    );
    let _ = writeln!(
        out,
        "sokol_blocks_active{{family=\"ipv6\"}} {}",
        s.blocks_active_v6
    );
    family(
        &mut out,
        "sokol_blocks_capacity",
        "gauge",
        "Entries each blocklist map can hold.",
    );
    let _ = writeln!(out, "sokol_blocks_capacity {}", s.blocks_capacity);
    family(
        &mut out,
        "sokol_blocks_pending",
        "gauge",
        "Targets whose kernel entry does not match the block decisions yet (retried every second).",
    );
    let _ = writeln!(out, "sokol_blocks_pending {}", s.blocks_pending);
    family(
        &mut out,
        "sokol_event_ids_remembered",
        "gauge",
        "Detector event ids remembered to recognise resends.",
    );
    let _ = writeln!(out, "sokol_event_ids_remembered {}", s.event_ids_remembered);
    family(
        &mut out,
        "sokol_event_ids_evicted_total",
        "counter",
        "Event ids forgotten early because the memory was full (a resend of one adds a strike).",
    );
    let _ = writeln!(out, "sokol_event_ids_evicted_total {}", s.event_ids_evicted);
    family(
        &mut out,
        "sokol_strikes_remembered",
        "gauge",
        "Targets whose detector strikes are remembered (bounded by MAX_STRIKES).",
    );
    let _ = writeln!(out, "sokol_strikes_remembered {}", s.strikes_remembered);
    family(
        &mut out,
        "sokol_strikes_evicted_total",
        "counter",
        "Targets whose strikes were forgotten early because the memory was full (they restart at the base TTL).",
    );
    let _ = writeln!(out, "sokol_strikes_evicted_total {}", s.strikes_evicted);
    family(
        &mut out,
        "sokol_claims_waiting",
        "gauge",
        "Peers' claims known here but waiting for a slot in their issuer's envelope (ADR-0007): not enforced yet.",
    );
    let _ = writeln!(out, "sokol_claims_waiting {}", s.claims_waiting);
    family(
        &mut out,
        "sokol_p2p_active_peers",
        "gauge",
        "Authenticated mesh nodes connected (a node with two connections counts once).",
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

    family(
        &mut out,
        "sokol_audit_healthy",
        "gauge",
        "1 while the audit log is written and fsynced; 0 while the node is DEGRADED (enforcement continues).",
    );
    let _ = writeln!(out, "sokol_audit_healthy {}", s.audit_healthy as u8);
    family(
        &mut out,
        "sokol_state_healthy",
        "gauge",
        "1 while --state-file is written; 0 while this node's decisions are not being persisted.",
    );
    let _ = writeln!(out, "sokol_state_healthy {}", s.state_healthy as u8);
    family(
        &mut out,
        "sokol_state_pending_seconds",
        "gauge",
        "How long the oldest change to this node's decisions has waited to reach --state-file.",
    );
    let _ = writeln!(
        out,
        "sokol_state_pending_seconds {:.3}",
        s.state_pending_secs
    );
    family(
        &mut out,
        "sokol_state_restore_ok",
        "gauge",
        "0 after a state file failed to restore, until ACCEPT_STATE_LOSS on the control socket.",
    );
    let _ = writeln!(out, "sokol_state_restore_ok {}", s.state_restore_ok as u8);
    family(
        &mut out,
        "sokol_protected_refresh_ok",
        "gauge",
        "0 while this host's addresses and gateways cannot be re-read (the last known ones stay protected).",
    );
    let _ = writeln!(
        out,
        "sokol_protected_refresh_ok {}",
        s.protected_refresh_ok as u8
    );
    let gauges: [(&str, &str, f64); 3] = [
        (
            "sokol_blocks_pending_oldest_seconds",
            "How long the oldest failing kernel map operation has been retried.",
            s.blocks_pending_oldest_secs,
        ),
        (
            "sokol_tick_seconds",
            "Time the last maintenance tick took (expiry, state hand-off, digest, heartbeat, stats).",
            s.tick_secs,
        ),
        (
            "sokol_tick_seconds_max",
            "Longest maintenance tick since start.",
            s.tick_max_secs,
        ),
    ];
    for (name, help, value) in gauges {
        family(&mut out, name, "gauge", help);
        let _ = writeln!(out, "{} {:.6}", name, value);
    }
    let counters: [(&str, &str, u64); 4] = [
        (
            "sokol_mesh_handshakes_refused_total",
            "Connections refused: too many not yet authenticated (in total or from one address).",
            s.mesh_handshakes_refused,
        ),
        (
            "sokol_mesh_handshake_timeouts_total",
            "Connections closed for not authenticating within the handshake timeout.",
            s.mesh_handshake_timeouts,
        ),
        (
            "sokol_mesh_frames_delayed_total",
            "Frames from an authenticated peer read late because it exceeded its rate.",
            s.mesh_frames_delayed,
        ),
        (
            "sokol_mesh_sync_requests_throttled_total",
            "Snapshot requests not answered because the peer got one less than 5 s ago.",
            s.mesh_sync_requests_throttled,
        ),
    ];
    for (name, help, value) in counters {
        family(&mut out, name, "counter", help);
        let _ = writeln!(out, "{} {}", name, value);
    }
    family(
        &mut out,
        "sokol_block_outcomes_total",
        "counter",
        "Removed blocks by observed effect: dropped packets, dropped none, counter unreadable.",
    );
    for (effect, n) in [
        ("dropped", s.outcomes.effective),
        ("none", s.outcomes.idle),
        ("unknown", s.outcomes.unknown),
    ] {
        let _ = writeln!(
            out,
            "sokol_block_outcomes_total{{effect=\"{}\"}} {}",
            effect, n
        );
    }
    family(
        &mut out,
        "sokol_block_outcome_packets_total",
        "counter",
        "Packets dropped by blocks, counted when each block is removed.",
    );
    let _ = writeln!(out, "sokol_block_outcome_packets_total {}", s.outcomes.hits);
    family(
        &mut out,
        "sokol_block_outcomes_lost_total",
        "counter",
        "Block outcomes lost before they were collected.",
    );
    let _ = writeln!(
        out,
        "sokol_block_outcomes_lost_total {}",
        s.outcomes.dropped
    );
    family(
        &mut out,
        "sokol_mesh_broadcasts_dropped_total",
        "counter",
        "Broadcasts not queued because a peer's queue was full: urgent (block decisions) or bulk (reports).",
    );
    let _ = writeln!(
        out,
        "sokol_mesh_broadcasts_dropped_total{{class=\"urgent\"}} {}",
        s.mesh_dropped_urgent
    );
    let _ = writeln!(
        out,
        "sokol_mesh_broadcasts_dropped_total{{class=\"bulk\"}} {}",
        s.mesh_dropped_bulk
    );
    family(
        &mut out,
        "sokol_mesh_envelopes_rejected_total",
        "counter",
        "Mesh envelopes refused, by reason; stale_timestamp means a peer's clock is out of the 30 s window.",
    );
    for (label, n) in crate::p2p::EnvelopeError::LABELS
        .iter()
        .zip(s.mesh_rejected)
    {
        let _ = writeln!(
            out,
            "sokol_mesh_envelopes_rejected_total{{reason=\"{}\"}} {}",
            label, n
        );
    }
    family(
        &mut out,
        "sokol_clock_steps_total",
        "counter",
        "Wall-clock steps of 5 s or more against the monotonic clock (ADR-0017); blocks in force keep their length.",
    );
    let _ = writeln!(out, "sokol_clock_steps_total {}", s.clock_steps);
    family(
        &mut out,
        "sokol_clock_last_step_seconds",
        "gauge",
        "Size of the last wall-clock step: positive forward, negative back.",
    );
    let _ = writeln!(
        out,
        "sokol_clock_last_step_seconds {:.3}",
        s.clock_last_step_ms as f64 / 1000.0
    );
    family(
        &mut out,
        "sokol_ipc_lines_delayed_total",
        "counter",
        "Detector lines handled late because a connection or the IPC socket exceeded its rate.",
    );
    let _ = writeln!(out, "sokol_ipc_lines_delayed_total {}", s.ipc_lines_delayed);
    family(
        &mut out,
        "sokol_audit_write_errors_total",
        "counter",
        "Failed audit writes and fsyncs.",
    );
    let _ = writeln!(
        out,
        "sokol_audit_write_errors_total {}",
        s.audit_write_errors
    );
    family(
        &mut out,
        "sokol_audit_lost_total",
        "counter",
        "Audit records that could not be written while the log was unavailable (queue overflow is counted separately).",
    );
    let _ = writeln!(out, "sokol_audit_lost_total {}", s.audit_lost);
    family(
        &mut out,
        "sokol_audit_last_sync_age_seconds",
        "gauge",
        "Time since the audit log was last fsynced successfully.",
    );
    let _ = writeln!(
        out,
        "sokol_audit_last_sync_age_seconds {:.3}",
        s.audit_sync_age_ms as f64 / 1000.0
    );
    family(
        &mut out,
        "sokol_defense_strict",
        "gauge",
        "1 while a distributed storm has XDP in strict mode (--storm-mode strict).",
    );
    let _ = writeln!(out, "sokol_defense_strict {}", s.defense_strict as u8);
    family(
        &mut out,
        "sokol_flowspec_announced",
        "gauge",
        "Blocks announced upstream as BGP Flowspec discard rules.",
    );
    let _ = writeln!(out, "sokol_flowspec_announced {}", s.flowspec_announced);
    family(
        &mut out,
        "sokol_external_attacks_active",
        "gauge",
        "Attack reports from flow detectors (FastNetMon) currently in force for this node.",
    );
    let _ = writeln!(out, "sokol_external_attacks_active {}", s.external_attacks);
    family(
        &mut out,
        "sokol_cluster_status",
        "gauge",
        "Cluster status: 0 unknown, 1 stable, 2 local incident, 3 distributed storm.",
    );
    let _ = writeln!(out, "sokol_cluster_status {}", s.cluster_status);
    family(
        &mut out,
        "sokol_cluster_nodes",
        "gauge",
        "Nodes (this one included) that reported telemetry recently.",
    );
    let _ = writeln!(out, "sokol_cluster_nodes {}", s.cluster_nodes);
    family(
        &mut out,
        "sokol_cluster_nodes_under_attack",
        "gauge",
        "Nodes reporting drops above their --attack-drops-per-sec.",
    );
    let _ = writeln!(
        out,
        "sokol_cluster_nodes_under_attack {}",
        s.cluster_attacked
    );
    family(
        &mut out,
        "sokol_cluster_storm_engaged",
        "gauge",
        "1 while the distributed-storm latch is engaged.",
    );
    let _ = writeln!(
        out,
        "sokol_cluster_storm_engaged {}",
        s.cluster_storm_engaged as u8
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
            events_lost: 6,
            mesh_rejected: [0, 0, 3, 0, 0],
            clock_steps: 2,
            clock_last_step_ms: -3_600_000,
            claims_waiting: 5,
            events_malformed: 2,
            strikes_remembered: 3,
            strikes_evicted: 4,
            blocks_active_v4: 2,
            blocks_active_v6: 1,
            blocks_capacity: 65536,
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
        assert!(text.contains("sokol_xdp_events_lost_total 6\n"));
        assert!(
            text.contains("sokol_mesh_envelopes_rejected_total{reason=\"stale_timestamp\"} 3\n")
        );
        assert!(text.contains("sokol_clock_steps_total 2\n"));
        assert!(text.contains("sokol_clock_last_step_seconds -3600.000\n"));
        assert!(text.contains("sokol_claims_waiting 5\n"));
        assert!(text.contains("sokol_xdp_events_malformed_total 2\n"));
        assert!(text.contains("sokol_strikes_remembered 3\n"));
        assert!(text.contains("sokol_strikes_evicted_total 4\n"));
        assert!(text.contains("sokol_blocks_active{family=\"ipv4\"} 2\n"));
        assert!(text.contains("sokol_blocks_capacity 65536\n"));
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
