//! Cluster status from the nodes' telemetry, and the storm latch that turns it into
//! engage/disengage transitions.
//!
//! Status (evaluated on every telemetry report, stale nodes pruned first):
//!
//! | nodes | share of nodes under attack      | status           |
//! |-------|----------------------------------|------------------|
//! | 0     | —                                | Unknown          |
//! | ≥ 1   | 0                                | Stable           |
//! | ≥ 1   | > 0 and ≤ storm threshold        | LocalIncident    |
//! | ≥ 1   | > storm threshold                | DistributedStorm |
//!
//! Storm latch (two states):
//!
//! | latch      | input                                          | next       | emits     |
//! |------------|------------------------------------------------|------------|-----------|
//! | Idle       | DistributedStorm                               | Engaged    | Engage    |
//! | Idle       | anything else                                  | Idle       | —         |
//! | Engaged    | DistributedStorm                               | Engaged    | — (calm timer reset) |
//! | Engaged    | not a storm, calm for less than `hold`         | Engaged    | —         |
//! | Engaged    | not a storm, calm for at least `hold`          | Idle       | Disengage |
//!
//! So Engage and Disengage strictly alternate, starting with Engage, and a storm that flickers
//! faster than `hold` produces one engagement instead of a flood of them.

use common::NodeTelemetry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterStatus {
    Stable,
    LocalIncident,
    DistributedStorm,
    Unknown,
}

impl ClusterStatus {
    /// Stable numeric code for metrics.
    pub fn code(self) -> u8 {
        match self {
            ClusterStatus::Unknown => 0,
            ClusterStatus::Stable => 1,
            ClusterStatus::LocalIncident => 2,
            ClusterStatus::DistributedStorm => 3,
        }
    }
}

pub fn classify(nodes: usize, attacked: usize, storm_threshold: f64) -> ClusterStatus {
    if nodes == 0 {
        return ClusterStatus::Unknown;
    }
    let ratio = attacked as f64 / nodes as f64;
    if ratio > storm_threshold {
        ClusterStatus::DistributedStorm
    } else if attacked > 0 {
        ClusterStatus::LocalIncident
    } else {
        ClusterStatus::Stable
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StormTransition {
    Engage,
    Disengage,
}

pub struct StormLatch {
    engaged: bool,
    calm_since: Option<Instant>,
    hold: Duration,
}

impl StormLatch {
    pub fn new(hold: Duration) -> Self {
        Self {
            engaged: false,
            calm_since: None,
            hold,
        }
    }

    pub fn engaged(&self) -> bool {
        self.engaged
    }

    pub fn update(&mut self, status: ClusterStatus, now: Instant) -> Option<StormTransition> {
        let storm = status == ClusterStatus::DistributedStorm;
        match (self.engaged, storm) {
            (false, true) => {
                self.engaged = true;
                self.calm_since = None;
                Some(StormTransition::Engage)
            }
            (false, false) => None,
            (true, true) => {
                self.calm_since = None;
                None
            }
            (true, false) => {
                let since = *self.calm_since.get_or_insert(now);
                if now.duration_since(since) >= self.hold {
                    self.engaged = false;
                    self.calm_since = None;
                    Some(StormTransition::Disengage)
                } else {
                    None
                }
            }
        }
    }
}

struct NodeState {
    telemetry: NodeTelemetry,
    last_seen: Instant,
}

struct ClusterState {
    nodes: HashMap<u64, NodeState>,
    total_dropped_packets: u64,
}

pub struct BirdEyeView {
    state: Arc<RwLock<ClusterState>>,
    storm_threshold: f64,
    ttl: Duration,
}

impl BirdEyeView {
    pub fn new(storm_threshold: f64, ttl: Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(ClusterState {
                nodes: HashMap::new(),
                total_dropped_packets: 0,
            })),
            storm_threshold,
            ttl,
        }
    }

    pub async fn ingest(&self, telemetry: NodeTelemetry) {
        let mut state = self.state.write().await;

        let old_drops = state
            .nodes
            .get(&telemetry.node_id)
            .map_or(0, |n| n.telemetry.dropped_packets);

        state.total_dropped_packets = state
            .total_dropped_packets
            .saturating_sub(old_drops)
            .saturating_add(telemetry.dropped_packets);

        state.nodes.insert(
            telemetry.node_id,
            NodeState {
                telemetry,
                last_seen: Instant::now(),
            },
        );
    }

    pub async fn global_cluster_health(&self) -> ClusterStatus {
        self.summary().await.0
    }

    /// (status, live nodes, nodes under attack), after pruning nodes not heard from in `ttl`.
    pub async fn summary(&self) -> (ClusterStatus, usize, usize) {
        let mut state = self.state.write().await;
        self.prune_stale_nodes_locked(&mut state).await;
        let nodes = state.nodes.len();
        let attacked = state
            .nodes
            .values()
            .filter(|n| n.telemetry.under_attack != 0)
            .count();
        (
            classify(nodes, attacked, self.storm_threshold),
            nodes,
            attacked,
        )
    }

    pub async fn is_global_storm_detected(&self) -> bool {
        matches!(
            self.global_cluster_health().await,
            ClusterStatus::DistributedStorm
        )
    }

    pub async fn total_cluster_drops(&self) -> u64 {
        let mut state = self.state.write().await;
        self.prune_stale_nodes_locked(&mut state).await;
        state.total_dropped_packets
    }

    async fn prune_stale_nodes_locked(&self, state: &mut ClusterState) {
        let now = Instant::now();
        let ttl = self.ttl;

        state.nodes.retain(|_, node| {
            let is_alive = now.duration_since(node.last_seen) <= ttl;
            if !is_alive {
                state.total_dropped_packets = state
                    .total_dropped_packets
                    .saturating_sub(node.telemetry.dropped_packets);
            }
            is_alive
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_matches_the_table() {
        assert_eq!(classify(0, 0, 0.5), ClusterStatus::Unknown);
        assert_eq!(classify(3, 0, 0.5), ClusterStatus::Stable);
        assert_eq!(
            classify(2, 1, 0.5),
            ClusterStatus::LocalIncident,
            "exactly the threshold is not a storm"
        );
        assert_eq!(classify(3, 2, 0.5), ClusterStatus::DistributedStorm);
        // Exhaustive over small clusters: total, and monotone in the number of attacked nodes.
        for nodes in 1..=12 {
            let mut last = 0;
            for attacked in 0..=nodes {
                let code = classify(nodes, attacked, 0.5).code();
                assert!(
                    code >= last,
                    "status must not improve as more nodes are attacked"
                );
                assert_ne!(code, 0, "a non-empty cluster always has a known status");
                last = code;
            }
        }
    }

    #[test]
    fn latch_follows_the_transition_table() {
        let t0 = Instant::now();
        let s = |secs| t0 + Duration::from_secs(secs);
        let mut latch = StormLatch::new(Duration::from_secs(30));
        assert_eq!(latch.update(ClusterStatus::LocalIncident, s(0)), None);
        assert_eq!(
            latch.update(ClusterStatus::DistributedStorm, s(1)),
            Some(StormTransition::Engage)
        );
        assert_eq!(latch.update(ClusterStatus::DistributedStorm, s(2)), None);
        assert_eq!(
            latch.update(ClusterStatus::Stable, s(3)),
            None,
            "calm, but not for 30 s yet"
        );
        assert_eq!(
            latch.update(ClusterStatus::DistributedStorm, s(20)),
            None,
            "storm resets the calm timer"
        );
        assert_eq!(latch.update(ClusterStatus::Stable, s(21)), None);
        assert_eq!(latch.update(ClusterStatus::Unknown, s(50)), None);
        assert_eq!(
            latch.update(ClusterStatus::Stable, s(51)),
            Some(StormTransition::Disengage)
        );
        assert!(!latch.engaged());
    }

    #[test]
    fn engage_and_disengage_strictly_alternate_for_any_input() {
        // Deterministic pseudo-random walks over statuses and time steps.
        let statuses = [
            ClusterStatus::Unknown,
            ClusterStatus::Stable,
            ClusterStatus::LocalIncident,
            ClusterStatus::DistributedStorm,
        ];
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..200 {
            let mut latch = StormLatch::new(Duration::from_secs(10));
            let mut now = Instant::now();
            let mut expected = StormTransition::Engage;
            for _ in 0..500 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                now += Duration::from_secs(seed % 7);
                let status = statuses[(seed >> 8) as usize % 4];
                if let Some(t) = latch.update(status, now) {
                    assert_eq!(t, expected);
                    if t == StormTransition::Engage {
                        assert_eq!(status, ClusterStatus::DistributedStorm);
                    }
                    expected = match t {
                        StormTransition::Engage => StormTransition::Disengage,
                        StormTransition::Disengage => StormTransition::Engage,
                    };
                }
                assert_eq!(latch.engaged(), expected == StormTransition::Disengage);
            }
        }
    }

    fn node(node_id: u64, dropped_packets: u64, under_attack: bool) -> NodeTelemetry {
        NodeTelemetry {
            node_id,
            rx_packets: 0,
            dropped_packets,
            anomaly_score: 0.0,
            under_attack: under_attack as u8,
            has_attacker_ip: 0,
            attacker_ip: [0; 16],
            _pad: [0; 6],
        }
    }

    #[tokio::test]
    async fn cluster_status_follows_the_share_of_attacked_nodes() {
        let bird_eye = BirdEyeView::new(0.4, Duration::from_secs(300));
        assert_eq!(
            bird_eye.global_cluster_health().await,
            ClusterStatus::Unknown
        );

        bird_eye.ingest(node(1, 0, false)).await;
        bird_eye.ingest(node(2, 0, false)).await;
        bird_eye.ingest(node(3, 20_000, true)).await;
        assert_eq!(
            bird_eye.global_cluster_health().await,
            ClusterStatus::LocalIncident
        );
        assert_eq!(bird_eye.total_cluster_drops().await, 20_000);

        bird_eye.ingest(node(4, 15_000, true)).await;
        bird_eye.ingest(node(5, 30_000, true)).await;
        assert_eq!(
            bird_eye.global_cluster_health().await,
            ClusterStatus::DistributedStorm
        );
        assert_eq!(bird_eye.total_cluster_drops().await, 65_000);

        bird_eye.ingest(node(5, 10_000, true)).await;
        assert_eq!(bird_eye.total_cluster_drops().await, 45_000);
    }
}
