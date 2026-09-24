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
        let mut state = self.state.write().await;
        self.prune_stale_nodes_locked(&mut state).await;

        let total_nodes = state.nodes.len();
        if total_nodes == 0 {
            return ClusterStatus::Unknown;
        }

        let attacked_nodes = state
            .nodes
            .values()
            .filter(|n| n.telemetry.under_attack != 0)
            .count();

        let attack_ratio = attacked_nodes as f64 / total_nodes as f64;

        if attack_ratio > self.storm_threshold {
            ClusterStatus::DistributedStorm
        } else if attack_ratio > 0.0 {
            ClusterStatus::LocalIncident
        } else {
            ClusterStatus::Stable
        }
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
