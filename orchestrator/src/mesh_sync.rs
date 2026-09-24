use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

use crate::cluster_state::{BirdEyeView, StormLatch, StormTransition};
use crate::SentinelDb;
use common::NodeTelemetry;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MeshCommand {
    BlockIp {
        ip: String,
        reason: String,
    },
    UnblockIp {
        ip: String,
    },
    EngageDefense,
    DisengageDefense,
    Alert {
        level: AlertLevel,
        message: String,
    },
    /// The sender's running dynamic blocks, sent to a peer when it (re)connects so a node that
    /// was cut off catches up on blocks it missed.
    BlockSync {
        blocks: Vec<SyncedBlock>,
    },
    /// Periodic load report of `node_id` (must be the authenticated sender).
    Telemetry {
        node_id: u64,
        rx_pps: u64,
        drops_per_sec: u64,
        under_attack: bool,
        blocks_active: u64,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SyncedBlock {
    pub ip: String,
    pub remaining_secs: u64,
}

/// Entries per BlockSync message (keeps each envelope well under the 128 KiB frame limit).
pub const SYNC_CHUNK: usize = 1000;

impl MeshCommand {
    pub fn telemetry_record(&self) -> Option<NodeTelemetry> {
        match *self {
            MeshCommand::Telemetry {
                node_id,
                rx_pps,
                drops_per_sec,
                under_attack,
                ..
            } => Some(NodeTelemetry {
                node_id,
                rx_packets: rx_pps,
                dropped_packets: drops_per_sec,
                anomaly_score: 0.0,
                under_attack: under_attack as u8,
                has_attacker_ip: 0,
                attacker_ip: [0; 16],
                _pad: [0; 6],
            }),
            _ => None,
        }
    }
}

/// What the telemetry processor last concluded, for metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClusterSummary {
    pub status_code: u8,
    pub nodes: usize,
    pub attacked: usize,
    pub storm_engaged: bool,
}

pub struct UpstreamBgpIntegration {
    upstream_router_addr: std::net::SocketAddr,
}

impl UpstreamBgpIntegration {
    pub fn new(upstream_router_addr: std::net::SocketAddr) -> Self {
        Self {
            upstream_router_addr,
        }
    }

    pub async fn dispatch_flowspec_v6(
        &self,
        prefix: &str,
        prefix_len: u8,
        drop: bool,
    ) -> anyhow::Result<()> {
        let ip_str = prefix.split('/').next().unwrap_or(prefix);
        let ipv6: Ipv6Addr = ip_str.parse()?;

        let mut nlri_buf = Vec::new();
        nlri_buf.push(prefix_len);
        let octets = ipv6.octets();

        let bytes_needed = (prefix_len as usize).div_ceil(8);
        if bytes_needed > 16 {
            anyhow::bail!("Invalid IPv6 Flowspec prefix length: {}", prefix_len);
        }
        nlri_buf.extend_from_slice(&octets[..bytes_needed]);

        // No BGP session exists yet: the NLRI is built but nothing is sent to the router.
        warn!(
            "[BGP Flowspec] NOT IMPLEMENTED: would {} upstream rule for IPv6 {}/{} on router {} (RFC 8955); nothing was sent",
            if drop { "announce drop" } else { "withdraw" },
            ipv6, prefix_len, self.upstream_router_addr
        );

        Ok(())
    }
}

pub struct MeshOrchestrator {
    bird_eye: BirdEyeView,
    telemetry_rx: mpsc::Receiver<NodeTelemetry>,
    cmd_tx: mpsc::Sender<MeshCommand>,
    sntl_db: Arc<SentinelDb>,
    shutdown_rx: watch::Receiver<bool>,
    bgp_integration: UpstreamBgpIntegration,
    local_node_ipv6_prefix: String,
    latch: StormLatch,
    summary_out: Arc<std::sync::RwLock<ClusterSummary>>,
}

impl MeshOrchestrator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bird_eye: BirdEyeView,
        telemetry_rx: mpsc::Receiver<NodeTelemetry>,
        cmd_tx: mpsc::Sender<MeshCommand>,
        sntl_db: Arc<SentinelDb>,
        shutdown_rx: watch::Receiver<bool>,
        upstream_router_addr: std::net::SocketAddr,
        local_node_ipv6_prefix: String,
        storm_hold: std::time::Duration,
        summary_out: Arc<std::sync::RwLock<ClusterSummary>>,
    ) -> Self {
        Self {
            bird_eye,
            telemetry_rx,
            cmd_tx,
            sntl_db,
            shutdown_rx,
            bgp_integration: UpstreamBgpIntegration::new(upstream_router_addr),
            local_node_ipv6_prefix,
            latch: StormLatch::new(storm_hold),
            summary_out,
        }
    }

    pub async fn run_telemetry_processor(&mut self) -> anyhow::Result<()> {
        info!("[MeshOrchestrator] Telemetry processor started (BGP Flowspec dispatch is not implemented; storms are only logged).");

        let mut shutdown_rx = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("[MeshOrchestrator] Shutdown signal received.");
                        break;
                    }
                }

                Some(telemetry) = self.telemetry_rx.recv() => {
                    self.bird_eye.ingest(telemetry).await;

                    if telemetry.has_attacker_ip != 0 {
                        let attacker_ipv6 = Ipv6Addr::from(telemetry.attacker_ip);
                        let ip_str = attacker_ipv6.to_string();

                        warn!(
                            "[MeshOrchestrator] Targeted threat detected: {} (Score: {:.2})",
                            ip_str, telemetry.anomaly_score
                        );

                        self.sntl_db.append(format!("AUTO_BLOCK_IP: {}", ip_str));

                        let block_cmd = MeshCommand::BlockIp {
                            ip: ip_str,
                            reason: format!("eBPF XDP probe drop (score: {:.2})", telemetry.anomaly_score),
                        };

                        let _ = self.cmd_tx.send(block_cmd).await;
                    }

                    let (status, nodes, attacked) = self.bird_eye.summary().await;
                    let transition = self.latch.update(status, std::time::Instant::now());
                    *self.summary_out.write().unwrap_or_else(|p| p.into_inner()) = ClusterSummary {
                        status_code: status.code(),
                        nodes,
                        attacked,
                        storm_engaged: self.latch.engaged(),
                    };

                    match transition {
                        Some(StormTransition::Engage) => {
                            warn!(
                                "[MeshOrchestrator] Distributed storm: {}/{} nodes under attack; defense engaged",
                                attacked, nodes
                            );
                            self.sntl_db.append(format!("CLUSTER_STORM_ENGAGED|Nodes:{}|Attacked:{}", nodes, attacked));

                            let prefix = self.local_node_ipv6_prefix.clone();
                            if let Err(e) = self.bgp_integration.dispatch_flowspec_v6(&prefix, 64, true).await {
                                error!("[MeshOrchestrator] Failed to dispatch BGP Flowspec drop: {:?}", e);
                            }
                            let _ = self.cmd_tx.send(MeshCommand::EngageDefense).await;
                        }
                        Some(StormTransition::Disengage) => {
                            info!(
                                "[MeshOrchestrator] Storm over: {}/{} nodes under attack; defense disengaged",
                                attacked, nodes
                            );
                            self.sntl_db.append(format!("CLUSTER_STORM_CLEARED|Nodes:{}|Attacked:{}", nodes, attacked));

                            let prefix = self.local_node_ipv6_prefix.clone();
                            let _ = self.bgp_integration.dispatch_flowspec_v6(&prefix, 64, false).await;
                            let _ = self.cmd_tx.send(MeshCommand::DisengageDefense).await;
                        }
                        None => {}
                    }
                }
            }
        }

        Ok(())
    }
}
