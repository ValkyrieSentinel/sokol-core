use std::net::Ipv6Addr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use log::{error, info, warn};

use common::NodeTelemetry;
use crate::cluster_state::BirdEyeView;
use crate::SentinelDb;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MeshCommand {
    BlockIp { ip: String, reason: String },
    UnblockIp { ip: String },
    EngageDefense,
    DisengageDefense,
    Alert { level: AlertLevel, message: String },
}

pub struct UpstreamBgpIntegration {
    upstream_router_addr: std::net::SocketAddr,
}

impl UpstreamBgpIntegration {
    pub fn new(upstream_router_addr: std::net::SocketAddr) -> Self {
        Self { upstream_router_addr }
    }

    pub async fn dispatch_flowspec_v6(&self, prefix: &str, prefix_len: u8, drop: bool) -> anyhow::Result<()> {
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
}

impl MeshOrchestrator {
    pub fn new(
        bird_eye: BirdEyeView,
        telemetry_rx: mpsc::Receiver<NodeTelemetry>,
        cmd_tx: mpsc::Sender<MeshCommand>,
        sntl_db: Arc<SentinelDb>,
        shutdown_rx: watch::Receiver<bool>,
        upstream_router_addr: std::net::SocketAddr,
        local_node_ipv6_prefix: String,
    ) -> Self {
        Self {
            bird_eye,
            telemetry_rx,
            cmd_tx,
            sntl_db,
            shutdown_rx,
            bgp_integration: UpstreamBgpIntegration::new(upstream_router_addr),
            local_node_ipv6_prefix,
        }
    }

    pub async fn run_telemetry_processor(&mut self) -> anyhow::Result<()> {
        info!("[MeshOrchestrator] Telemetry processor started (BGP Flowspec dispatch is not implemented; storms are only logged).");

        let mut storm_active = false;
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

                    let global_storm = self.bird_eye.is_global_storm_detected().await;

                    if global_storm && !storm_active {
                        storm_active = true;
                        warn!("[MeshOrchestrator] CRITICAL: Mesh-wide traffic storm or Anycast channel capacity limit breached!");

                        self.sntl_db.append("GLOBAL_STORM_ENGAGED_BGP_FLOWSPEC".to_string());

                        let prefix = self.local_node_ipv6_prefix.clone();
                        if let Err(e) = self.bgp_integration.dispatch_flowspec_v6(&prefix, 64, true).await {
                            error!("[MeshOrchestrator] Failed to dispatch BGP Flowspec drop: {:?}", e);
                        }

                        let _ = self.cmd_tx.send(MeshCommand::EngageDefense).await;

                    } else if !global_storm && storm_active {
                        storm_active = false;
                        info!("[MeshOrchestrator] Traffic normalized across Anycast mesh. Disengaging upstream BGP limits.");

                        self.sntl_db.append("GLOBAL_STORM_CLEARED".to_string());

                        let prefix = self.local_node_ipv6_prefix.clone();
                        let _ = self.bgp_integration.dispatch_flowspec_v6(&prefix, 64, false).await;

                        let _ = self.cmd_tx.send(MeshCommand::DisengageDefense).await;
                    }
                }
            }
        }

        Ok(())
    }
}