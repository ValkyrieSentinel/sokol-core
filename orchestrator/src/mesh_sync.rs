use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

use crate::block_table::{Claim, ClaimId};
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
    /// The sender's block decision; `claim.issuer` must be the authenticated sender.
    Claim {
        claim: Claim,
    },
    /// The sender takes back its own claims (by id).
    Retract {
        issuer: u64,
        claims: Vec<ClaimId>,
    },
    EngageDefense,
    DisengageDefense,
    Alert {
        level: AlertLevel,
        message: String,
    },
    /// The sender's own live detector claims and own retractions (every claim's issuer must be
    /// the sender). Sent when a peer (re)connects and when it asks (SyncRequest), so a node that
    /// missed messages converges. `issuer` is the sender.
    BlockSync {
        issuer: u64,
        claims: Vec<Claim>,
        retracted: Vec<ClaimId>,
    },
    /// Digest of the sender's own claims; a peer whose view of them differs sends SyncRequest
    /// (anti-entropy).
    Digest {
        issuer: u64,
        digest: String,
    },
    /// The sender asks for the receiver's own claims (a BlockSync).
    SyncRequest {
        issuer: u64,
    },
    /// A detection made on this node by the orchestrator itself; never accepted from a peer.
    LocalDetection {
        ip: String,
        reason: String,
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

/// JSON bytes one BlockSync may take: the transport's frame limit is 128 KiB, and the signature,
/// envelope fields and framing need the rest (R26-02).
pub const SNAPSHOT_PAYLOAD_BUDGET: usize = 112 * 1024;

/// Splits a node's own claims and retractions into BlockSync messages whose JSON stays within
/// SNAPSHOT_PAYLOAD_BUDGET, counting claims and retracted ids alike (a large tombstone list is
/// split too). Always at least one message, so a peer learns about retractions with no claims.
pub fn pack_snapshot(issuer: u64, claims: Vec<Claim>, retracted: Vec<ClaimId>) -> Vec<MeshCommand> {
    let empty = MeshCommand::BlockSync {
        issuer,
        claims: Vec::new(),
        retracted: Vec::new(),
    };
    // Envelope wrapper ({"Command":...}) and slack for separators.
    let base = serde_json::to_vec(&empty).map_or(128, |v| v.len()) + 64;
    let mut out = Vec::new();
    let (mut cur_claims, mut cur_ids, mut size) = (Vec::new(), Vec::new(), base);
    let flush = |out: &mut Vec<MeshCommand>, c: &mut Vec<Claim>, r: &mut Vec<ClaimId>| {
        out.push(MeshCommand::BlockSync {
            issuer,
            claims: std::mem::take(c),
            retracted: std::mem::take(r),
        });
    };
    for claim in claims {
        let n = serde_json::to_vec(&claim).map_or(1024, |v| v.len()) + 1;
        if size + n > SNAPSHOT_PAYLOAD_BUDGET && !(cur_claims.is_empty() && cur_ids.is_empty()) {
            flush(&mut out, &mut cur_claims, &mut cur_ids);
            size = base;
        }
        size += n;
        cur_claims.push(claim);
    }
    for id in retracted {
        let n = id.len() + 3;
        if size + n > SNAPSHOT_PAYLOAD_BUDGET && !(cur_claims.is_empty() && cur_ids.is_empty()) {
            flush(&mut out, &mut cur_claims, &mut cur_ids);
            size = base;
        }
        size += n;
        cur_ids.push(id);
    }
    if !cur_claims.is_empty() || !cur_ids.is_empty() || out.is_empty() {
        flush(&mut out, &mut cur_claims, &mut cur_ids);
    }
    out
}

/// How often each node sends its digest to its peers.
pub const DIGEST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

impl MeshCommand {
    /// The node a command claims to come from, if it names one; the transport requires it to be
    /// the authenticated sender.
    pub fn claimed_sender(&self) -> Option<u64> {
        match self {
            MeshCommand::Claim { claim } => Some(claim.issuer),
            MeshCommand::Retract { issuer, .. }
            | MeshCommand::BlockSync { issuer, .. }
            | MeshCommand::Digest { issuer, .. }
            | MeshCommand::SyncRequest { issuer } => Some(*issuer),
            MeshCommand::Telemetry { node_id, .. } => Some(*node_id),
            _ => None,
        }
    }
}

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
        nlri_buf.extend_from_slice(
            octets
                .get(..bytes_needed)
                .ok_or_else(|| anyhow::anyhow!("Invalid Flowspec prefix length: {}", prefix_len))?,
        );

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

                        let block_cmd = MeshCommand::LocalDetection {
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
