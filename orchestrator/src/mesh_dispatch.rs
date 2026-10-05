//! Commands that reach this node's decisions: from peers (authenticated and sender-bound by
//! `p2p.rs`) and from this node's own telemetry processor (`LocalCommand`, never on the wire).
//! Moved out of `main()` by the 2026-10-05 review (F7), unchanged in behaviour, so the most
//! security-relevant input after the transport has unit tests instead of only smoke coverage.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::NodeTelemetry;
use tokio::sync::mpsc;

use crate::block_policy::PolicyHandle;
use crate::block_table::{self, parse_target, show, Adoption, Blocklist};
use crate::defense::{self, ConfigMap, Defense};
use crate::mesh_sync::{self, LocalCommand, MeshCommand};
use crate::p2p::{now_ms, NodeCrypto, PeerRegistry};
use crate::{
    enforce_block_local, ip_tag, push_telemetry, send_snapshot, ttl_label, Detection, SentinelDb,
    SharedBlockTable,
};

/// Everything a command may touch. One task owns it, so commands apply in arrival order.
pub struct MeshDispatch<B: Blocklist, M: ConfigMap> {
    pub blocks: SharedBlockTable<B>,
    pub policy: PolicyHandle,
    pub db: Arc<SentinelDb>,
    pub registry: PeerRegistry,
    pub crypto: Arc<NodeCrypto>,
    pub node_id: u64,
    pub defense: Arc<Defense<M>>,
    /// When each peer last got a snapshot (bounded by the pinned peers: a SyncRequest names
    /// its authenticated sender).
    pub snapshots: mesh_sync::Cooldown,
    pub sync_throttled: Arc<AtomicU64>,
    pub telemetry_tx: mpsc::Sender<NodeTelemetry>,
}

impl<B: Blocklist + Send + 'static, M: ConfigMap + 'static> MeshDispatch<B, M> {
    /// Serves both channels until both are closed.
    pub async fn run(
        mut self,
        mut peer_rx: mpsc::Receiver<MeshCommand>,
        mut local_rx: mpsc::Receiver<LocalCommand>,
    ) {
        loop {
            tokio::select! {
                Some(cmd) = peer_rx.recv() => self.peer(cmd).await,
                Some(cmd) = local_rx.recv() => self.local(cmd).await,
                else => return,
            }
        }
    }

    /// A command from an authenticated peer. Every variant is handled; none is local-only.
    pub async fn peer(&mut self, cmd: MeshCommand) {
        match cmd {
            MeshCommand::Claim { claim } => {
                let shown = claim.target.clone();
                let reason = claim.reason.clone();
                let issuer = claim.issuer;
                let expires = claim.expires_ms;
                let refusal = claim
                    .net()
                    .and_then(|n| self.policy.current().check_net(n).err());
                let (now, wall) = (block_table::local_ms(), now_ms());
                let result = self
                    .blocks
                    .lock()
                    .await
                    .adopt(claim, refusal.is_none(), now);
                match (result, refusal) {
                    (Adoption::Enforced, _) => {
                        let left = expires.map(|e| Duration::from_millis(e.saturating_sub(wall)));
                        log::warn!(
                            "[Mesh] Synchronized block for {} from node {} ({}): {}",
                            shown,
                            issuer,
                            ttl_label(left),
                            reason
                        );
                        let tag = parse_target(&shown).map(ip_tag).unwrap_or("V4");
                        self.db.append(format!(
                            "MESH_BLOCK_{}|IP:{}|TTL:{}|Reason:{}",
                            tag,
                            shown,
                            ttl_label(left),
                            reason
                        ));
                        let telemetry_msg = format!(
                            "DB_LOG:NODE={}|TIER=MeshBlock|IP={}|VEC={}\n",
                            self.node_id, shown, reason
                        );
                        push_telemetry(&telemetry_msg).await;
                    }
                    (Adoption::Held(held @ ("quorum" | "quota" | "envelope")), _) => {
                        log::warn!(
                            "[Mesh] Holding block for {} from node {} ({}): {}",
                            shown,
                            issuer,
                            held,
                            reason
                        );
                        self.db.append(format!(
                            "MESH_BLOCK_HELD|IP:{}|Issuer:{}|Why:{}|Reason:{}",
                            shown, issuer, held, reason
                        ));
                    }
                    (Adoption::Held(_), Some(why)) => {
                        log::error!(
                            "[Mesh] Refusing mesh block for protected {} ({}): {}",
                            shown,
                            why,
                            reason
                        );
                        self.db.append(format!(
                            "MESH_BLOCK_REFUSED|IP:{}|Protected:{}|Reason:{}",
                            shown, why, reason
                        ));
                    }
                    (Adoption::Refused(why), _) => {
                        log::warn!(
                            "[Mesh] Ignoring claim for {} from node {}: {}",
                            shown,
                            issuer,
                            why
                        )
                    }
                    _ => {}
                }
            }
            MeshCommand::Retract { issuer, claims } => {
                let lifted =
                    self.blocks
                        .lock()
                        .await
                        .retract(issuer, &claims, block_table::local_ms());
                for net in lifted {
                    log::info!(
                        "[Mesh] Unblocked {}: node {} took back its block",
                        show(&net),
                        issuer
                    );
                    self.db
                        .append(format!("MESH_UNBLOCK|IP:{}|Issuer:{}", show(&net), issuer));
                }
            }
            MeshCommand::BlockSync {
                issuer,
                claims,
                retracted,
            } => {
                let (now, wall) = (block_table::local_ms(), now_ms());
                let mut adopted = 0;
                for claim in claims {
                    let refusal = claim
                        .net()
                        .and_then(|n| self.policy.current().check_net(n).err());
                    let (shown, secs) = (
                        claim.target.clone(),
                        claim.expires_ms.map(|e| e.saturating_sub(wall) / 1000),
                    );
                    let tag = parse_target(&shown).map(ip_tag).unwrap_or("V4");
                    if self
                        .blocks
                        .lock()
                        .await
                        .adopt(claim, refusal.is_none(), now)
                        == Adoption::Enforced
                    {
                        adopted += 1;
                        self.db.append(format!(
                            "MESH_BLOCK_{}|IP:{}|TTL:{}|Reason:sync from node {}",
                            tag,
                            shown,
                            secs.map_or("permanent".into(), |s| format!("{}s", s)),
                            issuer
                        ));
                    }
                }
                let lifted = self.blocks.lock().await.retract(issuer, &retracted, now);
                for net in &lifted {
                    self.db
                        .append(format!("MESH_UNBLOCK|IP:{}|Issuer:{}", show(net), issuer));
                }
                if adopted > 0 || !lifted.is_empty() {
                    log::warn!(
                    "[Mesh] Sync from node {}: adopted {} blocks missed while disconnected, {} taken back",
                    issuer,
                    adopted,
                    lifted.len()
                );
                }
            }
            MeshCommand::Digest { issuer, digest } => {
                // Our view of the sender's own claims differs: ask the sender for them.
                let ours = self
                    .blocks
                    .lock()
                    .await
                    .digest_of(issuer, block_table::local_ms());
                if ours != digest {
                    if let Some(addr) = self.registry.addr_of(issuer).await {
                        log::info!(
                            "[Mesh] Node {}'s claims differ from our view; asking it",
                            issuer
                        );
                        let cmd = MeshCommand::SyncRequest {
                            issuer: self.node_id,
                        };
                        let _ = self
                            .registry
                            .send_to(addr, &cmd, self.node_id, &self.crypto)
                            .await;
                    }
                }
            }
            MeshCommand::SyncRequest { issuer } => {
                // A snapshot is the most expensive answer (the whole table, signed frames):
                // at most one per peer per SYNC_COOLDOWN. A request dropped here is repeated
                // by the peer's next digest mismatch.
                if !self.snapshots.allow(issuer, std::time::Instant::now()) {
                    self.sync_throttled.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                if let Some(addr) = self.registry.addr_of(issuer).await {
                    send_snapshot(
                        addr,
                        &self.blocks,
                        &self.registry,
                        self.node_id,
                        &self.crypto,
                    )
                    .await;
                }
            }
            MeshCommand::Alert { level, message } => {
                log::info!("[MESH ALERT {:?}] {}", level, message);
            }
            telemetry @ MeshCommand::Telemetry { .. } => {
                if let Some(record) = telemetry.telemetry_record() {
                    let _ = self.telemetry_tx.try_send(record);
                }
            }
        }
    }

    /// A decision of this node's own telemetry processor.
    pub async fn local(&mut self, cmd: LocalCommand) {
        match cmd {
            LocalCommand::Detection { ip, reason } => {
                // The telemetry processor's own detections: enforced here and shared like
                // any other local decision.
                if let Some(net) = parse_target(&ip) {
                    enforce_block_local(
                        net,
                        &reason,
                        &self.blocks,
                        &self.db,
                        &self.registry,
                        self.node_id,
                        &self.crypto,
                        &self.policy.current(),
                        Detection::default(),
                    )
                    .await;
                }
            }
            c @ (LocalCommand::EngageDefense | LocalCommand::DisengageDefense) => {
                let engaged = matches!(c, LocalCommand::EngageDefense);
                match self.defense.set(engaged) {
                    Ok(flags) if self.defense.mode() == defense::StormMode::Strict => {
                        let label = if engaged { "Strict" } else { "Normal" };
                        log::warn!(
                            "[Defense] Distributed storm {}: XDP mode {} (flags {:#x})",
                            if engaged { "engaged" } else { "over" },
                            label,
                            flags
                        );
                        self.db
                            .append(format!("DEFENSE_MODE|{}|Flags:{:#x}", label, flags));
                    }
                    Ok(_) => log::warn!(
                        "[Defense] Distributed storm {} (--storm-mode observe: XDP unchanged)",
                        if engaged { "engaged" } else { "over" }
                    ),
                    Err(e) => log::error!("[Defense] Cannot update the XDP config: {:?}", e),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_policy::BlockPolicy;
    use crate::block_table::{BlockTable, Claim, ClaimKind, TtlPolicy};
    use crate::p2p::TrustStore;
    use ipnet::IpNet;
    use std::sync::Mutex;

    /// Records what the table asked the kernel map to hold.
    #[derive(Clone, Default)]
    struct Lists(Arc<Mutex<std::collections::HashSet<IpNet>>>);
    impl Blocklist for Lists {
        fn add(&mut self, net: IpNet) -> Result<(), aya::maps::MapError> {
            self.0.lock().unwrap().insert(net);
            Ok(())
        }
        fn delete(&mut self, net: IpNet) -> Result<(), aya::maps::MapError> {
            self.0.lock().unwrap().remove(&net);
            Ok(())
        }
        fn hits(&self, _: IpNet) -> Option<u64> {
            Some(0)
        }
    }

    /// The XDP CONFIG map's last written flags.
    #[derive(Clone, Default)]
    struct Config(Arc<Mutex<Option<u32>>>);
    impl ConfigMap for Config {
        fn write(&mut self, flags: u32) -> Result<(), aya::maps::MapError> {
            *self.0.lock().unwrap() = Some(flags);
            Ok(())
        }
    }

    struct Node {
        dispatch: MeshDispatch<Lists, Config>,
        kernel: Lists,
        config: Config,
        audit: String,
    }

    const NODE: u64 = 1;
    const PEER: u64 = 2;

    fn node(name: &str, protect: Option<&str>) -> Node {
        let dir =
            std::env::temp_dir().join(format!("sokol-dispatch-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let audit = dir.join("audit.log").to_string_lossy().into_owned();
        let kernel = Lists::default();
        let config = Config::default();
        let mut policy = BlockPolicy::builtin();
        if let Some(net) = protect {
            policy.protect(net.parse().unwrap(), "test");
        }
        let (telemetry_tx, _) = mpsc::channel(4);
        let dispatch = MeshDispatch {
            blocks: Arc::new(tokio::sync::Mutex::new(BlockTable::with_lists(
                kernel.clone(),
                TtlPolicy {
                    base: Duration::from_secs(60),
                    max: Duration::from_secs(600),
                },
                NODE,
            ))),
            policy: PolicyHandle::new(policy),
            db: Arc::new(SentinelDb::init(&audit, None).unwrap()),
            registry: PeerRegistry::new(TrustStore::default()),
            crypto: Arc::new(NodeCrypto::generate()),
            node_id: NODE,
            defense: Arc::new(Defense::new(config.clone(), 0, defense::StormMode::Strict)),
            snapshots: mesh_sync::Cooldown::new(Duration::from_secs(10)),
            sync_throttled: Arc::default(),
            telemetry_tx,
        };
        Node {
            dispatch,
            kernel,
            config,
            audit,
        }
    }

    impl Node {
        fn audit(&self) -> Vec<String> {
            assert!(self.dispatch.db.flush(Duration::from_secs(2)));
            let mut reader =
                common::audit_log::AuditReader::open(std::path::Path::new(&self.audit)).unwrap();
            let mut lines = Vec::new();
            while let Some(record) = reader.next_record().unwrap() {
                lines.push(String::from_utf8(record.payload).unwrap());
            }
            lines
        }
        fn in_kernel(&self, target: &str) -> bool {
            self.kernel
                .0
                .lock()
                .unwrap()
                .contains(&parse_target(target).unwrap())
        }
    }

    fn peer_claim(target: &str) -> Claim {
        let now = now_ms();
        Claim {
            issuer: PEER,
            kind: ClaimKind::Detector,
            target: target.into(),
            issued_ms: now,
            expires_ms: Some(now + 60_000),
            reason: "peer detector".into(),
        }
    }

    #[tokio::test]
    async fn a_peer_claim_is_enforced_audited_and_taken_back_only_by_its_issuer() {
        let mut n = node("claim", None);
        let claim = peer_claim("198.51.100.20");
        let id = claim.id();
        n.dispatch.peer(MeshCommand::Claim { claim }).await;
        assert!(n.in_kernel("198.51.100.20"));
        // Retractions are bound to their issuer: another node naming this claim changes nothing.
        n.dispatch
            .peer(MeshCommand::Retract {
                issuer: 3,
                claims: vec![id.clone()],
            })
            .await;
        assert!(n.in_kernel("198.51.100.20"));
        n.dispatch
            .peer(MeshCommand::Retract {
                issuer: PEER,
                claims: vec![id],
            })
            .await;
        assert!(!n.in_kernel("198.51.100.20"));
        let audit = n.audit();
        assert!(
            audit
                .iter()
                .any(|r| r.starts_with("MESH_BLOCK_V4|IP:198.51.100.20|")),
            "{:?}",
            audit
        );
        assert!(
            audit
                .iter()
                .any(|r| r == "MESH_UNBLOCK|IP:198.51.100.20|Issuer:2"),
            "{:?}",
            audit
        );
    }

    #[tokio::test]
    async fn a_peer_claim_on_a_protected_address_is_refused_and_audited() {
        let mut n = node("protected", Some("198.51.100.21/32"));
        n.dispatch
            .peer(MeshCommand::Claim {
                claim: peer_claim("198.51.100.21"),
            })
            .await;
        assert!(!n.in_kernel("198.51.100.21"));
        let audit = n.audit();
        assert!(
            audit
                .iter()
                .any(|r| r.starts_with("MESH_BLOCK_REFUSED|IP:198.51.100.21|")),
            "{:?}",
            audit
        );
    }

    #[tokio::test]
    async fn a_snapshot_adopts_the_senders_claims() {
        let mut n = node("sync", None);
        n.dispatch
            .peer(MeshCommand::BlockSync {
                issuer: PEER,
                claims: vec![peer_claim("198.51.100.22"), peer_claim("198.51.100.23")],
                retracted: vec![],
            })
            .await;
        assert!(n.in_kernel("198.51.100.22") && n.in_kernel("198.51.100.23"));
    }

    #[tokio::test]
    async fn a_local_detection_becomes_this_nodes_own_claim() {
        let mut n = node("local", None);
        n.dispatch
            .local(LocalCommand::Detection {
                ip: "198.51.100.24".into(),
                reason: "probe".into(),
            })
            .await;
        assert!(n.in_kernel("198.51.100.24"));
        let (claims, _) = n
            .dispatch
            .blocks
            .lock()
            .await
            .snapshot(block_table::local_ms());
        assert!(claims
            .iter()
            .any(|c| c.issuer == NODE && c.target == "198.51.100.24"));
    }

    #[tokio::test]
    async fn the_storm_latch_switches_xdp_flags_only_through_local_commands() {
        let mut n = node("storm", None);
        n.dispatch.local(LocalCommand::EngageDefense).await;
        assert_eq!(
            *n.config.0.lock().unwrap(),
            Some(defense::flags(0, defense::StormMode::Strict, true))
        );
        n.dispatch.local(LocalCommand::DisengageDefense).await;
        assert_eq!(*n.config.0.lock().unwrap(), Some(0));
    }
}
