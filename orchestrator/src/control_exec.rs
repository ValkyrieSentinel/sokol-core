//! Carries out operator control-socket commands (`control.rs` parses them). Moved verbatim out of `main.rs` by the 2026-10-05 review (W3.3); behaviour unchanged.
use super::*;

pub(crate) struct ControlCtx<B = block_table::KernelBlocklist> {
    pub(crate) state: Arc<StateStore>,
    pub(crate) peer_limits: PeerLimits,
    pub(crate) blocks: SharedBlockTable<B>,
    pub(crate) policy: PolicyHandle,
    pub(crate) sntl_db: Arc<SentinelDb>,
    pub(crate) registry: PeerRegistry,
    pub(crate) peers_file: Option<std::path::PathBuf>,
    pub(crate) node_id: u64,
    pub(crate) crypto: Arc<NodeCrypto>,
}

/// Tells the mesh that this node takes back its own claims.
pub(crate) async fn broadcast_retraction<B: block_table::Blocklist>(
    ctx: &ControlCtx<B>,
    ids: Vec<block_table::ClaimId>,
) {
    if ids.is_empty() {
        return;
    }
    let cmd = MeshCommand::Retract {
        issuer: ctx.node_id,
        claims: ids,
    };
    let _ = ctx.registry.broadcast(&cmd, ctx.node_id, &ctx.crypto).await;
}

pub(crate) async fn execute_control<B: block_table::Blocklist>(
    cmd: control::ControlCommand,
    ctx: &ControlCtx<B>,
) -> String {
    use control::ControlCommand;
    let (blocks, policy, sntl_db) = (&ctx.blocks, &ctx.policy.current(), &ctx.sntl_db);
    match cmd {
        ControlCommand::Ban(ip) => {
            let shown = show(&ip);
            if let Err(why) = policy.check_net(ip) {
                return format!("ERR {} is protected ({})", shown, why);
            }
            // Time and record under the table lock (audit order = lock order).
            let mut table = blocks.lock().await;
            let at = block_table::local_ms();
            let added = match table.add_local(ip, ClaimKind::Operator, "operator", at) {
                Ok(added) => added,
                Err(why) => return format!("ERR {} not banned: {}", shown, why),
            };
            sntl_db.append(format!(
                "OPERATOR_BAN_{}|IP:{}|At:{}",
                ip_tag(ip),
                shown,
                at
            ));
            drop(table);
            match added.applied {
                Ok(()) => {
                    log::warn!("[Control] Operator ban for {}", shown);
                    format!("OK banned {}", shown)
                }
                // The ban is in force in the table and retried into the kernel, as UNBAN's
                // "kernel removal pending": an operator decision, answered OK so it waits for
                // disk like every other (R26-04) and is not shown as a refusal.
                Err(e) => format!(
                    "OK banned {} (kernel update pending, retried every second: {:?})",
                    shown, e
                ),
            }
        }
        ControlCommand::Unban(ip) => {
            let shown = show(&ip);
            let (result, still_blocked) = {
                let mut table = blocks.lock().await;
                let at = block_table::local_ms();
                let result = table.lift(ip, at);
                // Submitted before the lock is released (audit order = lock order).
                if let Ok(lifted) = &result {
                    sntl_db.append(format!(
                        "OPERATOR_UNBAN_{}|IP:{}|Claims:{}|At:{}",
                        ip_tag(ip),
                        shown,
                        lifted.claims,
                        at
                    ));
                }
                (result, table.is_blocked(ip))
            };
            match result {
                Ok(lifted) => {
                    log::warn!("[Control] Operator unban for {}", shown);
                    broadcast_retraction(ctx, lifted.retracted).await;
                    if still_blocked {
                        format!(
                            "OK unbanned {} (kernel removal pending, retried every second)",
                            shown
                        )
                    } else {
                        format!("OK unbanned {}", shown)
                    }
                }
                Err(LiftError::Static) => format!(
                    "ERR {} is blocked by --block; change the configuration to lift it",
                    shown
                ),
                Err(LiftError::NotBlocked) => format!("ERR {} was not blocked", shown),
            }
        }
        ControlCommand::FlushDynamic => {
            let (released, lifted) = {
                let mut table = blocks.lock().await;
                let at = block_table::local_ms();
                let (released, lifted) = table.flush_detector(at);
                sntl_db.append(format!(
                    "OPERATOR_FLUSH|Released:{}|At:{}",
                    released.len(),
                    at
                ));
                (released, lifted)
            };
            log::warn!(
                "[Control] Operator flushed {} dynamic blocks",
                released.len()
            );
            broadcast_retraction(ctx, lifted.retracted).await;
            format!("OK released {} dynamic blocks", released.len())
        }
        ControlCommand::FlushAll => {
            let (released, lifted) = {
                let mut table = blocks.lock().await;
                let at = block_table::local_ms();
                let (released, lifted) = table.flush_all(at);
                sntl_db.append(format!(
                    "OPERATOR_FLUSH_ALL|Released:{}|At:{}",
                    released.len(),
                    at
                ));
                (released, lifted)
            };
            log::warn!(
                "[Control] Operator flushed {} blocks (operator and dynamic)",
                released.len()
            );
            broadcast_retraction(ctx, lifted.retracted).await;
            format!("OK released {} blocks", released.len())
        }
        ControlCommand::AcceptStateLoss => {
            if ctx.state.accept_loss() {
                log::warn!("[Control] Operator accepted running without the unrestored state");
                sntl_db.append("STATE_LOSS_ACCEPTED".to_string());
                "OK state loss accepted".to_string()
            } else {
                "ERR no failed state restore to accept".to_string()
            }
        }
        ControlCommand::ListBans => {
            let bans = blocks
                .lock()
                .await
                .operator_targets(block_table::local_ms());
            let shown: Vec<String> = bans.iter().take(LIST_BANS_MAX).map(show).collect();
            // "OK <total> <target>..."; at most LIST_BANS_MAX targets on the line.
            format!("OK {} {}", bans.len(), shown.join(" "))
                .trim_end()
                .to_string()
        }
        ControlCommand::ReloadPeers => match &ctx.peers_file {
            None => "ERR no --peers-file configured".to_string(),
            Some(path) => match TrustStore::load(path).and_then(|trust| {
                ctx.registry.check_candidate(&trust)?;
                Ok(trust)
            }) {
                Ok(trust) => {
                    let per_peer = ctx.peer_limits.per_peer(&trust);
                    let legacy = trust.legacy_peers().to_vec();
                    {
                        let mut table = ctx.blocks.lock().await;
                        if !table.configure_trusted_peers(
                            ctx.peer_limits.default,
                            per_peer,
                            ctx.peer_limits.quorum,
                            trust.node_ids(),
                            block_table::local_ms(),
                        ) {
                            return "ERR known-claims share below currently held claims; previous trust store kept"
                                .to_string();
                        }
                    }
                    let pinned = ctx.registry.reload(trust);
                    // Nodes no longer pinned, or bound elsewhere, get no broadcast from now on.
                    let dropped = ctx.registry.drop_untrusted().await;
                    log_inbound_budget(pinned);
                    log::warn!(
                        "[Control] Reloaded {}: {} pinned peers; connections of nodes {:?} unregistered",
                        path.display(),
                        pinned,
                        dropped
                    );
                    sntl_db.append(format!(
                        "PEERS_RELOADED|Pinned:{}|Legacy:{:?}|Unregistered:{:?}",
                        pinned, legacy, dropped
                    ));
                    if legacy.is_empty() {
                        format!("OK {} pinned peers", pinned)
                    } else {
                        format!(
                            "OK {} pinned peers; not trusted until their ML-DSA key is listed \
                             (legacy key only): {:?}",
                            pinned, legacy
                        )
                    }
                }
                // A broken file must not wipe the current trust: keep it and report.
                Err(e) => format!("ERR {:#}; previous trust store kept", e),
            },
        },
        ControlCommand::Unsupported(why) => format!("ERR {}", why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct AcceptLists;
    impl block_table::Blocklist for AcceptLists {
        fn add(&mut self, _: IpNet) -> Result<(), aya::maps::MapError> {
            Ok(())
        }
        fn delete(&mut self, _: IpNet) -> Result<(), aya::maps::MapError> {
            Ok(())
        }
        fn hits(&self, _: IpNet) -> Option<u64> {
            Some(0)
        }
    }

    #[tokio::test]
    async fn a_refused_share_reload_answers_error_and_keeps_trust_then_can_be_retried() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-reload-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("peers.json");
        let crypto = Arc::new(NodeCrypto::generate());
        let key = crypto.public_key_hex();
        let peer = |id, max_known| serde_json::json!({"node_id": id, "public_key": key, "envelope": {"max_known": max_known}});
        std::fs::write(
            &file,
            serde_json::to_vec(&vec![peer(2, 3), peer(3, 3)]).unwrap(),
        )
        .unwrap();
        let registry = PeerRegistry::new(TrustStore::load(&file).unwrap());
        let ttl = TtlPolicy {
            base: Duration::from_secs(60),
            max: Duration::from_secs(600),
        };
        let blocks = Arc::new(tokio::sync::Mutex::new(BlockTable::with_lists(
            AcceptLists,
            ttl,
            1,
        )));
        let now = block_table::local_ms();
        for i in 0..3 {
            let claim = block_table::Claim {
                issuer: 2,
                kind: ClaimKind::Detector,
                target: format!("203.0.113.{}", 10 + i),
                issued_ms: p2p::now_ms(),
                expires_ms: None,
                reason: "test".into(),
            };
            assert!(!matches!(
                blocks.lock().await.adopt(claim, true, now),
                block_table::Adoption::Refused(_)
            ));
        }
        let ctx = ControlCtx {
            state: Arc::new(StateStore::new(dir.join("state.json"))),
            peer_limits: PeerLimits {
                default: Envelope {
                    max_known: 1,
                    ..Envelope::unlimited(ttl.max)
                },
                quorum: Quorum::OFF,
            },
            blocks,
            policy: PolicyHandle::new(BlockPolicy::builtin()),
            sntl_db: Arc::new(
                SentinelDb::init(dir.join("events.sntl").to_str().unwrap(), None).unwrap(),
            ),
            registry,
            peers_file: Some(file.clone()),
            node_id: 1,
            crypto,
        };
        // A candidate both lowers the share below its held count and removes another peer.
        std::fs::write(&file, serde_json::to_vec(&vec![peer(2, 1)]).unwrap()).unwrap();
        assert_eq!(
            execute_control(control::ControlCommand::ReloadPeers, &ctx).await,
            "ERR known-claims share below currently held claims; previous trust store kept"
        );
        assert!(
            ctx.registry.trusts(3),
            "failed reload removed existing trust"
        );
        // Equality fits. The same command can subsequently install a valid candidate.
        std::fs::write(&file, serde_json::to_vec(&vec![peer(2, 3)]).unwrap()).unwrap();
        assert_eq!(
            execute_control(control::ControlCommand::ReloadPeers, &ctx).await,
            "OK 1 pinned peers"
        );
        assert!(
            !ctx.registry.trusts(3),
            "valid reload did not apply new trust"
        );
        // Revoking an over-default peer must not be refused as an implicit quota reduction.
        std::fs::write(&file, serde_json::to_vec(&vec![peer(3, 1)]).unwrap()).unwrap();
        assert_eq!(
            execute_control(control::ControlCommand::ReloadPeers, &ctx).await,
            "OK 1 pinned peers",
            "known claims must not prevent revocation"
        );
        assert!(!ctx.registry.trusts(2));
        assert!(
            !ctx.blocks
                .lock()
                .await
                .is_blocked("203.0.113.10/32".parse().unwrap()),
            "revoked peer still enforces its held claim"
        );
        drop(ctx);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A reload that revokes a connected node, or binds it to another address, stops this
    /// node's broadcasts to it at once (ROADMAP item 10). Before, its link stayed registered and
    /// got every broadcast until its own next envelope failed to authenticate (up to ~10 s).
    #[tokio::test]
    async fn a_reload_stops_broadcasts_to_a_revoked_or_moved_node_at_once() {
        let dir = std::env::temp_dir().join(format!(
            "sokol-reload-revoke-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("peers.json");
        let crypto = Arc::new(NodeCrypto::generate());
        let key = crypto.public_key_hex();
        let peer = |id: u64| serde_json::json!({"node_id": id, "public_key": key});
        let at = |id: u64, address: &str| serde_json::json!({"node_id": id, "public_key": key, "address": address});
        std::fs::write(
            &file,
            serde_json::to_vec(&vec![peer(2), peer(3), peer(4)]).unwrap(),
        )
        .unwrap();
        let registry = PeerRegistry::new(TrustStore::load(&file).unwrap());
        let mut queues = Vec::new();
        for id in [2u64, 3, 4] {
            let (urgent, urgent_rx) = tokio::sync::mpsc::channel(4);
            let (bulk, bulk_rx) = tokio::sync::mpsc::channel(4);
            let link = p2p::PeerLink {
                urgent,
                bulk,
                features: Arc::from(Vec::new()),
            };
            let addr = format!("127.0.0.{}:7946", id).parse().unwrap();
            registry.add_peer(addr, link, id, id).await;
            queues.push((id, urgent_rx, bulk_rx));
        }
        let ttl = TtlPolicy {
            base: Duration::from_secs(60),
            max: Duration::from_secs(600),
        };
        let ctx = ControlCtx {
            state: Arc::new(StateStore::new(dir.join("state.json"))),
            peer_limits: PeerLimits {
                default: Envelope::unlimited(ttl.max),
                quorum: Quorum::OFF,
            },
            blocks: Arc::new(tokio::sync::Mutex::new(BlockTable::with_lists(
                AcceptLists,
                ttl,
                1,
            ))),
            policy: PolicyHandle::new(BlockPolicy::builtin()),
            sntl_db: Arc::new(
                SentinelDb::init(dir.join("events.sntl").to_str().unwrap(), None).unwrap(),
            ),
            registry,
            peers_file: Some(file.clone()),
            node_id: 1,
            crypto: crypto.clone(),
        };
        // Node 2 revoked, node 3 bound to an address it is not connected from, node 4 kept.
        std::fs::write(
            &file,
            serde_json::to_vec(&vec![at(3, "192.0.2.3"), peer(4)]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            execute_control(control::ControlCommand::ReloadPeers, &ctx).await,
            "OK 2 pinned peers"
        );
        let alert = MeshCommand::Alert {
            level: crate::mesh_sync::AlertLevel::Info,
            message: "after the reload".into(),
        };
        ctx.registry.broadcast(&alert, 1, &crypto).await.unwrap();
        let mut reached = Vec::new();
        for (id, urgent_rx, bulk_rx) in queues.iter_mut() {
            if urgent_rx.try_recv().is_ok() || bulk_rx.try_recv().is_ok() {
                reached.push(*id);
            }
        }
        assert_eq!(
            reached,
            vec![4],
            "only the node the reloaded peers file still trusts at its address gets broadcasts"
        );
        assert!(ctx.sntl_db.flush(Duration::from_secs(2)));
        let mut reader = common::audit_log::AuditReader::open(&dir.join("events.sntl")).unwrap();
        let mut records = Vec::new();
        while let Some(record) = reader.next_record().unwrap() {
            records.push(String::from_utf8(record.payload).unwrap());
        }
        assert!(
            records
                .iter()
                .any(|r| r == "PEERS_RELOADED|Pinned:2|Legacy:[]|Unregistered:[2, 3]"),
            "{:?}",
            records
        );
        drop(ctx);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An operator ban the node keeps (the kernel write failed and is retried, like UNBAN's
    /// "kernel removal pending") is an operator decision in force: ARCHITECTURE (R26-04) says
    /// BAN waits for its generation on disk before the answer, and the serving loop does that
    /// only for an `OK` answer. An `ERR` answer also reads as REJECTED ("Node refused the
    /// command") in the operator while LIST_BANS shows the ban.
    #[tokio::test]
    async fn a_kept_operator_ban_is_not_answered_as_a_refusal() {
        // Nested: a test-only item at module level would join the closures of the pinned
        // witnesses here that name block_table.
        struct FullKernel;
        impl block_table::Blocklist for FullKernel {
            fn add(&mut self, _: IpNet) -> Result<(), aya::maps::MapError> {
                Err(aya::maps::MapError::OutOfBounds {
                    index: 0,
                    max_entries: 0,
                })
            }
            fn delete(&mut self, _: IpNet) -> Result<(), aya::maps::MapError> {
                Ok(())
            }
            fn hits(&self, _: IpNet) -> Option<u64> {
                None
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "sokol-ban-kept-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ttl = TtlPolicy {
            base: Duration::from_secs(60),
            max: Duration::from_secs(600),
        };
        let ctx = ControlCtx {
            state: Arc::new(StateStore::new(dir.join("state.json"))),
            peer_limits: PeerLimits {
                default: Envelope::unlimited(ttl.max),
                quorum: Quorum::OFF,
            },
            blocks: Arc::new(tokio::sync::Mutex::new(BlockTable::with_lists(
                FullKernel, ttl, 1,
            ))),
            policy: PolicyHandle::new(BlockPolicy::builtin()),
            sntl_db: Arc::new(
                SentinelDb::init(dir.join("events.sntl").to_str().unwrap(), None).unwrap(),
            ),
            registry: PeerRegistry::new(TrustStore::default()),
            peers_file: None,
            node_id: 1,
            crypto: Arc::new(NodeCrypto::generate()),
        };
        let target = block_table::parse_target("203.0.113.44").unwrap();
        let reply = execute_control(control::ControlCommand::Ban(target), &ctx).await;
        let kept = ctx
            .blocks
            .lock()
            .await
            .operator_targets(block_table::local_ms())
            .contains(&target);
        assert!(kept, "precondition: the node keeps the ban ({reply})");
        assert!(
            reply.starts_with("OK"),
            "a ban the node keeps and enforces later was answered as a refusal: {reply}"
        );
        drop(ctx);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
