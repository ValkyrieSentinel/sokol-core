//! Carries out operator control-socket commands (`control.rs` parses them). Moved verbatim out of `main.rs` by the 2026-10-05 review (W3.3); behaviour unchanged.
use super::*;

pub(crate) struct ControlCtx {
    pub(crate) state: Arc<StateStore>,
    pub(crate) peer_limits: PeerLimits,
    pub(crate) blocks: SharedBlockTable,
    pub(crate) policy: PolicyHandle,
    pub(crate) sntl_db: Arc<SentinelDb>,
    pub(crate) registry: PeerRegistry,
    pub(crate) peers_file: Option<std::path::PathBuf>,
    pub(crate) node_id: u64,
    pub(crate) crypto: Arc<NodeCrypto>,
}

/// Tells the mesh that this node takes back its own claims.
pub(crate) async fn broadcast_retraction(ctx: &ControlCtx, ids: Vec<block_table::ClaimId>) {
    if ids.is_empty() {
        return;
    }
    let cmd = MeshCommand::Retract {
        issuer: ctx.node_id,
        claims: ids,
    };
    let _ = ctx.registry.broadcast(&cmd, ctx.node_id, &ctx.crypto).await;
}

pub(crate) async fn execute_control(cmd: control::ControlCommand, ctx: &ControlCtx) -> String {
    use control::ControlCommand;
    let (blocks, policy, sntl_db) = (&ctx.blocks, &ctx.policy.current(), &ctx.sntl_db);
    match cmd {
        ControlCommand::Ban(ip) => {
            let shown = show(&ip);
            if let Err(why) = policy.check_net(ip) {
                return format!("ERR {} is protected ({})", shown, why);
            }
            let at = block_table::local_ms();
            let added = match blocks
                .lock()
                .await
                .add_local(ip, ClaimKind::Operator, "operator", at)
            {
                Ok(added) => added,
                Err(why) => return format!("ERR {} not banned: {}", shown, why),
            };
            sntl_db.append(format!(
                "OPERATOR_BAN_{}|IP:{}|At:{}",
                ip_tag(ip),
                shown,
                at
            ));
            match added.applied {
                Ok(()) => {
                    log::warn!("[Control] Operator ban for {}", shown);
                    format!("OK banned {}", shown)
                }
                Err(e) => format!(
                    "ERR kernel map update failed: {:?}; the ban is kept and retried every second",
                    e
                ),
            }
        }
        ControlCommand::Unban(ip) => {
            let shown = show(&ip);
            let at = block_table::local_ms();
            let (result, still_blocked) = {
                let mut table = blocks.lock().await;
                let result = table.lift(ip, at);
                (result, table.is_blocked(ip))
            };
            match result {
                Ok(lifted) => {
                    log::warn!("[Control] Operator unban for {}", shown);
                    sntl_db.append(format!(
                        "OPERATOR_UNBAN_{}|IP:{}|Claims:{}|At:{}",
                        ip_tag(ip),
                        shown,
                        lifted.claims,
                        at
                    ));
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
            let at = block_table::local_ms();
            let (released, lifted) = blocks.lock().await.flush_detector(at);
            log::warn!(
                "[Control] Operator flushed {} dynamic blocks",
                released.len()
            );
            sntl_db.append(format!(
                "OPERATOR_FLUSH|Released:{}|At:{}",
                released.len(),
                at
            ));
            broadcast_retraction(ctx, lifted.retracted).await;
            format!("OK released {} dynamic blocks", released.len())
        }
        ControlCommand::FlushAll => {
            let at = block_table::local_ms();
            let (released, lifted) = blocks.lock().await.flush_all(at);
            log::warn!(
                "[Control] Operator flushed {} blocks (operator and dynamic)",
                released.len()
            );
            sntl_db.append(format!(
                "OPERATOR_FLUSH_ALL|Released:{}|At:{}",
                released.len(),
                at
            ));
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
                        table.configure_peers(
                            ctx.peer_limits.default,
                            per_peer,
                            ctx.peer_limits.quorum,
                            block_table::local_ms(),
                        );
                        // A revoked node's claims stop counting here at once.
                        table.set_pinned(trust.node_ids(), block_table::local_ms());
                    }
                    let pinned = ctx.registry.reload(trust);
                    log_inbound_budget(pinned);
                    log::warn!(
                        "[Control] Reloaded {}: {} pinned peers",
                        path.display(),
                        pinned
                    );
                    sntl_db.append(format!(
                        "PEERS_RELOADED|Pinned:{}|Legacy:{:?}",
                        pinned, legacy
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
