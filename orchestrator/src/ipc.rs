//! The detector/trap IPC socket: one line in, one acknowledgement out (ACK mode, F09). Moved verbatim out of `main.rs` by the 2026-10-05 review (W3.3); behaviour unchanged.
use super::*;

pub(crate) struct IpcCtx {
    pub(crate) blocks: SharedBlockTable,
    pub(crate) db: Arc<SentinelDb>,
    pub(crate) registry: PeerRegistry,
    pub(crate) node_id: u64,
    pub(crate) crypto: Arc<NodeCrypto>,
    pub(crate) policy: PolicyHandle,
    pub(crate) reports: Arc<std::sync::Mutex<attack_reports::AttackReports>>,
}

/// One IPC command; returns the reply a client in ACK mode gets (F09): `OK applied`,
/// `OK refused <why>` (final, do not retry), `OK pending` (recorded, kernel write retried by the
/// node), `OK recorded`, or `ERR <why>` (malformed, do not retry).
pub(crate) async fn handle_ipc_line(content: &str, c: &IpcCtx) -> String {
    let outcome = |e: Enforcement| match e {
        Enforcement::Enforced => "OK applied".to_string(),
        Enforcement::Refused => "OK refused protected".to_string(),
        Enforcement::Pending => "OK pending".to_string(),
        Enforcement::Duplicate => "OK duplicate".to_string(),
    };
    if content.starts_with('{') {
        if let Err(e) = CanonicalParser::validate_strict_json_object(content) {
            log::error!("[CANONICAL FAULT] Rejected malformed IPC payload: {:?}", e);
            return "ERR malformed JSON".to_string();
        }
    }
    if let Some(raw_ip_str) = content.strip_prefix("DROP_IMMEDIATE:") {
        match parse_target(raw_ip_str.trim()) {
            Some(ip) => {
                log::warn!("[XDP_ACTION] Trap triggered ban for IP: {}", show(&ip));
                outcome(
                    enforce_block_local(
                        ip,
                        "Unix IPC DROP_IMMEDIATE trigger",
                        &c.blocks,
                        &c.db,
                        &c.registry,
                        c.node_id,
                        &c.crypto,
                        &c.policy.current(),
                        Detection {
                            source: crate::detections::TRAP,
                            ..Detection::default()
                        },
                    )
                    .await,
                )
            }
            None => {
                log::error!(
                    "[UNIX IPC FAULT] Failed to parse IP from 'DROP_IMMEDIATE:{}'",
                    raw_ip_str
                );
                "ERR not an IP address or CIDR prefix".to_string()
            }
        }
    } else if let Some(payload) = content.strip_prefix("ATTACK:") {
        match attack_reports::parse(payload) {
            Ok(report) => {
                c.reports
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .apply(&report, std::time::Instant::now());
                let (tag, verb) = if report.active {
                    ("ATTACK_REPORTED", "under attack")
                } else {
                    ("ATTACK_CLEARED", "attack cleared")
                };
                log::warn!(
                    "[Attack] {} reports {} {} ({} pps, {})",
                    report.source,
                    report.victim,
                    verb,
                    report.pps,
                    report.direction
                );
                c.db.append(format!(
                    "{}|Source:{}|Victim:{}|Direction:{}|PPS:{}",
                    tag, report.source, report.victim, report.direction, report.pps
                ));
                "OK recorded".to_string()
            }
            Err(e) => {
                log::error!("[UNIX IPC FAULT] Bad ATTACK line: {}", e);
                format!("ERR {}", e)
            }
        }
    } else if let Some(retract) = signal::parse_retract(content) {
        match retract {
            Ok(r) => retract_detection(&r, c).await,
            Err(e) => format!("ERR {}", e),
        }
    } else if let Some(verb) = signal::split_verb(content) {
        let verb = match verb {
            Ok(v) => v,
            Err(e) => return format!("ERR {}", e),
        };
        let event_id = match verb.id.map(signal::event_id).transpose() {
            Ok(id) => id,
            Err(e) => return format!("ERR {}", e),
        };
        match signal::parse(verb.payload) {
            Ok(sig) => match signal::target(&sig, &c.policy.current()) {
                Ok(ip) => {
                    c.db.append(format!(
                        "SIGNAL|Source:{}|Src:{}|Dst:{}|Target:{}|Reason:{}",
                        sig.source,
                        show(&sig.src),
                        sig.dst.map(|d| show(&d)).unwrap_or_else(|| "-".into()),
                        show(&ip),
                        sig.reason
                    ));
                    let reason = format!("{}: {}", sig.source, sig.reason);
                    let event = event_id.map(|id| (sig.source.as_str(), id));
                    outcome(
                        enforce_block_local(
                            ip,
                            &reason,
                            &c.blocks,
                            &c.db,
                            &c.registry,
                            c.node_id,
                            &c.crypto,
                            &c.policy.current(),
                            Detection {
                                source: &sig.source,
                                event,
                                requested: verb.ttl,
                            },
                        )
                        .await,
                    )
                }
                Err(why) => {
                    log::warn!("[Signal] {} signal not enforced: {}", sig.source, why);
                    c.db.append(format!(
                        "SIGNAL_REFUSED|Source:{}|Src:{}|Why:{}",
                        sig.source,
                        show(&sig.src),
                        why
                    ));
                    format!("OK refused {}", why)
                }
            },
            Err(e) => {
                log::error!("[UNIX IPC FAULT] Bad SIGNAL line: {}", e);
                format!("ERR {}", e)
            }
        }
    } else if let Some(log_content) = content.strip_prefix("DB_LOG:") {
        c.db.append_client_log(log_content);
        let telemetry_msg = format!("DB_LOG:NODE={}|{}\n", c.node_id, log_content.trim());
        push_telemetry(&telemetry_msg).await;
        "OK recorded".to_string()
    } else {
        "ERR unknown command".to_string()
    }
}

pub(crate) fn detector_retraction_reply(out: &block_table::DetectorRetraction) -> String {
    use block_table::DetectorRetraction as R;
    match out {
        R::Refused => "OK refused retraction state capacity",
        R::Duplicate => "OK duplicate",
        R::BeforeSignal => "OK recorded before its signal",
        R::NotHolding => "OK nothing held",
        R::StillHeld => "OK still held by other reasons",
        R::Lifted { reissued: None, .. } => "OK lifted",
        R::Lifted { .. } => "OK shortened",
    }
    .into()
}

/// A detector takes back one of its events (ADR-0019). The block ends, or gets shorter, only as
/// far as no other reason holds it; this node's own claims are retracted mesh-wide.
pub(crate) async fn retract_detection(r: &signal::Retract, c: &IpcCtx) -> String {
    let shown = show(&r.target);
    let now = block_table::local_ms();
    let (out, shares_own) = {
        let mut table = c.blocks.lock().await;
        (
            table.retract_detection(&r.source, &r.id, r.target, now),
            table.shares_own(),
        )
    };
    let label = out.label();
    let reply = detector_retraction_reply(&out);
    let claims = match &out {
        block_table::DetectorRetraction::Lifted { retracted, .. } => retracted.len(),
        _ => 0,
    };
    c.db.append(format!(
        "DETECTOR_RETRACT|IP:{}|Result:{}|Claims:{}|At:{}|Event:{}/{}",
        shown, label, claims, now, r.source, r.id
    ));
    if let block_table::DetectorRetraction::Lifted {
        retracted,
        reissued,
        unblocked,
    } = out
    {
        log::warn!(
            "[Local Security] {} took back event {} for {}: {} own claims retracted{}",
            r.source,
            r.id,
            shown,
            retracted.len(),
            if unblocked.is_empty() {
                ""
            } else {
                ", unblocked"
            }
        );
        if let Some(claim) = reissued.filter(|_| shares_own) {
            let _ = c
                .registry
                .broadcast(&MeshCommand::Claim { claim }, c.node_id, &c.crypto)
                .await;
        }
        let cmd = MeshCommand::Retract {
            issuer: c.node_id,
            claims: retracted,
        };
        let _ = c.registry.broadcast(&cmd, c.node_id, &c.crypto).await;
    }
    reply
}
