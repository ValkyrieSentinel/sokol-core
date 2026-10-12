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
    // One policy snapshot per line: the decision and its answer read the same never-block set,
    // so a refusal the policy does not explain is the table's, not a policy change in between.
    let policy = c.policy.current();
    let outcome = |e: Enforcement, target: IpNet| {
        let protected = policy.check_net(block_table::canonical(target)).is_err();
        enforcement_reply(e, protected)
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
                        &policy,
                        Detection {
                            source: crate::detections::TRAP,
                            ..Detection::default()
                        },
                    )
                    .await,
                    ip,
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
            Ok(sig) => match signal::target(&sig, &policy) {
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
                            &policy,
                            Detection {
                                source: &sig.source,
                                event,
                                requested: verb.ttl,
                            },
                        )
                        .await,
                        ip,
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

/// The answer to a block request. `protected`: the never-block policy refuses the target (the
/// same snapshot `enforce_block_local` checked). A refusal it does not explain comes from the
/// block table, whose only refusal (`Detected::Refused`) is the MAX_KNOWN_CLAIMS cap: reporting
/// that as "protected" would tell the adapter the target is safe when the node is full.
/// Both forms are `OK refused <why>`, which the outbox takes as a final refusal.
pub(crate) fn enforcement_reply(e: Enforcement, protected: bool) -> String {
    match e {
        Enforcement::Enforced => "OK applied".to_string(),
        Enforcement::Refused if protected => "OK refused protected".to_string(),
        Enforcement::Refused => format!("OK refused {}", block_table::TOO_MANY_CLAIMS),
        Enforcement::Pending => "OK pending".to_string(),
        Enforcement::Duplicate => "OK duplicate".to_string(),
    }
}

/// The answer to a detector retraction. `still_blocked`: the target is still blocked on this
/// node after it ([`block_table::BlockTable::still_blocks`]). `OK lifted` promises that nothing
/// else holds the block (docs/INTEGRATIONS.md); when an operator ban, a peer's claim or `--block`
/// still does, the detector's claims went, but the answer is that other reasons hold it.
pub(crate) fn retraction_reply(
    out: &block_table::DetectorRetraction,
    still_blocked: bool,
) -> String {
    match out {
        block_table::DetectorRetraction::Lifted { reissued: None, .. } if still_blocked => {
            "OK still held by other reasons".to_string()
        }
        _ => detector_retraction_reply(out),
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

/// The audit record of a detector retraction, with how many of this node's claims it retracted.
fn retraction_record(
    shown: &str,
    out: &block_table::DetectorRetraction,
    now: u64,
    r: &signal::Retract,
) -> String {
    let claims = match out {
        block_table::DetectorRetraction::Lifted { retracted, .. } => retracted.len(),
        _ => 0,
    };
    format!(
        "DETECTOR_RETRACT|IP:{}|Result:{}|Claims:{}|At:{}|Event:{}/{}",
        shown,
        out.label(),
        claims,
        now,
        r.source,
        r.id
    )
}

/// A detector takes back one of its events (ADR-0019). The block ends, or gets shorter, only as
/// far as no other reason holds it; this node's own claims are retracted mesh-wide.
pub(crate) async fn retract_detection(r: &signal::Retract, c: &IpcCtx) -> String {
    let shown = show(&r.target);
    // Time read and record submitted under the table lock.
    let (out, shares_own, still_blocked) = {
        let mut table = c.blocks.lock().await;
        let now = block_table::local_ms();
        let out = table.retract_detection(&r.source, &r.id, r.target, now);
        c.db.append(retraction_record(&shown, &out, now, r));
        (out, table.shares_own(), table.still_blocks(r.target, now))
    };
    let reply = retraction_reply(&out, still_blocked);
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

#[cfg(test)]
mod tests {
    use super::*;
    use block_table::{BlockTable, Claim, ClaimKind, TtlPolicy};

    const T0: u64 = 1_000_000_000;
    const S: u64 = 1000;

    /// No kernel: every write succeeds, so "blocked" is the table's own answer.
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

    fn table() -> BlockTable<AcceptLists> {
        BlockTable::with_lists(
            AcceptLists,
            TtlPolicy {
                base: Duration::from_secs(60),
                max: Duration::from_secs(600),
            },
            1,
        )
    }

    /// Something besides the detector that blocks the target.
    type Hold = fn(&mut BlockTable<AcceptLists>);

    /// `SIGNAL#17` then `RETRACT#17` on 203.0.113.9: the table step and the reply the node sends.
    fn signal_then_retract(t: &mut BlockTable<AcceptLists>) -> String {
        let net = parse_target("203.0.113.9").unwrap();
        assert!(matches!(
            t.detect(net, "crowdsec: x", T0 + S, Some(("crowdsec", "17")), None),
            block_table::Detected::Added(_)
        ));
        let out = t.retract_detection("crowdsec", "17", net, T0 + 2 * S);
        retraction_reply(&out, t.still_blocks(net, T0 + 2 * S))
    }

    #[test]
    fn a_retraction_record_counts_the_claims_it_retracted() {
        let mut t = table();
        let net = parse_target("203.0.113.9").unwrap();
        t.detect(net, "crowdsec: x", T0 + S, Some(("crowdsec", "17")), None);
        let out = t.retract_detection("crowdsec", "17", net, T0 + 2 * S);
        let r = signal::Retract {
            id: "17".into(),
            source: "crowdsec".into(),
            target: net,
        };
        assert_eq!(
            retraction_record("203.0.113.9", &out, T0 + 2 * S, &r),
            format!(
                "DETECTOR_RETRACT|IP:203.0.113.9|Result:lifted|Claims:1|At:{}|Event:crowdsec/17",
                T0 + 2 * S
            )
        );
    }

    #[test]
    fn a_retraction_answers_lifted_only_when_nothing_else_blocks_the_target() {
        let net = parse_target("203.0.113.9").unwrap();
        assert_eq!(signal_then_retract(&mut table()), "OK lifted");
        let others: [(&str, Hold); 3] = [
            ("an operator ban", |t| {
                t.add_local(
                    parse_target("203.0.113.9").unwrap(),
                    ClaimKind::Operator,
                    "ban",
                    T0,
                )
                .unwrap();
            }),
            ("a static block", |t| {
                t.add_local(
                    parse_target("203.0.113.9").unwrap(),
                    ClaimKind::Static,
                    "--block",
                    T0,
                )
                .unwrap();
            }),
            ("a peer's claim", |t| {
                let claim = Claim {
                    issuer: 2,
                    kind: ClaimKind::Detector,
                    target: "203.0.113.9".to_string(),
                    issued_ms: block_table::local_ms(),
                    expires_ms: None,
                    reason: "peer".to_string(),
                };
                assert_eq!(
                    t.adopt(claim, true, T0),
                    block_table::Adoption::Enforced,
                    "the peer's claim blocks on its own"
                );
            }),
        ];
        for (other, hold) in others {
            let mut t = table();
            hold(&mut t);
            let reply = signal_then_retract(&mut t);
            assert!(t.is_blocked(net), "{} still blocks", other);
            assert_ne!(reply, "OK lifted", "with {}", other);
            assert_eq!(reply, "OK still held by other reasons", "with {}", other);
        }
    }

    #[test]
    fn a_capacity_refusal_is_not_reported_as_a_protected_target() {
        assert_eq!(
            enforcement_reply(Enforcement::Refused, true),
            "OK refused protected"
        );
        let full = enforcement_reply(Enforcement::Refused, false);
        assert_ne!(full, "OK refused protected");
        assert_eq!(full, "OK refused too many known claims");
        assert_eq!(
            full,
            format!("OK refused {}", block_table::TOO_MANY_CLAIMS),
            "names the table's own refusal"
        );
    }
}
