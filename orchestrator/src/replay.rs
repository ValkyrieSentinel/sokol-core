//! Offline replay of this node's detector decisions from its audit log (ADR-0016).
//!
//! The replay runs the node's own `BlockTable` code, not a copy of its rules, over the inputs
//! the log records, and compares each recorded decision with the one the code makes again.
//! A decision is only claimed to be reproduced when its whole context is in the log:
//! - the run's start record (`NODE_START`: build, node id, TTL policy, digest);
//! - a fresh start (a state file restored at start holds decisions the log does not);
//! - the exact decision time and event id, written into the decision record itself.
//!
//! Anything else is reported as insufficient evidence, with the reason, never as a match.

use crate::block_table::{parse_target, BlockTable, Blocklist, ClaimKind, TtlPolicy};
use aya::maps::MapError;
use common::audit_log::{rotated_segments, verify_chain, AuditReader};
use ipnet::IpNet;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::time::Duration;

/// The context a run's decisions depend on, written once at start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartContext {
    pub build: String,
    pub node: u64,
    pub ttl_base_secs: u64,
    pub ttl_max_secs: u64,
}

impl StartContext {
    fn canonical(&self) -> String {
        format!(
            "Build:{}|Node:{}|TtlBase:{}|TtlMax:{}",
            self.build, self.node, self.ttl_base_secs, self.ttl_max_secs
        )
    }

    fn digest(&self) -> String {
        let hash = blake3::hash(self.canonical().as_bytes());
        hash.to_hex()
            .as_str()
            .get(..16)
            .unwrap_or_default()
            .to_string()
    }

    /// The audit record that opens a run.
    pub fn record(&self) -> String {
        format!("NODE_START|{}|Digest:{}", self.canonical(), self.digest())
    }

    fn parse(fields: &Fields) -> Result<Self, String> {
        let num = |k: &str| -> Result<u64, String> {
            fields
                .get(k)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| format!("start record without a valid {}", k))
        };
        let ctx = StartContext {
            build: fields
                .get("Build")
                .ok_or("start record without Build")?
                .to_string(),
            node: num("Node")?,
            ttl_base_secs: num("TtlBase")?,
            ttl_max_secs: num("TtlMax")?,
        };
        if fields.get("Digest") != Some(&ctx.digest().as_str()) {
            return Err("start record does not match its digest".into());
        }
        Ok(ctx)
    }

    fn policy(&self) -> TtlPolicy {
        TtlPolicy {
            base: Duration::from_secs(self.ttl_base_secs),
            max: Duration::from_secs(self.ttl_max_secs),
        }
    }
}

/// The kernel map, in memory: same capacity, no packets.
struct MemoryLists {
    nets: HashSet<IpNet>,
}

impl Blocklist for MemoryLists {
    fn add(&mut self, net: IpNet) -> Result<(), MapError> {
        let same_family = self
            .nets
            .iter()
            .filter(|n| n.addr().is_ipv4() == net.addr().is_ipv4())
            .count();
        if !self.nets.contains(&net) && same_family >= common::BLOCKLIST_CAPACITY as usize {
            return Err(MapError::KeyNotFound);
        }
        self.nets.insert(net);
        Ok(())
    }
    fn delete(&mut self, net: IpNet) -> Result<(), MapError> {
        self.nets.remove(&net);
        Ok(())
    }
    fn hits(&self, _net: IpNet) -> Option<u64> {
        None
    }
}

type Fields<'a> = BTreeMap<&'a str, &'a str>;

/// The node's protected-refusal marker precedes its free-text reason.
fn is_protected_refusal(tag: &str, payload: &str) -> bool {
    tag == "BLOCK_REFUSED"
        && payload
            .split('|')
            .nth(2)
            .is_some_and(|field| field.starts_with("Protected:"))
}

/// Parse the current node writers' layout, keeping the entire free-text Reason opaque.
/// Leading fields precede Reason; detector context is appended after it. Source/event ids
/// cannot contain '|', so the LAST matching context boundary belongs to the node, not Reason.
fn split(payload: &str) -> (&str, Fields<'_>) {
    let (head, text) = payload
        .split_once("|Reason:")
        .map_or((payload, None), |(head, text)| (head, Some(text)));
    let mut parts = head.split('|');
    let tag = parts.next().unwrap_or_default();
    let boundary = match tag {
        t if t.starts_with("DYNAMIC_BLOCK_") => Some("|Enforced|Claim:"),
        "BLOCK_PENDING" => Some("|Claim:"),
        "BLOCK_REFUSED" if !is_protected_refusal(tag, head) => Some("|At:"),
        _ => None,
    };
    let (reason, context) = match text {
        Some(text) => {
            let (reason, context) = boundary
                .and_then(|marker| text.rsplit_once(marker))
                .map_or((text, ""), |(reason, _)| {
                    (reason, text.get(reason.len() + 1..).unwrap_or_default())
                });
            (Some(reason), context)
        }
        None => (None, ""),
    };
    let mut fields: Fields<'_> = parts
        .chain(context.split('|'))
        .filter_map(|p| p.split_once(':'))
        .collect();
    if let Some(reason) = reason {
        fields.insert("Reason", reason);
    }
    (tag, fields)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub reproduced: u64,
    /// (record seq, what was recorded, what the replay decided)
    pub mismatched: Vec<(u64, String, String)>,
    /// reason -> decisions not replayed for it
    pub insufficient: BTreeMap<String, u64>,
    /// Refusals by the host's protected set, which the log does not record: not replayed.
    pub policy_refusals: u64,
}

impl Report {
    fn insufficient(&mut self, why: &str) {
        *self.insufficient.entry(why.to_string()).or_default() += 1;
    }
}

enum Run {
    /// No usable context: every decision is insufficient for this reason.
    Blind(String),
    Live(Box<BlockTable<MemoryLists>>),
}

fn ttl_label(ttl: Option<Duration>) -> String {
    match ttl {
        Some(d) => format!("{}s", d.as_secs()),
        None => "permanent".to_string(),
    }
}

fn is_decision(tag: &str) -> bool {
    tag.starts_with("DYNAMIC_BLOCK_")
        || tag == "BLOCK_PENDING"
        || tag == "BLOCK_REFUSED"
        || tag == "SIGNAL_DUPLICATE"
        || tag == "DETECTOR_RETRACT"
}

/// Replays records (seq, payload) in order. `this_build` is the replaying binary's build: a
/// run made by another build is not replayed, its code may decide differently.
pub fn replay_records<'a>(
    records: impl IntoIterator<Item = (u64, &'a str)>,
    this_build: &str,
) -> Report {
    let mut report = Report::default();
    let mut run = Run::Blind("no start record: the log begins inside a run".into());
    for (seq, payload) in records {
        let (tag, f) = split(payload);
        if tag == "NODE_START" {
            run = match StartContext::parse(&f) {
                Err(why) => Run::Blind(why),
                Ok(ctx) if ctx.build != this_build || ctx.build == "unknown" => {
                    Run::Blind(format!(
                        "run made by build {}, this is build {}",
                        ctx.build, this_build
                    ))
                }
                Ok(ctx) => Run::Live(Box::new(BlockTable::with_lists(
                    MemoryLists {
                        nets: HashSet::new(),
                    },
                    ctx.policy(),
                    ctx.node,
                ))),
            };
            continue;
        }
        // The protected set is not a replay input, regardless of run context.
        if is_protected_refusal(tag, payload) {
            report.policy_refusals += 1;
            continue;
        }
        let table = match &mut run {
            Run::Live(table) => table,
            Run::Blind(why) => {
                if is_decision(tag) {
                    let why = why.clone();
                    report.insufficient(&why);
                }
                continue;
            }
        };
        let net = f.get("IP").and_then(|v| parse_target(v));
        match tag {
            "STATE_RESTORED" => {
                run = Run::Blind(
                    "the run restored earlier decisions from a state file the log does not hold"
                        .into(),
                );
            }
            t if t.starts_with("STATIC_BLOCK_") => {
                if let Some(net) = net {
                    let _ = table.add_local(net, ClaimKind::Static, "--block", 0);
                }
            }
            t if t.starts_with("OPERATOR_BAN_") => {
                if let (Some(net), Some(at)) = (net, at(&f)) {
                    let _ = table.add_local(net, ClaimKind::Operator, "operator", at);
                }
            }
            t if t.starts_with("OPERATOR_UNBAN_") => {
                if let (Some(net), Some(at)) = (net, at(&f)) {
                    let _ = table.lift(net, at);
                }
            }
            "OPERATOR_FLUSH" => {
                if let Some(at) = at(&f) {
                    let _ = table.flush_detector(at);
                }
            }
            "OPERATOR_FLUSH_ALL" => {
                if let Some(at) = at(&f) {
                    let _ = table.flush_all(at);
                }
            }
            "DETECTOR_RETRACT" => {
                let event = f.get("Event").and_then(|e| e.split_once('/'));
                let (Some(net), Some(at), Some((source, id))) = (net, at(&f), event) else {
                    report.insufficient("retraction record without its context");
                    continue;
                };
                table.tick(at);
                let recorded = f.get("Result").copied().unwrap_or_default().to_string();
                let replayed = table
                    .retract_detection(source, id, net, at)
                    .label()
                    .to_string();
                // DetectorRetraction::Refused currently means capacity admission only.
                if recorded == "refused" && replayed != "refused" {
                    // Mesh claims/retraction owners are not logged as replay inputs.
                    // Do not certify the recorded refusal, or continue on the state
                    // produced by our speculative lift/shortening. Only a fresh start
                    // can establish a new replay context.
                    let why = "unverified retraction capacity refusal: recorded resource state cannot be established";
                    report.insufficient(why);
                    run = Run::Blind(why.into());
                } else if recorded == replayed {
                    report.reproduced += 1;
                } else {
                    report.mismatched.push((seq, recorded, replayed));
                }
            }
            t if is_decision(t) => {
                let (Some(net), Some(at)) = (net, at(&f)) else {
                    report.insufficient("decision record without its time (older format)");
                    continue;
                };
                let recorded = recorded_outcome(tag, &f);
                let reason = f.get("Reason").copied().unwrap_or_default();
                let requested = f
                    .get("Ttl")
                    .and_then(|t| t.parse().ok())
                    .map(Duration::from_secs);
                let replayed = decide(table, net, reason, f.get("Event").copied(), requested, at);
                if recorded == replayed {
                    report.reproduced += 1;
                } else {
                    report.mismatched.push((seq, recorded, replayed));
                }
            }
            _ => {}
        }
    }
    report
}

fn at(f: &Fields) -> Option<u64> {
    f.get("At")?.parse().ok()
}

/// A decision as a comparable string: what the node recorded.
fn recorded_outcome(tag: &str, f: &Fields) -> String {
    match tag {
        "SIGNAL_DUPLICATE" => "duplicate".into(),
        "BLOCK_REFUSED" => format!("refused {}", f.get("Why").copied().unwrap_or_default()),
        _ => format!(
            "{} {}",
            f.get("TTL").copied().unwrap_or_default(),
            f.get("Claim").copied().unwrap_or_default()
        ),
    }
}

/// The same steps `enforce_block_local` takes under the table lock, at the recorded time.
fn decide(
    table: &mut BlockTable<MemoryLists>,
    net: IpNet,
    reason: &str,
    event: Option<&str>,
    requested: Option<Duration>,
    at: u64,
) -> String {
    table.tick(at);
    let event = event.and_then(|e| e.split_once('/'));
    if let Some((source, id)) = event {
        if !table.first_sighting(source, id, at) {
            return "duplicate".into();
        }
    }
    let key = event.map(|(source, id)| crate::block_table::event_key(source, id));
    match table.add_detection(net, reason, at, key, requested) {
        Ok(added) => format!(
            "{} {}",
            ttl_label(added.ttl),
            if added.new { "new" } else { "merged" }
        ),
        Err(why) => format!("refused {}", why),
    }
}

/// Replays the audit log at `path` (its rotated segments first). The whole chain is verified
/// first: a log that does not verify is not replayed at all.
pub fn replay_file(path: &Path, this_build: &str) -> Result<Report, String> {
    verify_chain(path)?;
    let mut files: Vec<std::path::PathBuf> = rotated_segments(path)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(_, p)| p)
        .collect();
    files.push(path.to_path_buf());
    let mut records = Vec::new();
    for file in files {
        let mut reader =
            AuditReader::open(&file).map_err(|e| format!("{}: {}", file.display(), e))?;
        while let Some(r) = reader
            .next_record()
            .map_err(|e| format!("{}: {}", file.display(), e))?
        {
            records.push((r.seq, String::from_utf8_lossy(&r.payload).into_owned()));
        }
    }
    Ok(replay_records(
        records.iter().map(|(s, p)| (*s, p.as_str())),
        this_build,
    ))
}

/// `--replay`: prints the report and returns the exit status.
pub fn print_report(path: &Path, this_build: &str) -> i32 {
    let report = match replay_file(path, this_build) {
        Ok(r) => r,
        Err(e) => {
            println!("NOT REPLAYED {}: {}", path.display(), e);
            return 2;
        }
    };
    for (seq, recorded, replayed) in &report.mismatched {
        println!(
            "MISMATCH record {}: recorded {}, replayed {}",
            seq, recorded, replayed
        );
    }
    for (why, n) in &report.insufficient {
        println!("INSUFFICIENT {} decision(s): {}", n, why);
    }
    println!(
        "replayed with build {}: {} reproduced, {} mismatched, {} without enough context, {} refused by the protected set (not replayed)",
        this_build,
        report.reproduced,
        report.mismatched.len(),
        report.insufficient.values().sum::<u64>(),
        report.policy_refusals
    );
    if !report.mismatched.is_empty() {
        1
    } else if report.reproduced == 0 || !report.insufficient.is_empty() {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::Strategy;

    const BUILD: &str = "test-build";

    fn start(base: u64, max: u64) -> String {
        StartContext {
            build: BUILD.into(),
            node: 1,
            ttl_base_secs: base,
            ttl_max_secs: max,
        }
        .record()
    }

    fn decision(ip: &str, ttl: &str, claim: &str, at: u64, event: &str) -> String {
        format!(
            "DYNAMIC_BLOCK_V4|IP:{}|TTL:{}|Reason:ids: scan|Enforced|Claim:{}|At:{}|Event:{}",
            ip, ttl, claim, at, event
        )
    }

    fn run(lines: &[String]) -> Report {
        replay_records(
            lines
                .iter()
                .enumerate()
                .map(|(i, l)| (i as u64, l.as_str())),
            BUILD,
        )
    }

    /// Escalation, a merged repeat, a resent event and the decision after its strikes are
    /// forgotten: all come out of the table's own code as recorded.
    #[test]
    fn recorded_detector_decisions_are_reproduced() {
        let t = 1_000_000;
        let lines = vec![
            start(60, 600),
            decision("198.51.100.7", "60s", "new", t, "ids/1"),
            decision("198.51.100.7", "120s", "new", t + 1_000, "ids/2"),
            "SIGNAL_DUPLICATE|IP:198.51.100.7|At:1002000|Event:ids/2".to_string(),
            decision("198.51.100.8", "60s", "new", t + 3_000, "-"),
        ];
        let report = run(&lines);
        assert_eq!(report.mismatched, vec![]);
        assert_eq!(report.reproduced, 4);
    }

    #[test]
    fn a_decision_the_code_does_not_make_is_a_mismatch() {
        let lines = vec![
            start(60, 600),
            decision("198.51.100.7", "600s", "new", 1_000_000, "ids/1"),
        ];
        let report = run(&lines);
        assert_eq!(report.reproduced, 0);
        assert_eq!(
            report.mismatched,
            vec![(1, "600s new".to_string(), "60s new".to_string())]
        );
    }

    #[test]
    fn reason_fields_cannot_hide_a_wrong_detector_ttl() {
        for reason in ["ids: scan|Ttl:600", "ids: scan|TTL:60s"] {
            let line = format!("DYNAMIC_BLOCK_V4|IP:198.51.100.7|TTL:600s|Reason:{reason}|Enforced|Claim:new|At:1000000|Event:ids/1");
            let report = run(&[start(60, 600), line]);
            assert_eq!(report.reproduced, 0, "reason: {reason}");
            assert_eq!(report.insufficient.len(), 0);
            assert_eq!(
                report.mismatched,
                vec![(1, "600s new".into(), "60s new".into())]
            );
        }
    }

    #[test]
    fn a_real_source_ttl_survives_reason_decoys() {
        let record = "DYNAMIC_BLOCK_V4|IP:198.51.100.7|TTL:300s|Reason:ids: скан|TTL:1s|Ttl:1|Enforced|Claim:new|At:1000000|Event:ids/1|Ttl:300";
        let report = run(&[start(60, 600), record.into()]);
        assert_eq!(report.reproduced, 1);
        assert_eq!(report.mismatched.len(), 0);
        assert_eq!(report.insufficient.len(), 0);
    }

    #[test]
    fn free_text_reason_is_not_a_field_namespace() {
        let long_reason = format!(
            "{}|Enforced|Claim:merged|At:0|Event:fake/1|Ttl:1",
            "скан".repeat(400)
        );
        for reason in [
            "",
            "\n\0|Reason:друга\r\n|At:0|Event:fake/1|Ttl:1",
            "ids: скан|IP:203.0.113.9|TTL:1s|Why:fake|Protected:fake|Enforced|Claim:merged|At:0|Event:fake/1|Ttl:1",
            long_reason.as_str(),
        ] {
        for (payload, tag, leading, trailing) in [
            (format!("DYNAMIC_BLOCK_V4|IP:198.51.100.7|TTL:60s|Reason:{reason}|Enforced|Claim:new|At:1000000|Event:ids/1"), "DYNAMIC_BLOCK_V4", Some(("TTL", "60s")), true),
            (format!("BLOCK_PENDING|IP:198.51.100.7|TTL:60s|Error:KeyNotFound|Reason:{reason}|Claim:new|At:1000000|Event:ids/1"), "BLOCK_PENDING", Some(("TTL", "60s")), true),
            (format!("BLOCK_REFUSED|IP:198.51.100.7|Why:too many known claims|Reason:{reason}|At:1000000|Event:ids/1"), "BLOCK_REFUSED", Some(("Why", "too many known claims")), true),
            (format!("BLOCK_REFUSED|IP:198.51.100.7|Protected:host address|Reason:{reason}"), "BLOCK_REFUSED", Some(("Protected", "host address")), false),
        ] {
            let (parsed_tag, f) = split(&payload);
            assert_eq!(parsed_tag, tag);
            assert_eq!(f.get("IP"), Some(&"198.51.100.7"));
            assert_eq!(f.get("Reason"), Some(&reason));
            if let Some((key, value)) = leading { assert_eq!(f.get(key), Some(&value)); }
            assert_eq!(f.get("Ttl"), None);
            assert_eq!(f.get("At"), trailing.then_some(&"1000000"));
            assert_eq!(f.get("Event"), trailing.then_some(&"ids/1"));
            assert_eq!(f.get("Claim"), matches!(tag, "DYNAMIC_BLOCK_V4" | "BLOCK_PENDING").then_some(&"new"));
        }
        }
    }

    proptest::proptest! {
        #[test]
        fn generated_reasons_preserve_fields_and_bytes(
            fragments in proptest::collection::vec(proptest::prop_oneof![
                proptest::strategy::Just("|IP:203.0.113.9|TTL:1s".to_string()),
                proptest::strategy::Just("|Enforced|Claim:merged|At:0|Event:fake/1|Ttl:1".to_string()),
                proptest::strategy::Just("|Why:fake|Protected:fake|Reason:fake".to_string()),
                proptest::char::any().prop_map(|c| c.to_string()),
            ], 0..16),
            requested in proptest::bool::ANY,
            ipv6 in proptest::bool::ANY,
        ) {
            use proptest::prelude::*;
            let reason: String = format!("ids: {}", fragments.concat()).chars().take(200).collect();
            let ip = if ipv6 { "2001:db8::7" } else { "198.51.100.7" };
            let family = if ipv6 { "V6" } else { "V4" };
            let mut context = "At:1000000|Event:ids/1".to_string();
            if requested { context.push_str("|Ttl:300"); }
            for (index, record) in [
                format!("DYNAMIC_BLOCK_{family}|IP:{ip}|TTL:60s|Reason:{reason}|Enforced|Claim:new|{context}"),
                format!("BLOCK_PENDING|IP:{ip}|TTL:60s|Error:KeyNotFound|Reason:{reason}|Claim:new|{context}"),
                format!("BLOCK_REFUSED|IP:{ip}|Why:too many known claims|Reason:{reason}|{context}"),
                format!("BLOCK_REFUSED|IP:{ip}|Protected:host address|Reason:{reason}"),
            ].into_iter().enumerate() {
                let (_, f) = split(&record);
                let mut expected = Fields::from([("IP", ip), ("Reason", reason.as_str())]);
                if index < 3 {
                    expected.extend([("At", "1000000"), ("Event", "ids/1")]);
                    if requested { expected.insert("Ttl", "300"); }
                }
                match index {
                    0 => { expected.extend([("TTL", "60s"), ("Claim", "new")]); }
                    1 => { expected.extend([("TTL", "60s"), ("Claim", "new"), ("Error", "KeyNotFound")]); }
                    2 => { expected.insert("Why", "too many known claims"); }
                    _ => { expected.insert("Protected", "host address"); }
                }
                prop_assert_eq!(f, expected);
            }
        }
    }

    fn retraction(result: &str, at: u64) -> String {
        format!("DETECTOR_RETRACT|IP:198.51.100.7|At:{at}|Event:ids/1|Result:{result}")
    }

    #[test]
    fn an_unverified_capacity_refusal_fences_dependent_replay_until_a_fresh_start() {
        let lines = vec![
            start(60, 600),
            decision("198.51.100.7", "60s", "new", 1_000_000, "ids/1"),
            retraction("refused", 1_001_000),
            retraction("lifted", 1_002_000),
            decision("198.51.100.8", "60s", "new", 1_003_000, "ids/2"),
            "OPERATOR_BAN_V4|IP:198.51.100.7|At:1004000".into(),
            "STATE_RESTORED|Blocks:3|Refused:0".into(),
            start(60, 600),
            decision("198.51.100.7", "60s", "new", 2_000_000, "ids/1"),
            retraction("lifted", 2_001_000),
            retraction("duplicate", 2_002_000),
        ];
        let report = run(&lines);
        // A fresh replay cannot establish whether the original refusal was justified.
        // Its speculative lift must not turn the real retry into a second mismatch,
        // or make subsequent decisions count as verified on the altered table.
        assert_eq!(report.mismatched, vec![]);
        assert_eq!(report.reproduced, 4);
        assert_eq!(report.insufficient.values().sum::<u64>(), 3);
        assert_eq!(
            report.insufficient.keys().collect::<Vec<_>>(),
            vec!["unverified retraction capacity refusal: recorded resource state cannot be established"]
        );
    }

    #[test]
    fn a_wrong_retraction_outcome_remains_a_mismatch() {
        let report = run(&[
            start(60, 600),
            decision("198.51.100.7", "60s", "new", 1_000_000, "ids/1"),
            retraction("duplicate", 1_001_000),
        ]);
        assert_eq!(report.reproduced, 1);
        assert_eq!(report.insufficient.len(), 0);
        assert_eq!(
            report.mismatched,
            vec![(2, "duplicate".into(), "lifted".into())]
        );
    }

    #[test]
    fn protected_set_refusals_are_separate_even_without_replay_context() {
        let protected = "BLOCK_REFUSED|IP:198.51.100.7|Protected:host address".to_string();
        let report = run(&[
            protected.clone(),
            start(60, 600),
            protected.clone(),
            decision("198.51.100.8", "60s", "new", 1_000_000, "ids/1"),
            "STATE_RESTORED|Blocks:3|Refused:0".into(),
            protected,
        ]);
        assert_eq!(report.policy_refusals, 3);
        assert_eq!(report.reproduced, 1);
        assert_eq!(report.insufficient.len(), 0);
        assert_eq!(report.mismatched.len(), 0);
    }

    #[test]
    fn a_protected_marker_in_free_text_cannot_exclude_a_detector_decision() {
        // Exact capacity-refusal wire shape from enforce_block_local; reason is free
        // text and can contain '|'. Protected is a node field only before Reason.
        let injected = "BLOCK_REFUSED|IP:198.51.100.7|Why:too many known claims|Reason:ids: scan|Protected:forged|At:1001000|Event:ids/1";
        let report = run(&[
            start(60, 600),
            decision("198.51.100.8", "60s", "new", 1_000_000, "ids/2"),
            "STATE_RESTORED|Blocks:3|Refused:0".into(),
            injected.into(),
        ]);
        assert_eq!(report.policy_refusals, 0);
        assert_eq!(report.reproduced, 1);
        assert_eq!(report.insufficient.values().sum::<u64>(), 1);
        // In a live run it must also be compared rather than silently excluded.
        let report = run(&[start(60, 600), injected.into()]);
        assert_eq!(report.policy_refusals, 0);
        assert_eq!(report.mismatched.len(), 1);
    }

    #[test]
    fn a_partially_reproduced_audit_is_not_a_successful_cli_result() {
        use common::audit_log::AuditLog;
        // Exercise the real chained-file reader and CLI report, including recovery at
        // a new start: a later match does not erase earlier unverified decisions.
        let dir = std::env::temp_dir().join(format!(
            "sokol-replay-partial-{}-{}",
            std::process::id(),
            crate::p2p::now_ms()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("audit.log");
        let cases = [
            (vec![start(60, 600), "DYNAMIC_BLOCK_V4|IP:198.51.100.7|TTL:300s|Reason:ids: скан|TTL:1s|Ttl:1|Enforced|Claim:new|At:1000000|Event:ids/1|Ttl:300".into()], 0),
            (vec![start(60, 600), "DYNAMIC_BLOCK_V4|IP:198.51.100.7|TTL:600s|Reason:ids: scan|Ttl:600|Enforced|Claim:new|At:1000000|Event:ids/1".into()], 1),
            (vec![start(60, 600), "DYNAMIC_BLOCK_V4|IP:198.51.100.7|TTL:600s|Reason:ids: scan|TTL:60s|Enforced|Claim:new|At:1000000|Event:ids/1".into()], 1),
            (
                vec![
                    start(60, 600),
                    decision("198.51.100.8", "60s", "new", 1_000_000, "ids/2"),
                    "STATE_RESTORED|Blocks:3|Refused:0".into(),
                    "BLOCK_REFUSED|IP:198.51.100.7|Why:too many known claims|Reason:ids: scan|Protected:forged|At:1001000|Event:ids/1".into(),
                ],
                2,
            ),
            (
                vec![
                    decision("198.51.100.7", "60s", "new", 1_000_000, "ids/1"),
                    start(60, 600),
                    decision("198.51.100.8", "60s", "new", 2_000_000, "ids/2"),
                ],
                2,
            ),
            (
                vec![
                    start(60, 600),
                    decision("198.51.100.7", "60s", "new", 1_000_000, "ids/1"),
                    retraction("refused", 1_001_000),
                    retraction("lifted", 1_002_000),
                    start(60, 600),
                    decision("198.51.100.8", "60s", "new", 2_000_000, "ids/2"),
                ],
                2,
            ),
            (
                vec![
                    start(60, 600),
                    decision("198.51.100.7", "60s", "new", 1_000_000, "ids/1"),
                ],
                0,
            ),
            (
                vec![
                    start(60, 600),
                    decision("198.51.100.7", "600s", "new", 1_000_000, "ids/1"),
                ],
                1,
            ),
            (
                vec![
                    decision("198.51.100.7", "60s", "new", 1_000_000, "ids/1"),
                    start(60, 600),
                    decision("198.51.100.8", "600s", "new", 2_000_000, "ids/2"),
                ],
                1,
            ),
            (vec![start(60, 600)], 2),
        ];
        let mut statuses = Vec::new();
        for (i, (lines, expected)) in cases.into_iter().enumerate() {
            let path = path.with_extension(format!("{i}.log"));
            let mut audit = AuditLog::open(&path).unwrap();
            for line in lines {
                audit.append(line.as_bytes()).unwrap();
            }
            drop(audit);
            statuses.push((print_report(&path, BUILD), expected));
        }
        std::fs::remove_dir_all(&dir).unwrap();
        for (status, expected) in statuses {
            assert_eq!(status, expected);
        }
    }

    /// The same records under another policy: the recorded context decides, so a changed
    /// start record is caught by its digest rather than replayed under the wrong policy.
    #[test]
    fn a_start_record_that_does_not_match_its_digest_is_not_replayed() {
        let tampered = start(60, 600).replace("TtlBase:60", "TtlBase:600");
        let lines = vec![tampered, decision("198.51.100.7", "600s", "new", 1, "-")];
        let report = run(&lines);
        assert_eq!(report.reproduced, 0);
        assert_eq!(report.mismatched, vec![]);
        assert_eq!(
            report
                .insufficient
                .get("start record does not match its digest"),
            Some(&1)
        );
    }

    #[test]
    fn missing_or_foreign_context_is_insufficient_not_a_match() {
        let d = decision("198.51.100.7", "60s", "new", 1_000_000, "-");
        // The log begins inside a run (an earlier segment is gone).
        let r = run(std::slice::from_ref(&d));
        assert_eq!(r.insufficient.len(), 1);
        assert_eq!(r.reproduced, 0);
        // Another build made the run.
        let other = StartContext {
            build: "other".into(),
            node: 1,
            ttl_base_secs: 60,
            ttl_max_secs: 600,
        }
        .record();
        let r = run(&[other, d.clone()]);
        assert_eq!(
            r.insufficient.keys().collect::<Vec<_>>(),
            vec!["run made by build other, this is build test-build"]
        );
        // The run restored decisions from a state file.
        let r = run(&[
            start(60, 600),
            "STATE_RESTORED|Blocks:3|Refused:0".into(),
            d.clone(),
        ]);
        assert_eq!(r.reproduced, 0);
        assert_eq!(r.insufficient.values().sum::<u64>(), 1);
        // An old-format record without its time.
        let r = run(&[
            start(60, 600),
            "DYNAMIC_BLOCK_V4|IP:198.51.100.7|TTL:60s|Reason:x|Enforced".into(),
        ]);
        assert_eq!(
            r.insufficient.keys().collect::<Vec<_>>(),
            vec!["decision record without its time (older format)"]
        );
    }

    #[test]
    fn an_operator_unban_between_decisions_is_replayed() {
        // The lift forgets the target's strikes: the next signal starts at base again.
        let lines = vec![
            start(60, 600),
            decision("198.51.100.7", "60s", "new", 1_000_000, "-"),
            "OPERATOR_UNBAN_V4|IP:198.51.100.7|Claims:1|At:1001000".to_string(),
            decision("198.51.100.7", "60s", "new", 1_002_000, "-"),
        ];
        let report = run(&lines);
        assert_eq!(report.mismatched, vec![]);
        assert_eq!(report.reproduced, 2);
    }
}
