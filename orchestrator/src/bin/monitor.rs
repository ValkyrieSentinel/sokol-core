// Release builds abort on panic (panic = "abort"), so a panic reachable from input (a peer's
// frame, an IPC line, a trap connection, a file) stops the node. Outside tests, code must not
// be able to panic: no unwrap/expect, no unchecked indexing or slicing, no panic!-family macros.
// A provably safe exception is allowed locally, with its reason.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use common::audit_log::{rotated_segments, verify_chain, AuditReader, ChainVerifyError};

const DB_FILE: &str = "/var/lib/sokol/audit.log";

#[derive(Debug, Clone)]
struct AuditEvent {
    seq: u64,
    ip: String,
    tier: String,
    payload_len: String,
    payload_snippet: String,
    #[allow(dead_code)]
    raw: String,
}

type Reader = AuditReader<io::BufReader<std::fs::File>>;

fn read_new_events(reader: &mut Option<Reader>, events: &mut Vec<AuditEvent>) -> io::Result<()> {
    let path = Path::new(DB_FILE);
    if !path.exists() {
        *reader = None;
        events.clear();
        return Ok(());
    }

    // A file smaller than what we already verified was replaced: start over.
    if let Some(r) = reader.as_ref() {
        if std::fs::metadata(path)?.len() < r.offset() {
            *reader = None;
            events.clear();
        }
    }
    let r = match reader {
        Some(r) => r,
        None => reader.insert(AuditReader::open(path)?),
    };

    loop {
        let record = match r.next_record() {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(e) => return Err(io::Error::other(e.to_string())),
        };
        let data_len = record.payload.len();
        {
            let log_str = String::from_utf8_lossy(&record.payload)
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .to_string();

            let mut ip = "Unknown".to_string();
            let mut tier = "Event".to_string();
            let mut payload_len = data_len.to_string();
            let mut payload_snippet = String::new();

            let parts: Vec<&str> = log_str.split('|').collect();
            if let Some(first) = parts.first() {
                tier = first.trim().to_string();
            }

            for part in &parts {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("IP=") {
                    ip = val.to_string();
                } else if let Some(val) = part.strip_prefix("IP:") {
                    ip = val.to_string();
                } else if let Some(val) = part.strip_prefix("TIER=") {
                    tier = val.to_string();
                } else if let Some(val) = part.strip_prefix("LEN=") {
                    payload_len = val.to_string();
                } else if let Some(val) = part.strip_prefix("DATA=") {
                    payload_snippet = val.to_string();
                }
            }

            if ip == "Unknown" {
                if let Some(found_ip) = log_str
                    .split(|c: char| {
                        c.is_whitespace()
                            || c == '|'
                            || c == '='
                            || c == ','
                            || c == '"'
                            || c == '\''
                    })
                    .map(|token| token.trim_matches(|c: char| !c.is_ascii_digit() && c != '.'))
                    .find_map(|candidate| candidate.parse::<Ipv4Addr>().ok())
                {
                    ip = found_ip.to_string();
                }
            }

            if payload_snippet.is_empty() {
                payload_snippet = log_str.chars().take(30).collect();
            }

            events.push(AuditEvent {
                seq: record.seq,
                ip,
                tier,
                payload_len,
                payload_snippet,
                raw: log_str,
            });
        }
    }

    Ok(())
}

fn get_ebpf_active_blocks() -> Vec<String> {
    let output = Command::new("bpftool")
        .args(["map", "dump", "name", "BLOCKLIST_V4"])
        .output()
        .or_else(|_| {
            Command::new("sudo")
                .args(["bpftool", "map", "dump", "name", "BLOCKLIST_V4"])
                .output()
        });

    let mut banned_ips = Vec::new();
    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if let Some((_, key_str)) = line.split_once("key:") {
                    let hex_bytes: Vec<u8> = key_str
                        .split_whitespace()
                        .filter_map(|s| u8::from_str_radix(s, 16).ok())
                        .collect();

                    if let Some([a, b, c, d]) = hex_bytes.get(4..8) {
                        let ip = format!("{}.{}.{}.{}", a, b, c, d);
                        banned_ips.push(ip);
                    }
                }
            }
        }
    }
    banned_ips
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// `monitor --verify [path]`: checks every retained segment and the active log as one chain.
/// Exit code 0 = verified retained chain, 1 = observed corruption, 2 = unverified (I/O).
/// Record the printed head somewhere the node cannot write
/// to make later rewrites of the whole chain detectable.
fn verify(path: &str) -> ! {
    match verify_chain(Path::new(path)) {
        Ok(s) => {
            println!(
                "OK {}: {} file(s), records {}..{}, head {}",
                path,
                s.segments,
                s.first_seq,
                s.next_seq,
                to_hex(&s.head)
            );
            std::process::exit(0);
        }
        Err(e @ ChainVerifyError::Broken { .. }) => {
            println!("BROKEN {}: {}", path, e);
            std::process::exit(1);
        }
        Err(e) => {
            println!("UNVERIFIED {}: {}", path, e);
            std::process::exit(2);
        }
    }
}

/// `monitor --dump [path]`: every verified record of the active file as
/// `<seq>\t<timestamp_ms>\t<payload>`, for scripts and investigations.
fn dump(path: &str) -> ! {
    let mut reader = match AuditReader::open(Path::new(path)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot open {}: {}", path, e);
            std::process::exit(1);
        }
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    loop {
        match reader.next_record() {
            Ok(Some(r)) => {
                let text: String = String::from_utf8_lossy(&r.payload)
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect();
                let _ = writeln!(out, "{}\t{}\t{}", r.seq, r.timestamp_ms, text);
            }
            Ok(None) => std::process::exit(0),
            Err(e) => {
                eprintln!("{}: {}", path, e);
                std::process::exit(1);
            }
        }
    }
}

/// One `BLOCK_OUTCOME` record: packets dropped (`None`: unknown), seconds in force, cause.
fn parse_outcome(text: &str) -> Option<(Option<u64>, u64, String)> {
    let rest = text.strip_prefix("BLOCK_OUTCOME|")?;
    let (fields, cause) = match rest.split_once("|Cause:") {
        Some((fields, cause)) => (fields, cause.to_string()),
        None => (rest, "unknown".to_string()),
    };
    let field = |name: &str| {
        fields
            .split('|')
            .find_map(|f| f.strip_prefix(name))
            .map(str::to_string)
    };
    let dropped = field("Dropped:")?.parse().ok();
    let seconds = field("Seconds:")?.parse().ok()?;
    Some((dropped, seconds, cause))
}

/// Groups causes by what decided them, not by the details that vary between decisions: the
/// text before a parenthesis (CrowdSec appends the remaining duration), at most 80 characters.
fn cause_key(cause: &str) -> String {
    let base = cause.split(" (").next().unwrap_or(cause).trim();
    base.chars().take(80).collect()
}

#[derive(Default, Debug, PartialEq)]
struct CauseStats {
    blocks: u64,
    dropped_nothing: u64,
    unknown: u64,
    packets: u64,
    seconds: Vec<u64>,
}

fn summarize<'a>(records: impl Iterator<Item = &'a str>) -> Vec<(String, CauseStats)> {
    let mut by: std::collections::BTreeMap<String, CauseStats> = Default::default();
    for text in records {
        let Some((dropped, seconds, cause)) = parse_outcome(text) else {
            continue;
        };
        let s = by.entry(cause_key(&cause)).or_default();
        s.blocks += 1;
        match dropped {
            Some(0) => s.dropped_nothing += 1,
            Some(n) => s.packets += n,
            None => s.unknown += 1,
        }
        s.seconds.push(seconds);
    }
    let mut out: Vec<(String, CauseStats)> = by.into_iter().collect();
    out.sort_by(|a, b| b.1.blocks.cmp(&a.1.blocks).then(a.0.cmp(&b.0)));
    out
}

/// `monitor --outcomes [path]`: what the node's blocks did, by the decision behind them, over
/// the whole retained audit chain. Evidence for reviewing detectors and TTLs, not a verdict.
fn outcomes(path: &str) -> ! {
    let mut files: Vec<std::path::PathBuf> = rotated_segments(Path::new(path))
        .map(|segs| segs.into_iter().map(|(_, p)| p).collect())
        .unwrap_or_default();
    files.push(Path::new(path).to_path_buf());
    let mut texts = Vec::new();
    for file in &files {
        let Ok(mut reader) = AuditReader::open(file) else {
            continue;
        };
        while let Ok(Some(r)) = reader.next_record() {
            texts.push(String::from_utf8_lossy(&r.payload).into_owned());
        }
    }
    let rows = summarize(texts.iter().map(String::as_str));
    println!(
        "{:>7} {:>9} {:>11} {:>9}  cause",
        "blocks", "idle %", "packets", "median s"
    );
    for (cause, s) in rows {
        let mut secs = s.seconds.clone();
        secs.sort_unstable();
        let median = secs.get(secs.len() / 2).copied().unwrap_or(0);
        println!(
            "{:>7} {:>8.0}% {:>11} {:>9}  {}",
            s.blocks,
            100.0 * s.dropped_nothing as f64 / s.blocks.max(1) as f64,
            s.packets,
            median,
            cause
        );
    }
    std::process::exit(0)
}

/// A field of an audit record: the text after `|<name>:` up to the next `|`.
fn record_field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.split('|')
        .find_map(|f| f.strip_prefix(name)?.strip_prefix(':'))
}

/// Who asked for a block, from a decision's reason or an outcome's cause: a detector's name
/// (`suricata: …`), `trap`, `telemetry`, `peer <id>`, `operator` or `static`.
fn source_of(text: &str) -> String {
    let text = text.strip_prefix("detector: ").unwrap_or(text);
    if let Some(rest) = text.strip_prefix("peer ") {
        return format!("peer {}", rest.split(':').next().unwrap_or("").trim());
    }
    for (prefix, source) in [
        ("operator", "operator"),
        ("static", "static"),
        ("Decoy TCP trap hit", "trap"),
        ("Unix IPC DROP_IMMEDIATE", "trap"),
        ("eBPF XDP probe drop", "telemetry"),
    ] {
        if text.starts_with(prefix) {
            return source.to_string();
        }
    }
    match text.split_once(": ") {
        Some((name, _))
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') =>
        {
            name.to_string()
        }
        _ => "other".to_string(),
    }
}

/// How a block left the kernel map, from the record that preceded its outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    Expired,
    OperatorLift,
    SourceRetraction,
}

/// A new decision on a target this soon after the operator lifted it is a relapse: the human
/// and the detector disagree.
const RELAPSE_MS: u64 = 10 * 60 * 1000;

/// What a source's blocks became (ROADMAP: regret, measured, not optimized). Regret is a lower
/// bound of harm: a block that hurt someone who never complained leaves no trace here.
#[derive(Default, Debug, PartialEq, Eq)]
struct Regret {
    /// Blocks that left the map (one per BLOCK_OUTCOME).
    blocks: u64,
    /// Dropped nothing: cost a slot and a broadcast, did nothing (idle, not wrong).
    idle: u64,
    unknown: u64,
    packets: u64,
    /// The operator lifted it in the first half of its duration, or a permanent one: a
    /// correction. Later lifts are counted apart: often a cleanup after the attack.
    lifted_early: u64,
    lifted_late: u64,
    /// A new decision of the same source on the same target within RELAPSE_MS of a lift.
    relapses: u64,
    /// Ended by an operator flush (all dynamic blocks at once): incident response.
    flushed: u64,
    /// Taken back by its source (a retraction; with CrowdSec also a timed decision's expiry).
    retracted: u64,
    expired: u64,
    /// Ended otherwise (quorum, envelope, protected set, a newer decision, a restart).
    other: u64,
}

fn regret<'a>(records: impl Iterator<Item = (u64, &'a str)>) -> Vec<(String, Regret)> {
    let mut by: std::collections::BTreeMap<String, Regret> = Default::default();
    // Per target: the last decision's duration (ms; None: permanent) and source, the record
    // that ended its block, and when the operator last lifted it.
    let mut decided: HashMap<String, (Option<u64>, String)> = HashMap::new();
    let mut ended: HashMap<String, (Ended, u64)> = HashMap::new();
    let mut lifted: HashMap<String, (u64, String)> = HashMap::new();
    let mut flushed_at: Option<u64> = None;
    for (at, text) in records {
        let ip = record_field(text, "IP").map(str::to_string);
        let tag = text.split('|').next().unwrap_or("");
        match (tag, ip) {
            (t, Some(ip)) if t.starts_with("DYNAMIC_BLOCK_") || t == "BLOCK_PENDING" => {
                let reason = text.split_once("|Reason:").map_or("", |(_, r)| r);
                let source = source_of(reason);
                let ttl = record_field(text, "TTL")
                    .and_then(|t| t.strip_suffix('s'))
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|s| s * 1000);
                if let Some((lift_at, by_source)) = lifted.remove(&ip) {
                    if by_source == source && at.saturating_sub(lift_at) <= RELAPSE_MS {
                        by.entry(source.clone()).or_default().relapses += 1;
                    }
                }
                decided.insert(ip, (ttl, source));
            }
            (t, Some(ip)) if t.starts_with("OPERATOR_UNBAN_") => {
                ended.insert(ip, (Ended::OperatorLift, at));
            }
            ("DETECTOR_RETRACT", Some(ip)) if record_field(text, "Result") == Some("lifted") => {
                ended.insert(ip, (Ended::SourceRetraction, at));
            }
            (t, Some(ip)) if t.starts_with("BLOCK_EXPIRED_") => {
                ended.insert(ip, (Ended::Expired, at));
            }
            ("OPERATOR_FLUSH" | "OPERATOR_FLUSH_ALL", _)
                if record_field(text, "Released").is_some_and(|n| n != "0") =>
            {
                flushed_at = Some(at);
            }
            ("BLOCK_OUTCOME", Some(ip)) => {
                let Some((dropped, seconds, cause)) = parse_outcome(text) else {
                    continue;
                };
                let source = source_of(&cause);
                let since = at.saturating_sub(seconds.saturating_mul(1000) + 1000);
                let s = by.entry(source.clone()).or_default();
                s.blocks += 1;
                match dropped {
                    Some(0) => s.idle += 1,
                    Some(n) => s.packets += n,
                    None => s.unknown += 1,
                }
                match ended.remove(&ip).filter(|(_, when)| *when >= since) {
                    Some((Ended::OperatorLift, when)) => {
                        let ttl = decided.get(&ip).and_then(|(ttl, _)| *ttl);
                        if ttl.is_none_or(|ttl| seconds.saturating_mul(2000) < ttl) {
                            s.lifted_early += 1;
                        } else {
                            s.lifted_late += 1;
                        }
                        lifted.insert(ip, (when, source));
                    }
                    Some((Ended::SourceRetraction, _)) => s.retracted += 1,
                    Some((Ended::Expired, _)) => s.expired += 1,
                    None if flushed_at.is_some_and(|f| f >= since) => s.flushed += 1,
                    None => s.other += 1,
                }
            }
            _ => {}
        }
    }
    let mut out: Vec<(String, Regret)> = by.into_iter().collect();
    out.sort_by(|a, b| b.1.blocks.cmp(&a.1.blocks).then(a.0.cmp(&b.0)));
    out
}

/// Every record of the retained audit chain, oldest first, with its timestamp.
fn chain_records(path: &str) -> Vec<(u64, String)> {
    let mut files: Vec<std::path::PathBuf> = rotated_segments(Path::new(path))
        .map(|segs| segs.into_iter().map(|(_, p)| p).collect())
        .unwrap_or_default();
    files.push(Path::new(path).to_path_buf());
    let mut records = Vec::new();
    for file in &files {
        let Ok(mut reader) = AuditReader::open(file) else {
            continue;
        };
        while let Ok(Some(r)) = reader.next_record() {
            records.push((
                r.timestamp_ms,
                String::from_utf8_lossy(&r.payload).into_owned(),
            ));
        }
    }
    records
}

/// `monitor --regret [path]`: by source, what its blocks became; corrections by the operator
/// and blocks that did nothing, beside the packets they dropped. Measured, not a verdict.
fn regret_report(path: &str) -> ! {
    let records = chain_records(path);
    let rows = regret(records.iter().map(|(at, t)| (*at, t.as_str())));
    println!(
        "{:>7} {:>7} {:>11} {:>8} {:>7} {:>8} {:>8} {:>9} {:>8} {:>6}  source",
        "blocks",
        "idle %",
        "packets",
        "lifted",
        "late",
        "relapse",
        "flushed",
        "retracted",
        "expired",
        "other"
    );
    for (source, r) in rows {
        println!(
            "{:>7} {:>6.0}% {:>11} {:>8} {:>7} {:>8} {:>8} {:>9} {:>8} {:>6}  {}",
            r.blocks,
            100.0 * r.idle as f64 / r.blocks.max(1) as f64,
            r.packets,
            r.lifted_early,
            r.lifted_late,
            r.relapses,
            r.flushed,
            r.retracted,
            r.expired,
            r.other,
            source
        );
    }
    println!(
        "lifted: by the operator in the first half of the block's duration (a correction); late:\n\
         after it (often a cleanup). Regret is a lower bound: harm nobody reported is not here."
    );
    std::process::exit(0)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--verify") => verify(args.get(2).map(String::as_str).unwrap_or(DB_FILE)),
        Some("--dump") => dump(args.get(2).map(String::as_str).unwrap_or(DB_FILE)),
        Some("--outcomes") => outcomes(args.get(2).map(String::as_str).unwrap_or(DB_FILE)),
        Some("--regret") => regret_report(args.get(2).map(String::as_str).unwrap_or(DB_FILE)),
        _ => {}
    }

    let mut reader: Option<Reader> = None;
    let mut events: Vec<AuditEvent> = Vec::new();
    let mut read_error: Option<String> = None;

    loop {
        read_error = read_new_events(&mut reader, &mut events)
            .err()
            .map(|e| e.to_string())
            .or(read_error);

        let total_attacks = events.len();
        let mut unique_ips = HashMap::new();
        let mut tiers_counter = HashMap::new();

        for ev in &events {
            *unique_ips.entry(ev.ip.clone()).or_insert(0) += 1;
            *tiers_counter.entry(ev.tier.clone()).or_insert(0) += 1;
        }

        let ebpf_blocks = get_ebpf_active_blocks();

        print!("\x1B[H\x1B[2J");
        io::stdout().flush()?;

        println!("==================================================================");
        println!("       SOKOL-CORE: RUST NATIVE SECURITY & EBPF TELEMETRY         ");
        println!("==================================================================");

        if let Some(err) = &read_error {
            println!("[!] AUDIT LOG VERIFICATION FAILED: {}", err);
        }
        println!("[*] Total Intercepted Attacks (audit) : {}", total_attacks);
        println!(
            "[*] Unique Attacker IPs Logged         : {}",
            unique_ips.len()
        );
        println!(
            "[*] Active eBPF XDP Kernel Drops (IPs) : {}",
            ebpf_blocks.len()
        );

        println!("\n--- Active eBPF Kernel Blocklist (BLOCKLIST_V4) ---");
        if ebpf_blocks.is_empty() {
            println!("    (No active IP blocks in kernel XDP map yet)");
        } else {
            for ip in &ebpf_blocks {
                println!("    [XDP_DROP] Blocked IP -> {}", ip);
            }
        }

        println!("\n--- Trident Tier Distribution ---");
        for (tier, count) in &tiers_counter {
            println!("    {:<25} : {}", tier, count);
        }

        println!("\n--- Live Captured Attack Payloads (audit log) ---");
        println!(
            "{:<6} | {:<15} | {:<18} | {:<6} | {:<20}",
            "SEQ", "IP ADDRESS", "TIER", "LEN", "PAYLOAD SNIPPET"
        );
        println!("{}", "-".repeat(78));

        let start = events.len().saturating_sub(8);

        for ev in events.iter().skip(start) {
            println!(
                "{:<6} | {:<15} | {:<18.18} | {:<6} | {:<20.20}",
                ev.seq, ev.ip, ev.tier, ev.payload_len, ev.payload_snippet
            );
        }

        println!("\n[Press Ctrl+C to exit]");
        thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1000;

    fn decision(ip: &str, ttl: &str, reason: &str) -> String {
        format!(
            "DYNAMIC_BLOCK_V4|IP:{ip}|TTL:{ttl}|Reason:{reason}|Enforced|Claim:new|At:0|Event:-"
        )
    }

    fn outcome(ip: &str, dropped: &str, seconds: u64, cause: &str) -> String {
        format!("BLOCK_OUTCOME|IP:{ip}|Dropped:{dropped}|Seconds:{seconds}|Cause:{cause}")
    }

    fn row(rows: &[(String, Regret)], source: &str) -> Regret {
        let r = rows.iter().find(|(s, _)| s == source);
        let r = r.unwrap_or_else(|| panic!("no row for {source}: {rows:?}"));
        Regret { ..r.1 }
    }

    /// Each way a block ends is told apart, per source, from the records the node writes.
    #[test]
    fn regret_tells_how_each_block_ended_and_who_asked_for_it() {
        let records: Vec<(u64, String)> = vec![
            // suricata: lifted after 10 s of a 600 s block (a correction), then decided again
            // 2 minutes later (a relapse).
            (0, decision("198.51.100.1", "600s", "suricata: sid:1 scan")),
            (
                10 * S,
                "OPERATOR_UNBAN_V4|IP:198.51.100.1|Claims:1|At:10000".into(),
            ),
            (
                11 * S,
                outcome("198.51.100.1", "0", 10, "detector: suricata: sid:1 scan"),
            ),
            (
                131 * S,
                decision("198.51.100.1", "600s", "suricata: sid:1 scan"),
            ),
            // suricata: lifted after 500 s of 600 s (late, often a cleanup), with packets.
            (0, decision("198.51.100.2", "600s", "suricata: sid:2 brute")),
            (
                500 * S,
                "OPERATOR_UNBAN_V4|IP:198.51.100.2|Claims:1|At:500000".into(),
            ),
            (
                501 * S,
                outcome("198.51.100.2", "40", 500, "detector: suricata: sid:2 brute"),
            ),
            // crowdsec: taken back by its source; expired; flushed by the operator.
            (
                0,
                decision(
                    "198.51.100.3",
                    "3600s",
                    "crowdsec: ssh-bf (origin crowdsec)",
                ),
            ),
            (
                30 * S,
                "DETECTOR_RETRACT|IP:198.51.100.3|Result:lifted|Claims:1|At:30000|Event:crowdsec/7"
                    .into(),
            ),
            (
                31 * S,
                outcome(
                    "198.51.100.3",
                    "0",
                    30,
                    "detector: crowdsec: ssh-bf (origin crowdsec)",
                ),
            ),
            (
                0,
                decision("198.51.100.4", "60s", "crowdsec: ssh-bf (origin crowdsec)"),
            ),
            (60 * S, "BLOCK_EXPIRED_V4|IP:198.51.100.4".into()),
            (
                60 * S,
                outcome(
                    "198.51.100.4",
                    "unknown",
                    60,
                    "detector: crowdsec: ssh-bf (origin crowdsec)",
                ),
            ),
            (
                0,
                decision("198.51.100.5", "3600s", "crowdsec: http-probing"),
            ),
            (70 * S, "OPERATOR_FLUSH|Released:1|At:70000".into()),
            (
                71 * S,
                outcome("198.51.100.5", "3", 70, "detector: crowdsec: http-probing"),
            ),
            // trap, telemetry and a peer: sources named without a "<name>: " prefix.
            (
                80 * S,
                outcome(
                    "198.51.100.6",
                    "1",
                    5,
                    "detector: Decoy TCP trap hit on port 2222",
                ),
            ),
            (
                80 * S,
                outcome(
                    "198.51.100.7",
                    "0",
                    5,
                    "detector: eBPF XDP probe drop (score: 0.91)",
                ),
            ),
            (
                80 * S,
                outcome("198.51.100.8", "0", 5, "peer 3: suricata: sid:9 x"),
            ),
            // A permanent decision lifted at any time is a correction.
            (
                0,
                decision("198.51.100.9", "permanent", "suricata: sid:3 c2"),
            ),
            (
                900 * S,
                "OPERATOR_UNBAN_V4|IP:198.51.100.9|Claims:1|At:900000".into(),
            ),
            (
                901 * S,
                outcome("198.51.100.9", "7", 900, "detector: suricata: sid:3 c2"),
            ),
            // An end record from before the block was applied is not its end.
            (0, "BLOCK_EXPIRED_V4|IP:198.51.100.10".into()),
            (
                5000 * S,
                outcome("198.51.100.10", "0", 10, "detector: suricata: sid:4 y"),
            ),
        ];
        let rows = regret(records.iter().map(|(at, t)| (*at, t.as_str())));
        let suricata = row(&rows, "suricata");
        assert_eq!(
            (
                suricata.blocks,
                suricata.lifted_early,
                suricata.lifted_late,
                suricata.relapses
            ),
            (4, 2, 1, 1)
        );
        assert_eq!(
            (suricata.idle, suricata.packets, suricata.other),
            (2, 47, 1)
        );
        let crowdsec = row(&rows, "crowdsec");
        assert_eq!(
            (
                crowdsec.blocks,
                crowdsec.retracted,
                crowdsec.expired,
                crowdsec.flushed
            ),
            (3, 1, 1, 1)
        );
        assert_eq!(
            (crowdsec.idle, crowdsec.unknown, crowdsec.packets),
            (1, 1, 3)
        );
        assert_eq!(row(&rows, "trap").packets, 1);
        assert_eq!(row(&rows, "telemetry").idle, 1);
        assert_eq!(row(&rows, "peer 3").blocks, 1);
        assert_eq!(rows.iter().map(|r| r.1.blocks).sum::<u64>(), 10);
    }

    #[test]
    fn source_names_are_detector_names_or_other() {
        assert_eq!(source_of("detector: my-ids_2: x"), "my-ids_2");
        assert_eq!(
            source_of("detector: my ids: x"),
            "other",
            "a space is not in a name"
        );
        assert_eq!(source_of("detector: : x"), "other", "an empty name");
        assert_eq!(source_of("detector: no prefix at all"), "other");
        assert_eq!(source_of("operator: ban"), "operator");
        assert_eq!(source_of("static: --block"), "static");
    }

    /// The edges: an end record within the one second the outcome's whole seconds can hide;
    /// a lift at exactly half the duration is late, one second earlier is early; a detector
    /// retraction that left the block held is not its end.
    #[test]
    fn regret_edges() {
        let records: Vec<(u64, String)> = vec![
            (
                500,
                "DETECTOR_RETRACT|IP:198.51.100.1|Result:lifted|Claims:1|At:500|Event:ids/1".into(),
            ),
            (10_900, outcome("198.51.100.1", "0", 10, "detector: ids: x")),
            (0, decision("198.51.100.2", "600s", "ids: x")),
            (
                300 * S,
                "OPERATOR_UNBAN_V4|IP:198.51.100.2|Claims:1|At:300000".into(),
            ),
            (
                300 * S,
                outcome("198.51.100.2", "0", 300, "detector: ids: x"),
            ),
            (0, decision("198.51.100.3", "600s", "ids: x")),
            (
                299 * S,
                "OPERATOR_UNBAN_V4|IP:198.51.100.3|Claims:1|At:299000".into(),
            ),
            (
                299 * S,
                outcome("198.51.100.3", "0", 299, "detector: ids: x"),
            ),
            (
                0,
                "DETECTOR_RETRACT|IP:198.51.100.4|Result:still_held|Claims:0|At:0|Event:ids/2"
                    .into(),
            ),
            (60 * S, outcome("198.51.100.4", "0", 60, "detector: ids: x")),
            // A flush that released nothing ended no block.
            (70 * S, "OPERATOR_FLUSH|Released:0|At:70000".into()),
            (71 * S, outcome("198.51.100.5", "0", 5, "detector: ids: x")),
        ];
        let rows = regret(records.iter().map(|(at, t)| (*at, t.as_str())));
        let r = row(&rows, "ids");
        assert_eq!(
            (r.retracted, r.lifted_late, r.lifted_early, r.other),
            (1, 1, 1, 2)
        );
        assert_eq!(r.flushed, 0);
    }

    /// The report reads the real chain, rotated segments included, oldest first.
    #[test]
    fn the_report_reads_every_record_of_the_chain() {
        let dir = std::env::temp_dir().join(format!("sokol-regret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let mut log = common::audit_log::AuditLog::open(&path).unwrap();
        log.append(b"first").unwrap();
        log.append(b"second").unwrap();
        log.sync().unwrap();
        let records = chain_records(path.to_str().unwrap());
        assert_eq!(
            records.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert!(
            records.iter().all(|(at, _)| *at > 0),
            "records carry their time"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_relapse_is_the_same_source_soon_after_a_lift() {
        let lift = |ip: &str| -> Vec<(u64, String)> {
            vec![
                (0, decision(ip, "600s", "suricata: sid:1 scan")),
                (
                    10 * S,
                    format!("OPERATOR_UNBAN_V4|IP:{ip}|Claims:1|At:10000"),
                ),
                (
                    11 * S,
                    outcome(ip, "0", 10, "detector: suricata: sid:1 scan"),
                ),
            ]
        };
        let mut records = lift("198.51.100.1");
        records.push((
            11 * S + RELAPSE_MS,
            decision("198.51.100.1", "600s", "suricata: sid:1 scan"),
        ));
        records.extend(lift("198.51.100.2"));
        records.push((20 * S, decision("198.51.100.2", "600s", "crowdsec: ssh-bf")));
        let rows = regret(records.iter().map(|(at, t)| (*at, t.as_str())));
        assert_eq!(
            row(&rows, "suricata").relapses,
            0,
            "too late, and another source"
        );
    }

    #[test]
    fn outcomes_are_grouped_by_the_decision_behind_them() {
        let records = [
            "BLOCK_OUTCOME|IP:198.51.100.1|Dropped:0|Seconds:900|Cause:detector: crowdsec: ssh-bf (origin crowdsec, crowdsec duration 3h59m)",
            "BLOCK_OUTCOME|IP:198.51.100.2|Dropped:40|Seconds:600|Cause:detector: crowdsec: ssh-bf (origin crowdsec, crowdsec duration 1h2m)",
            "BLOCK_OUTCOME|IP:198.51.100.3|Dropped:unknown|Seconds:30|Cause:operator: ban",
            "BLOCK_OUTCOME|IP:198.51.100.4|Dropped:5|Seconds:10",
            "BLOCK_EXPIRED_V4|IP:198.51.100.9",
        ];
        let rows = summarize(records.iter().copied());
        assert_eq!(
            rows[0].0, "detector: crowdsec: ssh-bf",
            "durations do not split a cause"
        );
        assert_eq!(
            (
                rows[0].1.blocks,
                rows[0].1.dropped_nothing,
                rows[0].1.packets
            ),
            (2, 1, 40)
        );
        let operator = rows.iter().find(|r| r.0 == "operator: ban").unwrap();
        assert_eq!(operator.1.unknown, 1);
        assert!(
            rows.iter().any(|r| r.0 == "unknown"),
            "a record without a cause still counts"
        );
        assert_eq!(rows.iter().map(|r| r.1.blocks).sum::<u64>(), 4);
    }
}
