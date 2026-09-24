use std::collections::HashMap;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use common::audit_log::{verify_chain, AuditReader};

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
    if reader.is_none() {
        *reader = Some(AuditReader::open(path)?);
    }
    let r = reader.as_mut().unwrap();

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
                if let Some(idx) = line.find("key:") {
                    let key_str = &line[idx + 4..];
                    let hex_bytes: Vec<u8> = key_str
                        .split_whitespace()
                        .filter_map(|s| u8::from_str_radix(s, 16).ok())
                        .collect();

                    if hex_bytes.len() >= 8 {
                        let ip = format!(
                            "{}.{}.{}.{}",
                            hex_bytes[4], hex_bytes[5], hex_bytes[6], hex_bytes[7]
                        );
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
/// Exit code 0 = intact, 1 = broken. Record the printed head somewhere the node cannot write
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
        Err(e) => {
            println!("BROKEN {}: {}", path, e);
            std::process::exit(1);
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--verify") {
        verify(args.get(2).map(String::as_str).unwrap_or(DB_FILE));
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

        for ev in &events[start..] {
            println!(
                "{:<6} | {:<15} | {:<18.18} | {:<6} | {:<20.20}",
                ev.seq, ev.ip, ev.tier, ev.payload_len, ev.payload_snippet
            );
        }

        println!("\n[Press Ctrl+C to exit]");
        thread::sleep(Duration::from_secs(2));
    }
}
