//! `--verify-witnesses` (ADR-0021): checks this node's audit log against the heads a peer
//! recorded for it. The hash chain alone detects edits that do not recompute every later
//! record; a writer with full access can recompute it. A head kept in a peer's log, under the
//! peer's own chain, is out of that writer's reach unless it rewrites the peer's log as well.
use std::path::Path;

use common::audit_log::{check_witnesses, verify_chain, AuditReader, WitnessVerdict, CHAIN_LEN};

/// One witness the peer's log holds for `node_id`: (peer's record seq, records, head).
pub type Witness = (u64, u64, [u8; CHAIN_LEN]);

/// The `AUDIT_WITNESS` records for `node_id` in the peer's log, after verifying its chain.
pub fn witnesses_for(peer_log: &Path, node_id: u64) -> Result<Vec<Witness>, String> {
    verify_chain(peer_log).map_err(|e| format!("peer log does not verify: {}", e))?;
    let mut files: Vec<std::path::PathBuf> = common::audit_log::rotated_segments(peer_log)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(_, p)| p)
        .collect();
    files.push(peer_log.to_path_buf());
    let mut out = Vec::new();
    for file in files {
        let mut reader =
            AuditReader::open(&file).map_err(|e| format!("{}: {}", file.display(), e))?;
        while let Some(record) = reader
            .next_record()
            .map_err(|e| format!("{}: {}", file.display(), e))?
        {
            if let Some(w) = parse(&String::from_utf8_lossy(&record.payload), node_id) {
                out.push((record.seq, w.0, w.1));
            }
        }
    }
    Ok(out)
}

/// `AUDIT_WITNESS|Issuer:<id>|Records:<n>|Head:<64 hex>` for `node_id`, or None.
fn parse(payload: &str, node_id: u64) -> Option<(u64, [u8; CHAIN_LEN])> {
    let rest = payload.strip_prefix("AUDIT_WITNESS|")?;
    let mut fields = rest.split('|');
    let issuer: u64 = fields.next()?.strip_prefix("Issuer:")?.parse().ok()?;
    let records: u64 = fields.next()?.strip_prefix("Records:")?.parse().ok()?;
    let hex = fields.next()?.strip_prefix("Head:")?;
    if issuer != node_id || fields.next().is_some() || hex.len() != 2 * CHAIN_LEN {
        return None;
    }
    let mut head = [0u8; CHAIN_LEN];
    for (byte, pair) in head.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some((records, head))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub confirmed: usize,
    pub contradicted: usize,
    pub missing: usize,
    pub pruned: usize,
}

impl Summary {
    /// 0: at least one confirmed, nothing contradicted or missing; 1: a contradiction or missing
    /// records; 2: nothing checkable.
    pub fn exit_code(&self) -> i32 {
        if self.contradicted > 0 || self.missing > 0 {
            1
        } else if self.confirmed > 0 {
            0
        } else {
            2
        }
    }
}

/// Checks and summarises; the lines are what `--verify-witnesses` prints.
pub fn verify(
    own_log: &Path,
    peer_log: &Path,
    node_id: u64,
) -> Result<(Summary, Vec<String>), String> {
    let witnesses = witnesses_for(peer_log, node_id)?;
    let claims: Vec<(u64, [u8; CHAIN_LEN])> = witnesses.iter().map(|w| (w.1, w.2)).collect();
    let verdicts = check_witnesses(own_log, &claims).map_err(|e| format!("own log: {}", e))?;
    let mut summary = Summary::default();
    let mut lines = Vec::new();
    for ((peer_seq, records, _), verdict) in witnesses.iter().zip(verdicts) {
        let what = match verdict {
            WitnessVerdict::Confirmed => {
                summary.confirmed += 1;
                "confirmed".to_string()
            }
            WitnessVerdict::Contradicted(found) => {
                summary.contradicted += 1;
                format!(
                    "CONTRADICTED: this log now has head {}",
                    crate::p2p::to_hex(&found)
                )
            }
            WitnessVerdict::Missing => {
                summary.missing += 1;
                "MISSING: this log has fewer records now".to_string()
            }
            WitnessVerdict::Pruned => {
                summary.pruned += 1;
                "unknown: in a pruned segment".to_string()
            }
        };
        lines.push(format!(
            "peer record {}: head after {} records {}",
            peer_seq, records, what
        ));
    }
    Ok((summary, lines))
}

pub fn print_report(own_log: &Path, peer_log: &Path, node_id: u64) -> i32 {
    match verify(own_log, peer_log, node_id) {
        Ok((summary, lines)) => {
            for line in &lines {
                println!("{}", line);
            }
            println!(
                "witnesses for node {}: {} confirmed, {} contradicted, {} missing, {} pruned",
                node_id, summary.confirmed, summary.contradicted, summary.missing, summary.pruned
            );
            summary.exit_code()
        }
        Err(why) => {
            eprintln!("{}", why);
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::audit_log::AuditLog;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sokol-witness-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(path: &Path, payloads: &[String]) -> (u64, [u8; CHAIN_LEN]) {
        let _ = std::fs::remove_file(path);
        let mut log = AuditLog::open(path).unwrap();
        for p in payloads {
            log.append(p.as_bytes()).unwrap();
        }
        log.sync().unwrap();
        (log.len(), log.head())
    }

    fn witness(issuer: u64, (records, head): (u64, [u8; CHAIN_LEN])) -> String {
        format!(
            "AUDIT_WITNESS|Issuer:{}|Records:{}|Head:{}",
            issuer,
            records,
            crate::p2p::to_hex(&head)
        )
    }

    /// ADR-0021 end to end on real logs: node 1's head kept by node 2 confirms the log as
    /// written, and exposes a rewrite that recomputed node 1's whole chain.
    #[test]
    fn a_peers_witness_confirms_the_log_and_exposes_a_recomputed_rewrite() {
        let d = dir("e2e");
        let (own, peer) = (d.join("node1.log"), d.join("node2.log"));
        let decisions: Vec<String> = (1..=4)
            .map(|i| format!("DYNAMIC_BLOCK_V4|IP:198.51.100.{}", i))
            .collect();
        let head = write(&own, &decisions);
        write(
            &peer,
            &[
                "NODE_START|Node:2".into(),
                witness(1, head),
                witness(3, head), // another node's witness is not about node 1
                "AUDIT_WITNESS|Issuer:1|Records:x|Head:zz".into(), // malformed: ignored
            ],
        );
        let (summary, lines) = verify(&own, &peer, 1).unwrap();
        assert_eq!(
            (summary.confirmed, summary.exit_code()),
            (1, 0),
            "{:?}",
            lines
        );

        let mut rewritten = decisions.clone();
        rewritten[1] = "DYNAMIC_BLOCK_V4|IP:203.0.113.200".into();
        write(&own, &rewritten);
        assert!(
            verify_chain(&own).is_ok(),
            "the rewrite verifies on its own"
        );
        let (summary, lines) = verify(&own, &peer, 1).unwrap();
        assert_eq!(
            (summary.contradicted, summary.exit_code()),
            (1, 1),
            "{:?}",
            lines
        );
        assert!(lines[0].contains("CONTRADICTED"));

        write(&own, &decisions[..3]);
        let (summary, _) = verify(&own, &peer, 1).unwrap();
        assert_eq!((summary.missing, summary.exit_code()), (1, 1));

        let (summary, _) = verify(&own, &peer, 9).unwrap();
        assert_eq!(
            summary.exit_code(),
            2,
            "no witness for that node: nothing checked"
        );
        std::fs::remove_dir_all(d).unwrap();
    }
}
