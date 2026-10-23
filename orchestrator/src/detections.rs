//! Block decisions by the detector that asked for them (`sokol_detections_total`).
//!
//! A detector that misfires (a bad rule, a poisoned feed) makes this node block whatever it
//! names, within the block policy. The aggregate `sokol_blocks_active` shows that only once the
//! map fills up; counted per source, a surge shows within minutes (`SokolDetectorSurge`).
//!
//! Sources are names adapters choose, so the label set is bounded: the first
//! `MAX_SOURCES` names seen get their own label, every later one counts as `other`.

use std::sync::Mutex;

/// Results, in counter order.
pub const RESULTS: [&str; 4] = ["enforced", "pending", "refused", "duplicate"];
/// Distinct source labels besides `other`.
pub const MAX_SOURCES: usize = 16;
/// Source of the node's own telemetry detections.
pub const TELEMETRY: &str = "telemetry";
/// Source of trap hits (`DROP_IMMEDIATE`).
pub const TRAP: &str = "trap";
const OTHER: &str = "other";

#[derive(Default)]
pub struct Detections {
    sources: Vec<(String, [u64; RESULTS.len()])>,
    other: [u64; RESULTS.len()],
}

pub static DETECTIONS: Mutex<Detections> = Mutex::new(Detections {
    sources: Vec::new(),
    other: [0; RESULTS.len()],
});

/// The label for a source an adapter named on the IPC socket: this node's own sources (`trap`,
/// `telemetry`) are not names an adapter can take, so such a decision counts as `other`.
pub fn adapter_label(name: &str) -> &str {
    if name == TRAP || name == TELEMETRY {
        OTHER
    } else {
        name
    }
}

/// A name usable as a label value as it is (what `signal::parse` admits for a source).
fn plain(source: &str) -> bool {
    !source.is_empty()
        && source.len() <= 64
        && source
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

impl Detections {
    /// Counts one decision; `result` is an index into `RESULTS`.
    pub fn record(&mut self, source: &str, result: usize) {
        let row = match self.sources.iter().position(|(s, _)| s == source) {
            Some(i) => self.sources.get_mut(i).map(|(_, row)| row),
            None if plain(source) && source != OTHER && self.sources.len() < MAX_SOURCES => {
                self.sources.push((source.to_string(), [0; RESULTS.len()]));
                self.sources.last_mut().map(|(_, row)| row)
            }
            None => None,
        };
        let row = row.unwrap_or(&mut self.other);
        if let Some(n) = row.get_mut(result) {
            *n += 1;
        }
    }

    /// (source, counts) for every label, `other` last.
    pub fn rows(&self) -> Vec<(String, [u64; RESULTS.len()])> {
        let mut rows = self.sources.clone();
        rows.push((OTHER.to_string(), self.other));
        rows
    }
}

/// Counts one decision in `DETECTIONS`.
pub fn record(source: &str, result: usize) {
    if let Ok(mut d) = DETECTIONS.lock() {
        d.record(source, result);
    }
}

/// A copy of `DETECTIONS` for the metrics snapshot.
pub fn rows() -> Vec<(String, [u64; RESULTS.len()])> {
    DETECTIONS.lock().map(|d| d.rows()).unwrap_or_default()
}

/// Peer claims by what this node did with them, in counter order (`sokol_mesh_claims_total`):
/// enforced here, held (known, not enforced: protected, quota, envelope, quorum, map full),
/// refused (not taken in), known (a copy already held).
pub const PEER_RESULTS: [&str; 4] = ["enforced", "held", "refused", "known"];
/// Distinct issuer labels besides `other`: issuers are pinned peers, so this bound is reached
/// only by a mesh larger than any measured (30 nodes); later issuers count as `other`.
pub const MAX_ISSUERS: usize = 64;

/// The mesh counterpart of `Detections`: a peer whose detector misfires, or a compromised peer
/// within its envelope (ADR-7), makes this node block what it claims; counted per issuer, a
/// surge shows within minutes (`SokolPeerClaimSurge`) instead of when the map fills.
#[derive(Default)]
pub struct PeerClaims {
    issuers: Vec<(u64, [u64; PEER_RESULTS.len()])>,
    other: [u64; PEER_RESULTS.len()],
}

pub static PEER_CLAIMS: Mutex<PeerClaims> = Mutex::new(PeerClaims {
    issuers: Vec::new(),
    other: [0; PEER_RESULTS.len()],
});

impl PeerClaims {
    /// Counts one claim of `issuer`; `result` is an index into `PEER_RESULTS`.
    pub fn record(&mut self, issuer: u64, result: usize) {
        let row = match self.issuers.iter().position(|(i, _)| *i == issuer) {
            Some(i) => self.issuers.get_mut(i).map(|(_, row)| row),
            None if self.issuers.len() < MAX_ISSUERS => {
                self.issuers.push((issuer, [0; PEER_RESULTS.len()]));
                self.issuers.last_mut().map(|(_, row)| row)
            }
            None => None,
        };
        let row = row.unwrap_or(&mut self.other);
        if let Some(n) = row.get_mut(result) {
            *n += 1;
        }
    }

    /// (issuer label, counts) for every issuer, `other` last.
    pub fn rows(&self) -> Vec<(String, [u64; PEER_RESULTS.len()])> {
        let mut rows: Vec<_> = self
            .issuers
            .iter()
            .map(|(issuer, row)| (issuer.to_string(), *row))
            .collect();
        rows.push((OTHER.to_string(), self.other));
        rows
    }
}

/// The `PEER_RESULTS` index of an adoption.
pub fn peer_result(adoption: &crate::block_table::Adoption) -> usize {
    use crate::block_table::Adoption;
    match adoption {
        Adoption::Enforced => 0,
        Adoption::Held(_) => 1,
        Adoption::Refused(_) => 2,
        Adoption::Known => 3,
    }
}

/// Counts one peer claim in `PEER_CLAIMS`.
pub fn record_peer(issuer: u64, adoption: &crate::block_table::Adoption) {
    if let Ok(mut c) = PEER_CLAIMS.lock() {
        c.record(issuer, peer_result(adoption));
    }
}

/// A copy of `PEER_CLAIMS` for the metrics snapshot.
pub fn peer_rows() -> Vec<(String, [u64; PEER_RESULTS.len()])> {
    PEER_CLAIMS.lock().map(|c| c.rows()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_source_counts_apart_and_the_label_set_is_bounded() {
        let mut d = Detections::default();
        d.record("suricata", 0);
        d.record("suricata", 0);
        d.record("crowdsec", 3);
        for i in 0..MAX_SOURCES + 5 {
            d.record(&format!("flood-{i}"), 1);
        }
        let rows = d.rows();
        assert_eq!(
            rows.len(),
            MAX_SOURCES + 1,
            "{} labels and other",
            MAX_SOURCES
        );
        assert_eq!(rows[0], ("suricata".to_string(), [2, 0, 0, 0]));
        assert_eq!(rows[1], ("crowdsec".to_string(), [0, 0, 0, 1]));
        // 2 known + 14 flood names got labels; the 7 after them count as other.
        assert_eq!(rows.last().unwrap(), &(OTHER.to_string(), [0, 7, 0, 0]));
        // A known source keeps its label once the table is full.
        d.record("suricata", 2);
        assert_eq!(d.rows()[0].1, [2, 0, 1, 0]);
    }

    #[test]
    fn a_name_unfit_for_a_label_counts_as_other() {
        let mut d = Detections::default();
        for bad in ["", "a b", "x\"y", "other", &"x".repeat(65)] {
            d.record(bad, 0);
        }
        assert_eq!(d.rows(), vec![(OTHER.to_string(), [5, 0, 0, 0])]);
        d.record(&"x".repeat(64), 0);
        d.record("suricata_eve.v2", 0);
        assert_eq!(
            d.rows().len(),
            3,
            "64 bytes, dots and underscores are names"
        );
    }

    #[test]
    fn only_this_nodes_own_source_names_are_relabelled() {
        assert_eq!(adapter_label(TRAP), OTHER);
        assert_eq!(adapter_label(TELEMETRY), OTHER);
        assert_eq!(adapter_label("suricata"), "suricata");
        assert_eq!(adapter_label("trap2"), "trap2");
    }

    #[test]
    fn each_issuer_counts_apart_and_the_label_set_is_bounded() {
        use crate::block_table::Adoption;
        let mut c = PeerClaims::default();
        c.record(2, peer_result(&Adoption::Enforced));
        c.record(2, peer_result(&Adoption::Held("quota")));
        c.record(3, peer_result(&Adoption::Refused("x")));
        c.record(3, peer_result(&Adoption::Known));
        for i in 0..MAX_ISSUERS as u64 + 3 {
            c.record(1_000 + i, 0);
        }
        let rows = c.rows();
        assert_eq!(
            rows.len(),
            MAX_ISSUERS + 1,
            "{} labels and other",
            MAX_ISSUERS
        );
        assert_eq!(rows[0], ("2".to_string(), [1, 1, 0, 0]));
        assert_eq!(rows[1], ("3".to_string(), [0, 0, 1, 1]));
        // 2 known + 62 new issuers got labels; the 5 after them count as other.
        assert_eq!(rows.last().unwrap(), &(OTHER.to_string(), [5, 0, 0, 0]));
        c.record(2, 0);
        assert_eq!(
            c.rows()[0].1,
            [2, 1, 0, 0],
            "a known issuer keeps its label"
        );
    }
}
