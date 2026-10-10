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
}
