//! Bounded decoding of the state the node's own writer can produce.
//! The reader validates JSON token sizes before serde allocates strings; sequences refuse
//! before storing more than their runtime limits. One extra, bounded record may be decoded.
use crate::block_table::{self, Claim, ClaimId, Persisted, SavedReasons};
use serde::de::{DeserializeOwned, Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::io::{self, BufReader, Read};

pub const MAX_TARGET_BYTES: usize = 43; // longest canonical IPv6 prefix, including /128
pub const MAX_ID_BYTES: usize = 64;
pub const MAX_EVENT_BYTES: usize = 32;
pub const MAX_JSON_STRING_BYTES: usize = 6 * block_table::MAX_REASON_BYTES;
pub const MAX_JSON_ATOM_BYTES: usize = 32; // u64 uses at most 20 decimal bytes
pub const READ_BUFFER_BYTES: usize = 65_536; // 64 KiB prefetch, independent of admission
/// Input policy ceiling, derived for the current maximal compact writer profile:
/// known*(6*reason+256+3*128) + events*80 + support*(128+8*80) + 1024.
/// Its named runtime counts/record sizes are checked against real serialization below;
/// increasing them beyond this ceiling requires a new input policy, not a silent larger cap.
pub const MAX_STATE_BYTES: usize = 1_028_654_080;

struct JsonReader<R> {
    inner: R,
    budget: usize,
    string_bytes: usize,
    atom_bytes: usize,
    in_string: bool,
    escaped: bool,
}

impl<R: Read> Read for JsonReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(out)?;
        for byte in out.iter().take(count) {
            self.budget = self
                .budget
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("state file exceeds byte limit"))?;
            if self.in_string {
                if *byte == b'"' && !self.escaped {
                    self.in_string = false;
                } else {
                    self.string_bytes += 1;
                    if self.string_bytes > MAX_JSON_STRING_BYTES {
                        return Err(io::Error::other("state JSON string exceeds wire limit"));
                    }
                    self.escaped = *byte == b'\\' && !self.escaped;
                }
            } else if *byte == b'"' {
                self.in_string = true;
                self.escaped = false;
                self.string_bytes = 0;
                self.atom_bytes = 0;
            } else if byte.is_ascii_whitespace() || b"{}[]:,".contains(byte) {
                self.atom_bytes = 0;
            } else {
                self.atom_bytes += 1;
                if self.atom_bytes > MAX_JSON_ATOM_BYTES {
                    return Err(io::Error::other("state JSON atom exceeds wire limit"));
                }
            }
        }
        Ok(count)
    }
}

fn entries<'de, D, T, F>(deserializer: D, limit: usize, valid: F) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
    F: Fn(&T) -> bool,
{
    struct Bounded<T, F>(usize, F, std::marker::PhantomData<T>);
    impl<'de, T: DeserializeOwned, F: Fn(&T) -> bool> Visitor<'de> for Bounded<T, F> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("bounded state sequence")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Vec<T>, A::Error> {
            let mut values = Vec::new();
            while let Some(value) = input.next_element::<T>()? {
                if values.len() >= self.0 || !(self.1)(&value) {
                    return Err(A::Error::custom("state sequence or record exceeds limit"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded(limit, valid, std::marker::PhantomData))
}

fn claims<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Claim>, D::Error> {
    entries(d, block_table::MAX_KNOWN_CLAIMS, |v: &Claim| {
        v.target.len() <= MAX_TARGET_BYTES && v.reason.len() <= block_table::MAX_REASON_BYTES
    })
}
fn ids<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(ClaimId, Option<u64>)>, D::Error> {
    entries(
        d,
        block_table::MAX_KNOWN_CLAIMS,
        |v: &(String, Option<u64>)| v.0.len() <= MAX_ID_BYTES,
    )
}
type SavedEnd = (ClaimId, u64, Option<u64>);
fn ends<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<SavedEnd>, D::Error> {
    entries(
        d,
        block_table::MAX_KNOWN_CLAIMS,
        |v: &(String, u64, Option<u64>)| v.0.len() <= MAX_ID_BYTES,
    )
}
fn events<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(String, u64)>, D::Error> {
    entries(d, block_table::MAX_EVENTS, |v: &(String, u64)| {
        v.0.len() <= MAX_EVENT_BYTES
    })
}
fn reasons<'de, D: Deserializer<'de>>(d: D) -> Result<SavedReasons, D::Error> {
    entries(
        d,
        block_table::MAX_SUPPORT_PER_TARGET,
        |v: &(Option<String>, Option<u64>)| v.0.as_ref().is_none_or(|s| s.len() <= MAX_EVENT_BYTES),
    )
}
#[derive(Deserialize)]
struct Support(String, #[serde(deserialize_with = "reasons")] SavedReasons);
fn support<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Support>, D::Error> {
    entries(d, block_table::MAX_SUPPORT_TARGETS, |v: &Support| {
        v.0.len() <= MAX_TARGET_BYTES
    })
}
fn schema<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    let schema = u32::deserialize(d)?;
    if schema != block_table::STATE_SCHEMA {
        return Err(D::Error::custom(format!(
            "state schema {schema}, this build reads {} (no migration)",
            block_table::STATE_SCHEMA
        )));
    }
    Ok(schema)
}
fn first_schema() -> u32 {
    1 // an unversioned file has layout 1, even if a future writer changes its schema
}
#[derive(Deserialize)]
struct State {
    #[serde(default = "first_schema", deserialize_with = "schema")]
    schema: u32,
    #[serde(deserialize_with = "claims")]
    claims: Vec<Claim>,
    #[serde(deserialize_with = "ids")]
    operator_lifts: Vec<(ClaimId, Option<u64>)>,
    #[serde(deserialize_with = "ids")]
    retracted: Vec<(ClaimId, Option<u64>)>,
    #[serde(default, deserialize_with = "ends")]
    peer_ends: Vec<SavedEnd>,
    #[serde(default, deserialize_with = "events")]
    events: Vec<(String, u64)>,
    #[serde(default, deserialize_with = "support")]
    support: Vec<Support>,
    #[serde(default)]
    saved_ms: Option<u64>,
}

pub fn parse<R: Read>(input: R) -> Result<Persisted, String> {
    let state: State = serde_json::from_reader(JsonReader {
        inner: BufReader::with_capacity(READ_BUFFER_BYTES, input),
        budget: MAX_STATE_BYTES,
        string_bytes: 0,
        atom_bytes: 0,
        in_string: false,
        escaped: false,
    })
    .map_err(|e| e.to_string())?;
    Ok(Persisted {
        schema: state.schema,
        claims: state.claims,
        operator_lifts: state.operator_lifts,
        retracted: state.retracted,
        peer_ends: state.peer_ends,
        events: state.events,
        support: state.support.into_iter().map(|v| (v.0, v.1)).collect(),
        saved_ms: state.saved_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(bytes: &[u8], budget: usize) -> JsonReader<&[u8]> {
        JsonReader {
            inner: bytes,
            budget,
            string_bytes: 0,
            atom_bytes: 0,
            in_string: false,
            escaped: false,
        }
    }

    #[test]
    fn a_byte_budget_counts_whitespace_and_refuses_a_growing_stream() {
        let mut read = reader(b"{} ", 3);
        let mut bytes = Vec::new();
        assert_eq!(read.read_to_end(&mut bytes).unwrap(), 3);
        assert_eq!(bytes, b"{} ");
        assert!(reader(b"{}  ", 3).read_to_end(&mut Vec::new()).is_err());
        assert_eq!(reader(b"", 0).read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn wire_string_and_atom_bounds_apply_before_serde_allocates() {
        let string = |n| format!("\"{}\"", "x".repeat(n));
        for (n, ok) in [
            (MAX_JSON_STRING_BYTES, true),
            (MAX_JSON_STRING_BYTES + 1, false),
        ] {
            let bytes = string(n);
            assert_eq!(
                reader(bytes.as_bytes(), usize::MAX)
                    .read_to_end(&mut Vec::new())
                    .is_ok(),
                ok
            );
        }
        for (n, ok) in [
            (MAX_JSON_ATOM_BYTES, true),
            (MAX_JSON_ATOM_BYTES + 1, false),
        ] {
            assert_eq!(
                reader(&vec![b'1'; n], usize::MAX)
                    .read_to_end(&mut Vec::new())
                    .is_ok(),
                ok
            );
        }
        let escaped = br#"{"k":"a\\\"b\\c","n":18446744073709551615}"#;
        let mut bytes = Vec::new();
        reader(escaped, escaped.len())
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, escaped);
        // An escaped quote must not restart the wire budget. Spaces after it keep a
        // broken scanner from accidentally refusing this vector as an oversized atom.
        for (n, ok) in [
            (MAX_JSON_STRING_BYTES, true),
            (MAX_JSON_STRING_BYTES + 1, false),
        ] {
            let prefix = (n - 2) / 2;
            let json = format!(
                "\"{}\\\"{}\"",
                " ".repeat(prefix),
                " ".repeat(n - 2 - prefix)
            );
            assert!(serde_json::from_str::<String>(&json).is_ok());
            assert_eq!(
                reader(json.as_bytes(), usize::MAX)
                    .read_to_end(&mut Vec::new())
                    .is_ok(),
                ok,
                "escaped quote split the {n}-byte string budget"
            );
        }
    }

    #[test]
    fn sequences_refuse_cardinality_and_invalid_records_without_eviction() {
        for (json, expected) in [
            ("[]", Some(vec![])),
            ("[1,2]", Some(vec![1, 2])),
            ("[1,2,3]", None),
            ("[1,9]", None),
        ] {
            let mut d = serde_json::Deserializer::from_str(json);
            let result = entries(&mut d, 2, |v: &u64| *v < 3);
            assert_eq!(result.ok(), expected);
        }
    }

    #[test]
    fn maximal_writer_records_roundtrip_with_escaped_reasons_and_all_tables() {
        let target = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128";
        assert_eq!(target.len(), MAX_TARGET_BYTES);
        let claim = Claim {
            issuer: u64::MAX,
            kind: block_table::ClaimKind::Detector,
            target: target.into(),
            issued_ms: u64::MAX,
            expires_ms: Some(u64::MAX),
            reason: "\0".repeat(block_table::MAX_REASON_BYTES),
        };
        assert!(
            serde_json::to_vec(&claim).unwrap().len() <= 6 * block_table::MAX_REASON_BYTES + 256
        );
        let id = "f".repeat(MAX_ID_BYTES);
        let event = "f".repeat(MAX_EVENT_BYTES);
        let pair = (id.clone(), Some(u64::MAX));
        let end = (id, u64::MAX, Some(u64::MAX));
        assert!(serde_json::to_vec(&pair).unwrap().len() <= 128);
        assert!(serde_json::to_vec(&end).unwrap().len() <= 128);
        let reason = (Some(event.clone()), Some(u64::MAX));
        assert!(serde_json::to_vec(&reason).unwrap().len() <= 80);
        let saved = Persisted {
            claims: vec![claim],
            operator_lifts: vec![pair.clone()],
            retracted: vec![pair],
            peer_ends: vec![end],
            events: vec![(event, u64::MAX)],
            support: vec![(
                target.into(),
                vec![reason; block_table::MAX_SUPPORT_PER_TARGET],
            )],
            saved_ms: Some(u64::MAX),
            ..Persisted::default()
        };
        assert_eq!(
            parse(serde_json::to_vec(&saved).unwrap().as_slice()).unwrap(),
            saved
        );
        // Compute the complete maximal writer size from its serialized record bytes,
        // without allocating a gigabyte-sized test snapshot. A sequence with one record
        // gains exactly serialized_record.len()+1 bytes for each additional element.
        let mut full_bytes = serde_json::to_vec(&saved).unwrap().len();
        let tables = [
            (
                block_table::MAX_KNOWN_CLAIMS,
                serde_json::to_vec(&saved.claims[0]).unwrap().len(),
            ),
            (
                block_table::MAX_KNOWN_CLAIMS,
                serde_json::to_vec(&saved.operator_lifts[0]).unwrap().len(),
            ),
            (
                block_table::MAX_KNOWN_CLAIMS,
                serde_json::to_vec(&saved.retracted[0]).unwrap().len(),
            ),
            (
                block_table::MAX_KNOWN_CLAIMS,
                serde_json::to_vec(&saved.peer_ends[0]).unwrap().len(),
            ),
            (
                block_table::MAX_EVENTS,
                serde_json::to_vec(&saved.events[0]).unwrap().len(),
            ),
            (
                block_table::MAX_SUPPORT_TARGETS,
                serde_json::to_vec(&saved.support[0]).unwrap().len(),
            ),
        ];
        for (count, bytes) in tables {
            full_bytes += (count - 1) * (bytes + 1);
        }
        assert!(
            full_bytes <= MAX_STATE_BYTES,
            "writer profile needs {full_bytes} bytes"
        );
    }

    #[test]
    fn oversized_state_fields_are_refused_in_each_table() {
        let mut saved = Persisted::default();
        saved.claims.push(Claim {
            issuer: 1,
            kind: block_table::ClaimKind::Detector,
            target: "x".repeat(MAX_TARGET_BYTES + 1),
            issued_ms: 0,
            expires_ms: None,
            reason: String::new(),
        });
        assert!(parse(serde_json::to_vec(&saved).unwrap().as_slice()).is_err());
        for field in [
            "operator_lifts",
            "retracted",
            "peer_ends",
            "events",
            "support",
        ] {
            let mut json = serde_json::to_value(Persisted::default()).unwrap();
            let tuple = match field {
                "peer_ends" => serde_json::json!(["x".repeat(MAX_ID_BYTES + 1), 0, null]),
                "events" => serde_json::json!(["x".repeat(MAX_EVENT_BYTES + 1), 0]),
                "support" => serde_json::json!(["x".repeat(MAX_TARGET_BYTES + 1), []]),
                _ => serde_json::json!(["x".repeat(MAX_ID_BYTES + 1), null]),
            };
            json[field] = serde_json::json!([tuple]);
            assert!(
                parse(serde_json::to_vec(&json).unwrap().as_slice()).is_err(),
                "{field}"
            );
        }
        for reason in [
            serde_json::json!(["x".repeat(MAX_EVENT_BYTES + 1), null]),
            serde_json::json!([null, null]),
        ] {
            let count = if reason[0].is_null() {
                block_table::MAX_SUPPORT_PER_TARGET + 1
            } else {
                1
            };
            let json = serde_json::json!({"claims":[],"operator_lifts":[],"retracted":[],"support":[["198.51.100.1",vec![reason;count]]]});
            assert!(parse(serde_json::to_vec(&json).unwrap().as_slice()).is_err());
        }
    }
}
