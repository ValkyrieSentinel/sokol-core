//! Append-only audit log with a BLAKE3 hash chain.
//!
//! Record layout (little-endian):
//!
//! ```text
//! magic "SAL2" | len u32 | seq u64 | timestamp_ms u64 | payload[len] | chain [32]
//! chain = BLAKE3(previous chain || magic..payload)      (previous chain of record 0 = zeros)
//! ```
//!
//! On open the whole file is replayed: an incomplete record at the end (torn write after a
//! crash) is truncated away; a complete record whose chain does not match is reported as
//! corruption and the log is not opened, so evidence is never silently discarded.
//!
//! The chain detects accidental corruption and edits that do not rewrite every later record.
//! Someone with write access can recompute the whole chain; to make that detectable, export
//! `head()` somewhere they cannot write.
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC: [u8; 4] = *b"SAL2";
pub const HEADER_LEN: usize = 4 + 4 + 8 + 8;
pub const CHAIN_LEN: usize = 32;
pub const MAX_PAYLOAD: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub payload: Vec<u8>,
    pub chain: [u8; CHAIN_LEN],
}

#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    /// A complete record at `offset` does not continue the chain (or has a bad header).
    Corrupt {
        offset: u64,
        reason: &'static str,
    },
    PayloadTooLarge(usize),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "audit log I/O error: {}", e),
            Self::Corrupt { offset, reason } => {
                write!(f, "audit log corrupt at byte {}: {}", offset, reason)
            }
            Self::PayloadTooLarge(n) => {
                write!(
                    f,
                    "audit record of {} bytes exceeds {} bytes",
                    n, MAX_PAYLOAD
                )
            }
        }
    }
}

impl std::error::Error for AuditError {}

impl From<io::Error> for AuditError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn encode_header(len: u32, seq: u64, timestamp_ms: u64) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&MAGIC);
    h[4..8].copy_from_slice(&len.to_le_bytes());
    h[8..16].copy_from_slice(&seq.to_le_bytes());
    h[16..24].copy_from_slice(&timestamp_ms.to_le_bytes());
    h
}

fn next_chain(prev: &[u8; CHAIN_LEN], header: &[u8], payload: &[u8]) -> [u8; CHAIN_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev);
    hasher.update(header);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Incremental, verifying reader. Stops (without error) at an incomplete trailing record, so
/// it can be polled while a writer appends.
pub struct AuditReader<R> {
    inner: R,
    offset: u64,
    next_seq: u64,
    chain: [u8; CHAIN_LEN],
}

impl AuditReader<BufReader<File>> {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self::new(BufReader::new(File::open(path)?)))
    }
}

impl<R: Read + Seek> AuditReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            offset: 0,
            next_seq: 0,
            chain: [0u8; CHAIN_LEN],
        }
    }

    /// Byte offset just past the last verified record.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn head(&self) -> [u8; CHAIN_LEN] {
        self.chain
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Returns the next verified record, `Ok(None)` if the data ends (possibly mid-record).
    pub fn next_record(&mut self) -> Result<Option<Record>, AuditError> {
        self.inner.seek(SeekFrom::Start(self.offset))?;

        let mut header = [0u8; HEADER_LEN];
        if !read_full(&mut self.inner, &mut header)? {
            return Ok(None);
        }
        let corrupt = |reason| AuditError::Corrupt {
            offset: self.offset,
            reason,
        };
        if header[0..4] != MAGIC {
            return Err(corrupt("bad record magic (not a sokol audit log v2?)"));
        }
        let len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let seq = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let timestamp_ms = u64::from_le_bytes(header[16..24].try_into().unwrap());
        if len > MAX_PAYLOAD {
            return Err(corrupt("record length exceeds maximum"));
        }

        let mut body = vec![0u8; len + CHAIN_LEN];
        if !read_full(&mut self.inner, &mut body)? {
            return Ok(None);
        }
        let chain: [u8; CHAIN_LEN] = body[len..].try_into().unwrap();
        body.truncate(len);

        if seq != self.next_seq {
            return Err(corrupt("sequence number out of order"));
        }
        if next_chain(&self.chain, &header, &body) != chain {
            return Err(corrupt("hash chain mismatch"));
        }

        self.offset += (HEADER_LEN + len + CHAIN_LEN) as u64;
        self.next_seq += 1;
        self.chain = chain;
        Ok(Some(Record {
            seq,
            timestamp_ms,
            payload: body,
            chain,
        }))
    }
}

/// `Ok(false)` if EOF is reached before `buf` is full.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => return Ok(false),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

pub struct AuditLog {
    file: File,
    path: PathBuf,
    next_seq: u64,
    chain: [u8; CHAIN_LEN],
    unsynced: usize,
}

impl AuditLog {
    /// Opens or creates the log, verifying every existing record.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;

        let mut reader = AuditReader::new(BufReader::new(file.try_clone()?));
        while reader.next_record()?.is_some() {}

        let valid_len = reader.offset();
        if file.metadata()?.len() > valid_len {
            // Torn trailing write from a crash: drop the partial record.
            file.set_len(valid_len)?;
            file.sync_all()?;
        }

        Ok(Self {
            file,
            path: path.to_path_buf(),
            next_seq: reader.next_seq(),
            chain: reader.head(),
            unsynced: 0,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Chain value after the last record.
    pub fn head(&self) -> [u8; CHAIN_LEN] {
        self.chain
    }

    pub fn len(&self) -> u64 {
        self.next_seq
    }

    pub fn is_empty(&self) -> bool {
        self.next_seq == 0
    }

    /// Appends one record (written, not yet fsynced; see [`sync`](Self::sync)).
    pub fn append(&mut self, payload: &[u8]) -> Result<u64, AuditError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(AuditError::PayloadTooLarge(payload.len()));
        }
        let seq = self.next_seq;
        let header = encode_header(payload.len() as u32, seq, now_ms());
        let chain = next_chain(&self.chain, &header, payload);

        let mut record = Vec::with_capacity(HEADER_LEN + payload.len() + CHAIN_LEN);
        record.extend_from_slice(&header);
        record.extend_from_slice(payload);
        record.extend_from_slice(&chain);
        self.file.write_all(&record)?;

        self.next_seq += 1;
        self.chain = chain;
        self.unsynced += 1;
        Ok(seq)
    }

    pub fn unsynced(&self) -> usize {
        self.unsynced
    }

    pub fn sync(&mut self) -> Result<(), AuditError> {
        if self.unsynced > 0 {
            self.file.sync_data()?;
            self.unsynced = 0;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sokol-audit-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("audit.log")
    }

    fn read_all(path: &Path) -> Result<Vec<Record>, AuditError> {
        let mut reader = AuditReader::open(path)?;
        let mut out = Vec::new();
        while let Some(r) = reader.next_record()? {
            out.push(r);
        }
        Ok(out)
    }

    #[test]
    fn records_round_trip_and_survive_reopen() {
        let path = temp_path("roundtrip");
        {
            let mut log = AuditLog::open(&path).unwrap();
            assert_eq!(log.append(b"first").unwrap(), 0);
            assert_eq!(log.append(b"second").unwrap(), 1);
            log.sync().unwrap();
        }
        let mut log = AuditLog::open(&path).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log.append(b"third").unwrap(), 2);
        log.sync().unwrap();

        let records = read_all(&path).unwrap();
        let payloads: Vec<&[u8]> = records.iter().map(|r| r.payload.as_slice()).collect();
        assert_eq!(payloads, vec![&b"first"[..], b"second", b"third"]);
        assert_eq!(records.last().unwrap().chain, log.head());
    }

    #[test]
    fn short_records_are_compact() {
        let path = temp_path("compact");
        let mut log = AuditLog::open(&path).unwrap();
        log.append(&[b'x'; 30]).unwrap();
        log.sync().unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            (HEADER_LEN + 30 + CHAIN_LEN) as u64
        );
    }

    #[test]
    fn torn_tail_is_truncated_on_open() {
        let path = temp_path("torn");
        {
            let mut log = AuditLog::open(&path).unwrap();
            log.append(b"kept").unwrap();
            log.append(b"torn away").unwrap();
            log.sync().unwrap();
        }
        let full = std::fs::metadata(&path).unwrap().len();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(full - 5).unwrap();

        let mut log = AuditLog::open(&path).unwrap();
        assert_eq!(log.len(), 1);
        log.append(b"after crash").unwrap();
        log.sync().unwrap();
        let payloads: Vec<Vec<u8>> = read_all(&path)
            .unwrap()
            .into_iter()
            .map(|r| r.payload)
            .collect();
        assert_eq!(payloads, vec![b"kept".to_vec(), b"after crash".to_vec()]);
    }

    #[test]
    fn edited_record_breaks_the_chain_and_refuses_to_open() {
        let path = temp_path("edited");
        {
            let mut log = AuditLog::open(&path).unwrap();
            log.append(b"BLOCK 10.0.0.1").unwrap();
            log.append(b"BLOCK 10.0.0.2").unwrap();
            log.sync().unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        let pos = HEADER_LEN + b"BLOCK 10.0.0.".len();
        bytes[pos] = b'9';
        std::fs::write(&path, &bytes).unwrap();

        assert!(matches!(
            AuditLog::open(&path),
            Err(AuditError::Corrupt {
                offset: 0,
                reason: "hash chain mismatch"
            })
        ));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "corrupt log must not be modified"
        );
    }

    #[test]
    fn foreign_file_is_rejected() {
        let path = temp_path("foreign");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut old = vec![0u8; 4096];
        old[0..4].copy_from_slice(&0x534E544Cu32.to_le_bytes());
        std::fs::write(&path, &old).unwrap();
        assert!(matches!(
            AuditLog::open(&path),
            Err(AuditError::Corrupt { offset: 0, .. })
        ));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let path = temp_path("oversized");
        let mut log = AuditLog::open(&path).unwrap();
        assert!(matches!(
            log.append(&vec![0u8; MAX_PAYLOAD + 1]),
            Err(AuditError::PayloadTooLarge(_))
        ));
        assert!(log.is_empty());
    }

    #[test]
    fn reader_follows_a_growing_file() {
        let path = temp_path("follow");
        let mut log = AuditLog::open(&path).unwrap();
        log.append(b"one").unwrap();
        log.sync().unwrap();

        let mut reader = AuditReader::open(&path).unwrap();
        assert_eq!(reader.next_record().unwrap().unwrap().payload, b"one");
        assert!(reader.next_record().unwrap().is_none());

        log.append(b"two").unwrap();
        log.sync().unwrap();
        assert_eq!(reader.next_record().unwrap().unwrap().payload, b"two");
    }
}
