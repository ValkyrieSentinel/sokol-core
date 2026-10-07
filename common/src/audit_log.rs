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
//! Rotation (optional): when the active file reaches `max_bytes` it is renamed to
//! `<path>.<first seq, 20 digits>` and a new file starts with a segment header
//! (`"SALS" | start_seq u64 | previous chain [32]`), so the chain continues across files and
//! [`verify_chain`] can detect a missing, reordered or edited segment. Only the newest `keep`
//! rotated segments are kept.
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
pub const SEGMENT_MAGIC: [u8; 4] = *b"SALS";
pub const SEGMENT_HEADER_LEN: usize = 4 + 8 + CHAIN_LEN;

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
    /// Another writer holds the log (`<path>.lock`).
    Locked(PathBuf),
    /// A failed write could not be undone; the log must be reopened (which drops the torn tail).
    Poisoned,
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "audit log I/O error: {}", e),
            Self::Corrupt { offset, reason } => {
                write!(f, "audit log corrupt at byte {}: {}", offset, reason)
            }
            Self::Locked(p) => write!(f, "audit log is in use by another writer ({})", p.display()),
            Self::Poisoned => write!(f, "audit log unusable after a failed write; reopen it"),
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
    /// `(start_seq, previous chain)` from the segment header, if the file has one.
    segment_start: Option<(u64, [u8; CHAIN_LEN])>,
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
            segment_start: None,
        }
    }

    pub fn segment_start(&self) -> Option<(u64, [u8; CHAIN_LEN])> {
        self.segment_start
    }

    /// Consumes the segment header at the start of a rotated-in file. `Ok(false)` if the
    /// file is too short to tell yet.
    fn read_segment_header(&mut self) -> Result<bool, AuditError> {
        self.inner.seek(SeekFrom::Start(0))?;
        let mut magic = [0u8; 4];
        if !read_full(&mut self.inner, &mut magic)? {
            return Ok(false);
        }
        if magic != SEGMENT_MAGIC {
            return Ok(true);
        }
        let mut rest = [0u8; SEGMENT_HEADER_LEN - 4];
        if !read_full(&mut self.inner, &mut rest)? {
            return Ok(false);
        }
        let (Some(start), Some(prev)) = (chunk::<8>(&rest, 0), chunk::<CHAIN_LEN>(&rest, 8)) else {
            return Err(AuditError::Corrupt {
                offset: 0,
                reason: "short segment header",
            });
        };
        let start = u64::from_le_bytes(start);
        self.segment_start = Some((start, prev));
        self.next_seq = start;
        self.chain = prev;
        self.offset = SEGMENT_HEADER_LEN as u64;
        Ok(true)
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
        if self.offset == 0 && !self.read_segment_header()? {
            return Ok(None);
        }
        self.inner.seek(SeekFrom::Start(self.offset))?;

        let mut header = [0u8; HEADER_LEN];
        if !read_full(&mut self.inner, &mut header)? {
            return Ok(None);
        }
        let corrupt = |reason| AuditError::Corrupt {
            offset: self.offset,
            reason,
        };
        let (Some(magic), Some(len), Some(seq), Some(timestamp_ms)) = (
            chunk::<4>(&header, 0),
            chunk::<4>(&header, 4),
            chunk::<8>(&header, 8),
            chunk::<8>(&header, 16),
        ) else {
            return Err(corrupt("short record header"));
        };
        if magic != MAGIC {
            return Err(corrupt("bad record magic (not a sokol audit log v2?)"));
        }
        let len = u32::from_le_bytes(len) as usize;
        let seq = u64::from_le_bytes(seq);
        let timestamp_ms = u64::from_le_bytes(timestamp_ms);
        if len > MAX_PAYLOAD {
            return Err(corrupt("record length exceeds maximum"));
        }

        let mut body = vec![0u8; len + CHAIN_LEN];
        if !read_full(&mut self.inner, &mut body)? {
            return Ok(None);
        }
        let Some(chain) = chunk::<CHAIN_LEN>(&body, len) else {
            return Err(corrupt("short record"));
        };
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

/// The `N` bytes of `b` at `at`, if there are that many.
fn chunk<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// `Ok(false)` if EOF is reached before `buf` is full.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(buf.get_mut(filled..).unwrap_or_default()) {
            Ok(0) => return Ok(false),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rotation {
    pub max_bytes: u64,
    /// Rotated segments to keep; older ones are deleted.
    pub keep: usize,
}

pub struct AuditLog {
    file: File,
    path: PathBuf,
    next_seq: u64,
    chain: [u8; CHAIN_LEN],
    unsynced: usize,
    rotation: Option<Rotation>,
    size: u64,
    segment_start_seq: u64,
    /// Exclusive lock on `<path>.lock`, held while the log is open: two writers on one file
    /// would interleave sequence numbers and break the chain.
    _lock: File,
    poisoned: bool,
}

fn rotated_path(path: &Path, start_seq: u64) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{:020}", start_seq));
    PathBuf::from(name)
}

/// Rotated segments of `path`, oldest first.
pub fn rotated_segments(path: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let base = match path.file_name() {
        Some(b) => format!("{}.", b.to_string_lossy()),
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(suffix) = name.strip_prefix(&base) {
            // Twenty digits can still exceed u64 (a stray file must not stop the node).
            if suffix.len() == 20 && suffix.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(start) = suffix.parse() {
                    out.push((start, entry.path()));
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

fn segment_header(start_seq: u64, prev: &[u8; CHAIN_LEN]) -> [u8; SEGMENT_HEADER_LEN] {
    let mut h = [0u8; SEGMENT_HEADER_LEN];
    h[0..4].copy_from_slice(&SEGMENT_MAGIC);
    h[4..12].copy_from_slice(&start_seq.to_le_bytes());
    h[12..].copy_from_slice(prev);
    h
}

fn sync_dir(path: &Path) {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

impl AuditLog {
    /// Opens or creates the log, verifying every existing record.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        Self::open_with(path, None)
    }

    /// Like [`open`](Self::open), rotating the active file at `rotation.max_bytes`.
    pub fn open_with(path: &Path, rotation: Option<Rotation>) -> Result<Self, AuditError> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let lock_path = {
            let mut name = path.as_os_str().to_owned();
            name.push(".lock");
            PathBuf::from(name)
        };
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(AuditError::Locked(lock_path)),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
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

        let mut log = Self {
            file,
            path: path.to_path_buf(),
            next_seq: reader.next_seq(),
            chain: reader.head(),
            unsynced: 0,
            rotation,
            size: valid_len,
            segment_start_seq: reader.segment_start().map(|(s, _)| s).unwrap_or(0),
            _lock: lock,
            poisoned: false,
        };

        // A crash between renaming the old segment and writing the new header leaves an empty
        // active file next to rotated segments: continue the chain from the newest one.
        if valid_len == 0 {
            if let Some((_, last)) = rotated_segments(path)?.pop() {
                let mut prev = AuditReader::open(&last)?;
                while prev.next_record()?.is_some() {}
                log.start_segment(prev.next_seq(), prev.head())?;
            }
        }
        Ok(log)
    }

    fn start_segment(&mut self, start_seq: u64, prev: [u8; CHAIN_LEN]) -> Result<(), AuditError> {
        self.file.write_all(&segment_header(start_seq, &prev))?;
        self.file.sync_all()?;
        self.next_seq = start_seq;
        self.chain = prev;
        self.size = SEGMENT_HEADER_LEN as u64;
        self.segment_start_seq = start_seq;
        Ok(())
    }

    fn rotate(&mut self, keep: usize) -> Result<(), AuditError> {
        self.sync()?;
        let rotated = rotated_path(&self.path, self.segment_start_seq);
        // rename(2) replaces an existing file silently. A segment of that name can only exist if
        // an earlier rotation got past its rename and failed later; replacing it would destroy
        // evidence. Refuse, and refuse every later write through this handle.
        if rotated.exists() {
            self.poisoned = true;
            return Err(AuditError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists; not replacing an audit segment",
                    rotated.display()
                ),
            )));
        }
        std::fs::rename(&self.path, &rotated)?;
        self.file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .open(&self.path)?;
        let (seq, chain) = (self.next_seq, self.chain);
        self.start_segment(seq, chain)?;
        sync_dir(&self.path);

        let segments = rotated_segments(&self.path)?;
        let excess = segments.len().saturating_sub(keep);
        for (_, old) in segments.into_iter().take(excess) {
            std::fs::remove_file(old)?;
        }
        Ok(())
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
        if self.poisoned {
            return Err(AuditError::Poisoned);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(AuditError::PayloadTooLarge(payload.len()));
        }
        if let Some(rot) = self.rotation {
            let has_records = self.next_seq > self.segment_start_seq;
            if rot.max_bytes > 0 && self.size >= rot.max_bytes && has_records {
                self.rotate(rot.keep)?;
            }
        }
        let seq = self.next_seq;
        let header = encode_header(payload.len() as u32, seq, now_ms());
        let chain = next_chain(&self.chain, &header, payload);

        let mut record = Vec::with_capacity(HEADER_LEN + payload.len() + CHAIN_LEN);
        record.extend_from_slice(&header);
        record.extend_from_slice(payload);
        record.extend_from_slice(&chain);
        if let Err(e) = self.file.write_all(&record) {
            // A partial record would sit between this record and the next one and break the
            // chain for every later record: cut the file back to the last whole record.
            if self.file.set_len(self.size).is_err() {
                self.poisoned = true;
            }
            return Err(e.into());
        }

        self.size += record.len() as u64;
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

#[derive(Debug, PartialEq, Eq)]
pub struct ChainSummary {
    pub segments: usize,
    /// Sequence number of the oldest record still on disk (older segments may be pruned).
    pub first_seq: u64,
    pub next_seq: u64,
    pub head: [u8; CHAIN_LEN],
}

/// A failed read is not evidence that the chain is corrupt. The classification is
/// structural, never inferred from the rendered diagnostic.
#[derive(Debug)]
pub enum ChainVerifyError {
    Broken { path: PathBuf, reason: String },
    Unverified { path: PathBuf, reason: String },
}

impl ChainVerifyError {
    fn unverified(path: &Path, error: impl std::fmt::Display) -> Self {
        Self::Unverified {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
    }

    fn record(path: &Path, error: AuditError) -> Self {
        match error {
            AuditError::Corrupt { .. } => Self::Broken {
                path: path.to_path_buf(),
                reason: error.to_string(),
            },
            _ => Self::unverified(path, error),
        }
    }
}

impl std::fmt::Display for ChainVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Broken { path, reason } | Self::Unverified { path, reason } => {
                write!(f, "{}: {}", path.display(), reason)
            }
        }
    }
}

impl std::error::Error for ChainVerifyError {}

/// Verifies every retained segment and the active file as one chain.
pub fn verify_chain(path: &Path) -> Result<ChainSummary, ChainVerifyError> {
    let mut files: Vec<PathBuf> = rotated_segments(path)
        .map_err(|e| ChainVerifyError::unverified(path, e))?
        .into_iter()
        .map(|(_, p)| p)
        .collect();
    let rotated = files.len();
    files.push(path.to_path_buf());

    let mut expected: Option<(u64, [u8; CHAIN_LEN])> = None;
    let mut first_seq = None;
    for (i, file) in files.iter().enumerate() {
        let mut reader =
            AuditReader::open(file).map_err(|e| ChainVerifyError::unverified(file, e))?;
        while reader
            .next_record()
            .map_err(|e| ChainVerifyError::record(file, e))?
            .is_some()
        {}
        let start = reader.segment_start().unwrap_or((0, [0u8; CHAIN_LEN]));
        if let Some(exp) = expected {
            if start != exp {
                return Err(ChainVerifyError::Broken {
                    path: file.to_path_buf(),
                    reason: format!("does not continue the previous segment (starts at seq {}, expected {}); a segment is missing, reordered or edited", start.0, exp.0),
                });
            }
        }
        let len = std::fs::metadata(file)
            .map_err(|e| ChainVerifyError::unverified(file, e))?
            .len();
        if len < reader.offset() {
            return Err(ChainVerifyError::unverified(
                file,
                "file shortened during verification",
            ));
        }
        if i < rotated && len != reader.offset() {
            return Err(ChainVerifyError::Broken {
                path: file.to_path_buf(),
                reason: format!(
                    "rotated segment has {} trailing bytes",
                    len - reader.offset()
                ),
            });
        }
        first_seq.get_or_insert(start.0);
        expected = Some((reader.next_seq(), reader.head()));
    }
    let (next_seq, head) = expected.unwrap_or((0, [0u8; CHAIN_LEN]));
    Ok(ChainSummary {
        segments: files.len(),
        first_seq: first_seq.unwrap_or(0),
        next_seq,
        head,
    })
}

/// What this node's own log says about a head another node recorded for it (ADR-0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessVerdict {
    /// After the witnessed number of records the chain is the witnessed head.
    Confirmed,
    /// That record exists and its chain differs: the log was rewritten after it was witnessed
    /// (the chain may still verify on its own, if every later record was recomputed).
    Contradicted([u8; CHAIN_LEN]),
    /// The log now has fewer records than were witnessed: records were removed.
    Missing,
    /// The record lies in a rotated segment that was pruned; nothing can be said.
    Pruned,
}

/// Checks heads that peers witnessed for the log at `path`: each `(records, head)` says "after
/// `records` records the chain was `head`". The log's own chain is verified first; a log that
/// does not verify is not checked at all. A recomputed chain verifies on its own; only a head
/// kept somewhere its writer could not change exposes it.
pub fn check_witnesses(
    path: &Path,
    witnessed: &[(u64, [u8; CHAIN_LEN])],
) -> Result<Vec<WitnessVerdict>, ChainVerifyError> {
    let summary = verify_chain(path)?;
    let wanted: std::collections::HashSet<u64> = witnessed
        .iter()
        .filter(|(n, _)| *n > 0 && *n <= summary.next_seq && *n > summary.first_seq)
        .map(|(n, _)| n - 1)
        .collect();
    let mut found = std::collections::HashMap::new();
    let mut files: Vec<PathBuf> = rotated_segments(path)
        .map_err(|e| ChainVerifyError::unverified(path, e))?
        .into_iter()
        .map(|(_, p)| p)
        .collect();
    files.push(path.to_path_buf());
    for file in &files {
        let mut reader =
            AuditReader::open(file).map_err(|e| ChainVerifyError::unverified(file, e))?;
        while let Some(record) = reader
            .next_record()
            .map_err(|e| ChainVerifyError::record(file, e))?
        {
            if wanted.contains(&record.seq) {
                found.insert(record.seq, record.chain);
            }
        }
    }
    Ok(witnessed
        .iter()
        .map(|&(n, head)| {
            if n == 0 {
                return if head == [0u8; CHAIN_LEN] {
                    WitnessVerdict::Confirmed
                } else {
                    WitnessVerdict::Contradicted([0u8; CHAIN_LEN])
                };
            }
            if n > summary.next_seq {
                return WitnessVerdict::Missing;
            }
            match found.get(&(n - 1)) {
                Some(chain) if *chain == head => WitnessVerdict::Confirmed,
                Some(chain) => WitnessVerdict::Contradicted(*chain),
                None => WitnessVerdict::Pruned,
            }
        })
        .collect())
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

    /// Writes `payloads` as a fresh log at `path` (a writer with full access rebuilding it).
    fn write_log(path: &Path, payloads: &[&str]) -> (u64, [u8; CHAIN_LEN]) {
        let _ = std::fs::remove_file(path);
        let mut log = AuditLog::open(path).unwrap();
        for p in payloads {
            log.append(p.as_bytes()).unwrap();
        }
        log.sync().unwrap();
        (log.len(), log.head())
    }

    /// ADR-0021: a writer who rewrites the log and recomputes every later record passes
    /// `verify_chain` on its own; a head a peer kept from before the rewrite exposes it.
    #[test]
    fn a_witnessed_head_exposes_a_recomputed_rewrite_that_the_chain_alone_accepts() {
        let path = temp_path("witness");
        let original = [
            "BLOCK|IP:198.51.100.1",
            "BLOCK|IP:198.51.100.2",
            "UNBLOCK|IP:198.51.100.1",
        ];
        let witnessed = write_log(&path, &original);
        let early = (1, read_all(&path).unwrap()[0].chain);
        assert_eq!(
            check_witnesses(&path, &[witnessed, early, (0, [0; CHAIN_LEN])]).unwrap(),
            vec![WitnessVerdict::Confirmed; 3]
        );

        // The second decision is erased and the whole chain recomputed, at least a millisecond
        // later: records written in the same millisecond carry the same timestamp, and the
        // unchanged first record would then keep its chain value (flaked on a fast runner).
        std::thread::sleep(std::time::Duration::from_millis(2));
        write_log(
            &path,
            &[
                "BLOCK|IP:198.51.100.1",
                "BLOCK|IP:203.0.113.9",
                "UNBLOCK|IP:198.51.100.1",
            ],
        );
        assert!(
            verify_chain(&path).is_ok(),
            "the recomputed chain verifies on its own"
        );
        let verdicts = check_witnesses(&path, &[witnessed, early]).unwrap();
        // Rebuilt records carry new timestamps, which the chain covers: even the first record,
        // whose payload is unchanged, now has another chain value.
        assert!(
            verdicts
                .iter()
                .all(|v| matches!(v, WitnessVerdict::Contradicted(_))),
            "{:?}",
            verdicts
        );

        // Records removed after they were witnessed.
        write_log(&path, &original[..2]);
        assert_eq!(
            check_witnesses(&path, &[witnessed]).unwrap(),
            vec![WitnessVerdict::Missing]
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// A rotation never replaces an existing segment: rename(2) would, silently. The original
    /// segment stays byte for byte, the record is refused, and the handle stays refused.
    #[test]
    fn rotation_refuses_to_replace_an_existing_segment() {
        let path = temp_path("rotate-no-overwrite");
        let rotation = Some(Rotation {
            max_bytes: 1,
            keep: 10,
        });
        let mut log = AuditLog::open_with(&path, rotation).unwrap();
        log.append(b"first").unwrap();
        log.sync().unwrap();
        let taken = rotated_path(&path, 0);
        std::fs::write(&taken, b"an earlier segment's evidence").unwrap();
        assert!(
            log.append(b"second").is_err(),
            "rotation onto an existing name must fail"
        );
        assert_eq!(
            std::fs::read(&taken).unwrap(),
            b"an earlier segment's evidence"
        );
        assert!(matches!(log.append(b"third"), Err(AuditError::Poisoned)));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
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
    fn a_second_writer_is_refused_while_the_first_holds_the_log() {
        let path = temp_path("locked");
        let mut first = AuditLog::open(&path).unwrap();
        first.append(b"one").unwrap();
        assert!(matches!(AuditLog::open(&path), Err(AuditError::Locked(_))));
        first.append(b"two").unwrap();
        first.sync().unwrap();
        drop(first);
        let mut again = AuditLog::open(&path).expect("the lock is released with the writer");
        again.append(b"three").unwrap();
        assert_eq!(read_all(&path).unwrap().len(), 3);
    }

    #[test]
    fn a_failed_write_that_cannot_be_undone_poisons_the_writer() {
        let path = temp_path("poisoned");
        let mut log = AuditLog::open(&path).unwrap();
        log.append(b"kept").unwrap();
        log.sync().unwrap();
        // A read-only handle: the write fails and so does the truncation.
        log.file = File::open(&path).unwrap();
        assert!(log.append(b"lost").is_err());
        assert!(matches!(log.append(b"after"), Err(AuditError::Poisoned)));
        drop(log);
        let mut reopened = AuditLog::open(&path).unwrap();
        reopened.append(b"next").unwrap();
        let records = read_all(&path).unwrap();
        assert_eq!(
            records.len(),
            2,
            "the chain continues after the last whole record"
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

    const SMALL: Rotation = Rotation {
        max_bytes: 200,
        keep: 3,
    };

    #[test]
    fn a_stray_file_with_an_oversized_suffix_is_ignored() {
        // Twenty digits that overflow u64 used to panic, which aborts the node at startup.
        let path = temp_path("stray-suffix");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut stray = path.as_os_str().to_owned();
        stray.push(".99999999999999999999");
        std::fs::write(&stray, b"x").unwrap();
        assert_eq!(rotated_segments(&path).unwrap(), vec![]);
        std::fs::remove_file(&stray).unwrap();
    }

    #[test]
    fn rotation_keeps_one_chain_across_segments() {
        let path = temp_path("rotate");
        let mut log = AuditLog::open_with(&path, Some(SMALL)).unwrap();
        for i in 0..20 {
            log.append(format!("record {:02} with some padding", i).as_bytes())
                .unwrap();
        }
        log.sync().unwrap();
        let segs = rotated_segments(&path).unwrap();
        assert_eq!(segs.len(), 3, "only `keep` rotated segments remain");

        let summary = verify_chain(&path).unwrap();
        assert_eq!(summary.next_seq, 20);
        assert_eq!(summary.head, log.head());
        assert_eq!(summary.segments, 4);
        assert!(summary.first_seq > 0, "oldest segments were pruned");

        // Reopening continues the same chain and numbering.
        drop(log);
        let mut log = AuditLog::open_with(&path, Some(SMALL)).unwrap();
        assert_eq!(log.append(b"after reopen").unwrap(), 20);
        log.sync().unwrap();
        assert_eq!(verify_chain(&path).unwrap().next_seq, 21);
    }

    #[test]
    fn verify_detects_missing_or_edited_segments() {
        let path = temp_path("rotate-tamper");
        let mut log = AuditLog::open_with(
            &path,
            Some(Rotation {
                max_bytes: 200,
                keep: 10,
            }),
        )
        .unwrap();
        for i in 0..20 {
            log.append(format!("record {:02} with some padding", i).as_bytes())
                .unwrap();
        }
        log.sync().unwrap();
        let segs = rotated_segments(&path).unwrap();
        assert!(segs.len() >= 3);

        // Remove a middle segment.
        let (_, middle) = &segs[1];
        let saved = std::fs::read(middle).unwrap();
        std::fs::remove_file(middle).unwrap();
        let err = verify_chain(&path).unwrap_err();
        assert!(err.to_string().contains("does not continue"), "{}", err);
        std::fs::write(middle, &saved).unwrap();
        assert!(verify_chain(&path).is_ok());

        // Bytes appended to a rotated segment (mutation sweep 2026-10-07: untested).
        let (_, second) = &segs[1];
        let mut longer = saved.clone();
        longer.extend_from_slice(b"appended");
        std::fs::write(second, &longer).unwrap();
        let err = verify_chain(&path).unwrap_err();
        assert!(err.to_string().contains("trailing bytes"), "{}", err);
        std::fs::write(second, &saved).unwrap();
        assert!(verify_chain(&path).is_ok());
        // The live file may end in a record still being written: that is not tampering.
        let mut live = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut live, b"SAL2 half a record").unwrap();
        assert!(verify_chain(&path).is_ok());

        // Edit a byte inside a rotated segment.
        let (_, first) = &segs[0];
        let mut bytes = std::fs::read(first).unwrap();
        bytes[HEADER_LEN + 3] ^= 1;
        std::fs::write(first, &bytes).unwrap();
        assert!(verify_chain(&path)
            .unwrap_err()
            .to_string()
            .contains("hash chain mismatch"));
    }

    #[test]
    fn crash_between_rename_and_header_continues_the_chain() {
        let path = temp_path("rotate-crash");
        {
            let mut log = AuditLog::open_with(&path, Some(SMALL)).unwrap();
            for i in 0..5 {
                log.append(format!("record {:02} with some padding", i).as_bytes())
                    .unwrap();
            }
            log.sync().unwrap();
        }
        // Simulate the crash: the active file was renamed, the new one never written.
        let head_before = verify_chain(&path).unwrap();
        let seg_name = rotated_path(&path, 999);
        std::fs::rename(&path, &seg_name).unwrap();
        std::fs::write(&path, b"").unwrap();

        let mut log = AuditLog::open_with(&path, Some(SMALL)).unwrap();
        assert_eq!(log.append(b"next").unwrap(), head_before.next_seq);
        log.sync().unwrap();
        let _ = std::fs::remove_file(&seg_name);
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
