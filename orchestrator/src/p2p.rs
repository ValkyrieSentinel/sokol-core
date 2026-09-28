#![allow(clippy::too_many_arguments)]
//! Sovereign mesh transport.
//!
//! Trust model: a node accepts messages only from peers whose ML-DSA-65 (FIPS 204) public key
//! is pinned in its trust store (`--peers-file`). Every envelope is signed over all of its bytes
//! but the signature (wire version, sender, timestamp, nonce, payload), must fall inside a
//! clock-skew window and is accepted at most once. A connection is bound to the identity
//! announced in its first (handshake) envelope; any later envelope from a different sender
//! closes the connection.
//!
//! Wire format v2 (see [`SecureEnvelope::encode`]): each frame starts with `SKM` and a version
//! byte, so a node of another protocol version is recognised and refused by name instead of
//! failing to parse. The handshake carries the range of versions each side speaks; a
//! connection with no common version is closed with both ranges in the log.
//!
//! The transport authenticates but does not encrypt: mesh commands travel in plaintext.
use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, RwLock, Semaphore};
use tokio::time::timeout;

use ml_dsa::{EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey};
use rand::RngCore;

use crate::MeshCommand;
use common::canonical::CanonicalParser;

/// FIPS 204 context string of every envelope signature: a signature made for anything else
/// with the same key never verifies as a mesh envelope.
const SIGNATURE_CONTEXT: &[u8] = b"sokol-mesh-envelope";
/// Every frame starts with these bytes and the wire version.
const WIRE_MAGIC: &[u8; 3] = b"SKM";
/// Wire versions this node speaks. Handshakes are always sent as v2 envelopes (the stable
/// bootstrap format). Only v2 exists, so every frame is sealed as v2; a v3 must make the writer
/// use the version negotiated for its connection (see [`negotiate`]).
pub const WIRE_VERSION_MIN: u8 = 2;
pub const WIRE_VERSION_MAX: u8 = 2;
/// Public keys in the peers file and `--print-public-key` carry their algorithm.
pub const KEY_PREFIX: &str = "mldsa65:";
/// Node key file: this magic, then the 32-byte ML-DSA seed (FIPS 204 KeyGen_internal input).
const KEY_FILE_MAGIC: &[u8; 4] = b"SKK2";
/// A pre-v2 key file: raw Dilithium3 public key (1952 bytes) and secret key (4000 bytes).
const LEGACY_KEY_FILE_LEN: usize = 1952 + 4000;
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;
/// How long a nonce is remembered after it arrived: a timestamp accepted then is at most
/// MAX_CLOCK_SKEW_MS ahead, so it is stale this long after arrival.
const REPLAY_WINDOW_MS: u64 = 2 * MAX_CLOCK_SKEW_MS;
pub const MAX_FRAME_BYTES: usize = 128 * 1024;

// ---- Resource limits of the mesh transport (see ARCHITECTURE, ADR-0013) ----

/// A connection must authenticate (its handshake) within this long.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections not yet authenticated, at once, in total and from one address: an unknown
/// party cannot hold the slots pinned peers need.
pub const MAX_PENDING_HANDSHAKES: usize = 16;
pub const MAX_PENDING_PER_ADDRESS: usize = 2;
/// Frames and bytes an authenticated peer may send, per second and as a burst (a full snapshot
/// fits the burst). Past that the reader waits: the peer is slowed by TCP, nothing is dropped.
pub const FRAMES_PER_SEC: f64 = 500.0;
pub const FRAME_BURST: f64 = 5_000.0;
pub const BYTES_PER_SEC: f64 = 4.0 * 1024.0 * 1024.0;
pub const BYTE_BURST: f64 = 32.0 * 1024.0 * 1024.0;

/// A token bucket; `take` says how long to wait before the cost may be spent.
#[derive(Debug)]
pub struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    at: std::time::Instant,
}

impl Bucket {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            rate,
            burst,
            tokens: burst,
            at: std::time::Instant::now(),
        }
    }

    /// Spends `cost` (going into debt if needed) and returns the wait until the debt is paid.
    pub fn take(&mut self, cost: f64, now: std::time::Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst) - cost;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}

/// Counters of the transport's limits, for the metrics.
#[derive(Default)]
pub struct MeshStats {
    pub handshakes_refused: std::sync::atomic::AtomicU64,
    pub handshake_timeouts: std::sync::atomic::AtomicU64,
    pub frames_delayed: std::sync::atomic::AtomicU64,
    /// Broadcasts not queued because a peer's queue was full, by class.
    pub dropped_urgent: std::sync::atomic::AtomicU64,
    pub dropped_bulk: std::sync::atomic::AtomicU64,
    /// Envelopes refused, by `EnvelopeError::LABELS`. `stale_timestamp` rising from one peer
    /// means its clock and this node's disagree by more than the envelope window.
    pub rejected: [std::sync::atomic::AtomicU64; 5],
}

/// Admission of connections that have not authenticated yet.
#[derive(Clone)]
pub struct Admission {
    pending: Arc<Semaphore>,
    per_address: Arc<std::sync::Mutex<HashMap<std::net::IpAddr, usize>>>,
}

/// Held by a connection until it authenticates (or ends).
pub struct HandshakeTicket {
    _permit: tokio::sync::OwnedSemaphorePermit,
    address: std::net::IpAddr,
    per_address: Arc<std::sync::Mutex<HashMap<std::net::IpAddr, usize>>>,
}

impl Drop for HandshakeTicket {
    fn drop(&mut self) {
        let mut counts = self.per_address.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = counts.get_mut(&self.address) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.remove(&self.address);
            }
        }
    }
}

impl Default for Admission {
    fn default() -> Self {
        Self::new(MAX_PENDING_HANDSHAKES)
    }
}

impl Admission {
    pub fn new(pending: usize) -> Self {
        Self {
            pending: Arc::new(Semaphore::new(pending)),
            per_address: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// A ticket for a new, unauthenticated connection from `address`, if there is room.
    pub fn admit(&self, address: std::net::IpAddr) -> Option<HandshakeTicket> {
        let mut counts = self.per_address.lock().unwrap_or_else(|p| p.into_inner());
        let n = counts.entry(address).or_insert(0);
        if *n >= MAX_PENDING_PER_ADDRESS {
            return None;
        }
        let permit = self.pending.clone().try_acquire_owned().ok()?;
        *n += 1;
        Some(HandshakeTicket {
            _permit: permit,
            address,
            per_address: self.per_address.clone(),
        })
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    // Byte-wise over ASCII digits only: a multi-byte character is an error, not a slice across
    // its boundary (R27-01: that panicked, and panic aborts the node).
    let digit = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let s = s.trim().as_bytes();
    if !s.len().is_multiple_of(2) {
        bail!("hex string has odd length");
    }
    let (pairs, _) = s.as_chunks::<2>();
    pairs
        .iter()
        .map(|[hi, lo]| match (digit(*hi), digit(*lo)) {
            (Some(hi), Some(lo)) => Ok(hi << 4 | lo),
            _ => bail!("invalid hex digit"),
        })
        .collect()
}

pub struct NodeCrypto {
    pub public_key: VerifyingKey<MlDsa65>,
    signing_key: SigningKey<MlDsa65>,
}

impl NodeCrypto {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed.into());
        Self {
            public_key: signing_key.verifying_key(),
            signing_key,
        }
    }

    /// Loads the node identity from `path`, creating it (mode 0600) on first start so the
    /// node keeps the same identity across restarts and stays pinned in its peers' trust stores.
    ///
    /// A pre-v2 (Dilithium3) key file is moved aside to `<path>.dilithium3.retired` and a new
    /// ML-DSA-65 identity is created: v2 peers could not verify the old key anyway, and the
    /// node must keep protecting itself while its new public key is distributed.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let mode = std::fs::metadata(path)?.permissions().mode();
                if mode & 0o077 != 0 {
                    bail!(
                        "node key file {} is accessible by group/others (mode {:o}); expected 0600",
                        path.display(),
                        mode & 0o777
                    );
                }
                if bytes.len() == LEGACY_KEY_FILE_LEN {
                    let (crypto, retired) = Self::migrate_legacy(path)?;
                    error!(
                        "[P2P] {} held a legacy Dilithium3 key (mesh protocol v1), moved to {}. \
                         New ML-DSA-65 identity created: put its public key in every peer's \
                         peers file: {}",
                        path.display(),
                        retired.display(),
                        crypto.public_key_hex()
                    );
                    return Ok(crypto);
                }
                Self::from_key_bytes(&bytes)
                    .with_context(|| format!("node key file {} is malformed", path.display()))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let crypto = Self::create(path)?;
                info!(
                    "[P2P] Generated new node identity key at {}",
                    path.display()
                );
                Ok(crypto)
            }
            Err(e) => {
                Err(e).with_context(|| format!("failed to read node key file {}", path.display()))
            }
        }
    }

    fn create(path: &Path) -> Result<Self> {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Self::write_key(path, &seed)?;
        sync_dir(path)?;
        Ok(Self::from_seed(seed))
    }

    /// New key file, never replacing an existing one.
    fn write_key(path: &Path, seed: &[u8; 32]) -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to create node key file {}", path.display()))?;
        file.write_all(KEY_FILE_MAGIC)?;
        file.write_all(seed)?;
        file.sync_all()?;
        Ok(())
    }

    /// Replaces a v1 key file with a new ML-DSA identity without losing any key (R27-06):
    /// 1. the old file is hard-linked to the first free `<path>.dilithium3.retired[.N]` (a link
    ///    never replaces an existing backup), directory synced;
    /// 2. the new key is written to `<path>.new` and renamed over `<path>`, directory synced.
    ///
    /// A crash before step 2 leaves the old key in place (the next start migrates again, to a
    /// new backup name); after it, both keys exist.
    fn migrate_legacy(path: &Path) -> Result<(Self, std::path::PathBuf)> {
        let retired = (0..1000)
            .map(|n| {
                let mut name = path.as_os_str().to_owned();
                name.push(".dilithium3.retired");
                if n > 0 {
                    name.push(format!(".{}", n));
                }
                std::path::PathBuf::from(name)
            })
            .find_map(|candidate| match std::fs::hard_link(path, &candidate) {
                Ok(()) => Some(Ok(candidate)),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => None,
                Err(e) => Some(Err(e)),
            })
            .unwrap_or_else(|| Err(std::io::Error::other("no free backup name")))
            .with_context(|| format!("failed to keep the legacy key file {}", path.display()))?;
        sync_dir(path)?;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let mut staged = path.as_os_str().to_owned();
        staged.push(".new");
        let staged = std::path::PathBuf::from(staged);
        let _ = std::fs::remove_file(&staged); // left by an interrupted migration
        Self::write_key(&staged, &seed)?;
        std::fs::rename(&staged, path)
            .with_context(|| format!("failed to install the new key at {}", path.display()))?;
        sync_dir(path)?;
        Ok((Self::from_seed(seed), retired))
    }

    fn from_key_bytes(bytes: &[u8]) -> Result<Self> {
        let seed = bytes
            .strip_prefix(KEY_FILE_MAGIC.as_slice())
            .and_then(|seed| <[u8; 32]>::try_from(seed).ok())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "expected {} bytes starting with {:?}, found {} bytes",
                    KEY_FILE_MAGIC.len() + 32,
                    std::str::from_utf8(KEY_FILE_MAGIC).unwrap_or_default(),
                    bytes.len()
                )
            })?;
        Ok(Self::from_seed(seed))
    }

    /// `mldsa65:<hex>`, as the peers file expects it.
    pub fn public_key_hex(&self) -> String {
        format!("{}{}", KEY_PREFIX, to_hex(&self.public_key.encode()))
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = self
            .signing_key
            .expanded_key()
            .sign_deterministic(message, SIGNATURE_CONTEXT)
            .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;
        Ok(signature.encode().to_vec())
    }
}

/// Makes a rename or link in `path`'s directory durable.
fn sync_dir(path: &Path) -> Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("failed to sync directory {}", dir.display()))
}

/// A key as the peers file lists it.
enum PeerKey {
    MlDsa(VerifyingKey<MlDsa65>),
    /// A v1 Dilithium3 key: exactly 1952 bytes as unprefixed hex.
    Legacy,
}

fn classify_key(text: &str) -> Result<PeerKey> {
    let text = text.trim();
    if text.starts_with(KEY_PREFIX) {
        return parse_public_key(text).map(PeerKey::MlDsa);
    }
    if text.len() == 2 * 1952 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(PeerKey::Legacy);
    }
    bail!(
        "key is neither '{}<hex>' nor a legacy Dilithium3 key (3904 hex digits)",
        KEY_PREFIX
    )
}

/// Parses `mldsa65:<hex>`. An unprefixed key is a pre-v2 (Dilithium3) key: same length, but
/// no v2 signature would ever verify against it, so it is named as such instead.
pub fn parse_public_key(text: &str) -> Result<VerifyingKey<MlDsa65>> {
    let Some(hex) = text.trim().strip_prefix(KEY_PREFIX) else {
        bail!(
            "not an ML-DSA-65 key (expected '{}<hex>'; an unprefixed key is a legacy Dilithium3 \
             key from mesh protocol v1: regenerate it with --print-public-key)",
            KEY_PREFIX
        );
    };
    let bytes = from_hex(hex)?;
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes.as_slice()).map_err(|_| {
        anyhow::anyhow!(
            "an ML-DSA-65 public key has 1952 bytes, found {}",
            bytes.len()
        )
    })?;
    Ok(VerifyingKey::decode(&encoded))
}

#[derive(Deserialize)]
struct PeerEntry {
    node_id: u64,
    #[serde(default)]
    public_key: Option<String>,
    /// Several keys during a rotation: the node may sign with any of them.
    #[serde(default)]
    public_keys: Vec<String>,
    /// What this peer may impose on this node (ADR-7); unset fields take the command-line defaults.
    #[serde(default)]
    envelope: Option<EnvelopeSpec>,
}

/// Per-peer overrides of the envelope defaults, from the peers file.
#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSpec {
    pub max_active: Option<usize>,
    pub max_ttl_secs: Option<u64>,
    pub min_prefix_v4: Option<u8>,
    pub min_prefix_v6: Option<u8>,
}

/// Pinned `(node_id, public_key)` pairs. A peer absent from the store cannot be heard.
#[derive(Default)]
pub struct TrustStore {
    keys: HashMap<u64, Vec<VerifyingKey<MlDsa65>>>,
    envelopes: HashMap<u64, EnvelopeSpec>,
    /// Peers listed with only a pre-v2 key: not trusted until their ML-DSA key is listed.
    legacy: Vec<u64>,
}

impl TrustStore {
    /// Reads a JSON array of `{"node_id": u64, "public_key": "<hex>"}` objects; during a key
    /// rotation an entry may list `"public_keys": ["<old>", "<new>"]` instead.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read peers file {}", path.display()))?;
        let entries: Vec<PeerEntry> = serde_json::from_str(&raw)
            .with_context(|| format!("peers file {} is not a valid peer list", path.display()))?;
        let mut store = Self::default();
        let mut seen = std::collections::HashSet::new();
        for entry in entries {
            let id = entry.node_id;
            // Every entry counts, legacy or not (R27-02).
            if !seen.insert(id) {
                bail!("peers file lists node_id {} more than once", id);
            }
            if let Some(spec) = entry.envelope {
                if spec.min_prefix_v4.is_some_and(|p| p > 32)
                    || spec.min_prefix_v6.is_some_and(|p| p > 128)
                {
                    bail!("peer {}: envelope prefix length out of range", id);
                }
            }
            let hexes: Vec<&String> = entry
                .public_key
                .iter()
                .chain(entry.public_keys.iter())
                .collect();
            if hexes.is_empty() {
                bail!("peer {}: no public_key or public_keys", id);
            }
            let mut keys = Vec::new();
            let mut legacy = false;
            for hex in hexes {
                // A pre-v2 key must not keep the node from starting after an upgrade: the peer
                // is not trusted until its ML-DSA key is listed, and the log says so. Only the
                // exact v1 format counts as legacy; anything else is an error (a typo in the
                // prefix must not quietly revoke a peer, R27-02).
                match classify_key(hex).with_context(|| format!("peer {}", id))? {
                    PeerKey::MlDsa(key) => keys.push(key),
                    PeerKey::Legacy => legacy = true,
                }
            }
            if keys.is_empty() {
                error!(
                    "[P2P] Peer {} in {} has only a legacy Dilithium3 key (mesh protocol v1); \
                     it is not trusted until its '{}' key is listed",
                    id,
                    path.display(),
                    KEY_PREFIX
                );
                store.legacy.push(id);
                continue;
            }
            if legacy {
                warn!(
                    "[P2P] Peer {}: legacy Dilithium3 key ignored, its ML-DSA key is used",
                    id
                );
            }
            store.keys.insert(id, keys);
            if let Some(spec) = entry.envelope {
                store.envelopes.insert(id, spec);
            }
        }
        Ok(store)
    }

    pub fn insert(&mut self, node_id: u64, key: VerifyingKey<MlDsa65>) {
        self.keys.entry(node_id).or_default().push(key);
    }

    pub fn get(&self, node_id: u64) -> Option<&[VerifyingKey<MlDsa65>]> {
        self.keys.get(&node_id).map(Vec::as_slice)
    }

    /// Envelope overrides listed in the peers file.
    pub fn envelopes(&self) -> &HashMap<u64, EnvelopeSpec> {
        &self.envelopes
    }

    /// The pinned nodes' ids.
    pub fn node_ids(&self) -> std::collections::HashSet<u64> {
        self.keys.keys().copied().collect()
    }

    /// Peers skipped because the peers file lists only a legacy (pre-v2) key for them.
    pub fn legacy_peers(&self) -> &[u64] {
        &self.legacy
    }

    /// Number of pinned nodes.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// Nonces one sender can bring within the window: its frame limit (ADR-0013) over the window,
/// for the two connections a pair of nodes holds when each lists the other as a seed.
const REPLAY_PER_SENDER: usize =
    2 * (FRAME_BURST as usize + FRAMES_PER_SEC as usize * (REPLAY_WINDOW_MS / 1000) as usize);

/// One sender's remembered nonces, in arrival order.
#[derive(Default)]
struct SenderWindow {
    order: std::collections::VecDeque<(u64, u64)>,
    seen: std::collections::HashSet<u64>,
}

/// Remembers `(sender, nonce)` pairs for as long as their timestamp could still be accepted.
///
/// Kept per sender and bounded per sender (N02, 2026-09-28): one peer at its full frame rate
/// fills only its own window, never another's. Only authenticated senders reach it (the
/// signature is checked first), so the number of windows is bounded by the trust store.
/// Expiry pops the oldest arrivals, so a frame costs O(1) amortized, not a scan of the cache.
/// Arrival is wall-clock time, like the acceptance check: after a backward step an entry is
/// kept longer (the safe side), after a forward step what it guards is stale anyway.
#[derive(Default)]
pub struct ReplayGuard {
    senders: HashMap<u64, SenderWindow>,
}

impl ReplayGuard {
    #[cfg(test)]
    fn remembered(&self) -> usize {
        self.senders.values().map(|w| w.seen.len()).sum()
    }

    fn check_and_record(
        &mut self,
        sender_id: u64,
        nonce: u64,
        _timestamp_ms: u64,
        now: u64,
    ) -> bool {
        let w = self.senders.entry(sender_id).or_default();
        while let Some(&(arrived, old)) = w.order.front() {
            if arrived.saturating_add(REPLAY_WINDOW_MS) > now {
                break;
            }
            w.order.pop_front();
            w.seen.remove(&old);
        }
        if w.seen.contains(&nonce) {
            return false;
        }
        // Over its own budget a sender is refused (fail-closed), others are not affected.
        if w.seen.len() >= REPLAY_PER_SENDER {
            return false;
        }
        w.seen.insert(nonce);
        w.order.push_back((now, nonce));
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureEnvelope {
    /// Wire version it was sealed for (signed).
    pub version: u8,
    pub sender_id: u64,
    pub timestamp_ms: u64,
    pub nonce: u64,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Bytes before the payload: magic, version, sender, timestamp, nonce, payload length.
const ENVELOPE_HEADER_LEN: usize = 3 + 1 + 8 + 8 + 8 + 4;

/// Why a frame is not a v2 envelope.
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    /// Does not start with `SKM`: the pre-versioned protocol (v1, Dilithium3 over bincode).
    Legacy,
    /// `SKM` with a version this node does not speak.
    Unsupported(u8),
    Malformed(&'static str),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Legacy => write!(
                f,
                "peer speaks the pre-versioned mesh protocol (v1: Dilithium3 over bincode); \
                 this node speaks v{}..v{}: upgrade the peer",
                WIRE_VERSION_MIN, WIRE_VERSION_MAX
            ),
            Self::Unsupported(v) => write!(
                f,
                "peer sent mesh wire version {}; this node speaks v{}..v{}",
                v, WIRE_VERSION_MIN, WIRE_VERSION_MAX
            ),
            Self::Malformed(why) => write!(f, "malformed envelope: {}", why),
        }
    }
}

impl SecureEnvelope {
    /// Wire format v2, all integers little-endian:
    ///
    /// ```text
    /// "SKM" | version u8 = 2 | sender u64 | timestamp_ms u64 | nonce u64 | payload_len u32
    ///       | payload | ML-DSA-65 signature (3309 bytes, the rest of the frame)
    /// ```
    ///
    /// The signature covers every byte before it (so the version too: no downgrade), with the
    /// FIPS 204 context string `sokol-mesh-envelope`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = unsigned_bytes(
            self.version,
            self.sender_id,
            self.timestamp_ms,
            self.nonce,
            &self.payload,
        );
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(frame: &[u8]) -> Result<Self, WireError> {
        let Some((magic, rest)) = frame.split_first_chunk::<3>() else {
            return Err(WireError::Legacy);
        };
        if magic != WIRE_MAGIC {
            return Err(WireError::Legacy);
        }
        let Some((&version, rest)) = rest.split_first() else {
            return Err(WireError::Malformed("no version"));
        };
        if !(WIRE_VERSION_MIN..=WIRE_VERSION_MAX).contains(&version) {
            return Err(WireError::Unsupported(version));
        }
        let field =
            |rest: &[u8], at: usize| -> Option<[u8; 8]> { rest.get(at..at + 8)?.try_into().ok() };
        let (Some(sender), Some(timestamp), Some(nonce)) =
            (field(rest, 0), field(rest, 8), field(rest, 16))
        else {
            return Err(WireError::Malformed("short header"));
        };
        let payload_len = rest
            .get(24..28)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
            .ok_or(WireError::Malformed("short header"))? as usize;
        let body = rest.get(28..).unwrap_or_default();
        let (payload, signature) = body
            .split_at_checked(payload_len)
            .ok_or(WireError::Malformed("payload longer than the frame"))?;
        Ok(Self {
            version,
            sender_id: u64::from_le_bytes(sender),
            timestamp_ms: u64::from_le_bytes(timestamp),
            nonce: u64::from_le_bytes(nonce),
            payload: payload.to_vec(),
            signature: signature.to_vec(),
        })
    }
}

/// The signed part of a v2 envelope: everything but the signature.
fn unsigned_bytes(
    version: u8,
    sender_id: u64,
    timestamp_ms: u64,
    nonce: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ENVELOPE_HEADER_LEN + payload.len() + 3309);
    msg.extend_from_slice(WIRE_MAGIC);
    msg.push(version);
    msg.extend_from_slice(&sender_id.to_le_bytes());
    msg.extend_from_slice(&timestamp_ms.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes());
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(payload);
    msg
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkMessage {
    Command(MeshCommand),
    Ack,
    Ping,
    Pong,
    /// First message on a connection; `wire_min..=wire_max` are the wire versions the sender
    /// speaks.
    Handshake {
        node_id: u64,
        wire_min: u8,
        wire_max: u8,
    },
}

impl NetworkMessage {
    pub fn handshake(node_id: u64) -> Self {
        Self::Handshake {
            node_id,
            wire_min: WIRE_VERSION_MIN,
            wire_max: WIRE_VERSION_MAX,
        }
    }
}

/// The highest wire version both sides speak, or why there is none.
pub fn negotiate(peer_min: u8, peer_max: u8) -> Result<u8, String> {
    let (low, high) = (
        peer_min.max(WIRE_VERSION_MIN),
        peer_max.min(WIRE_VERSION_MAX),
    );
    if peer_min > peer_max || low > high {
        return Err(format!(
            "no common mesh protocol version: peer speaks v{}..v{}, this node v{}..v{}",
            peer_min, peer_max, WIRE_VERSION_MIN, WIRE_VERSION_MAX
        ));
    }
    Ok(high)
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    UnknownSender,
    BadSignature,
    StaleTimestamp,
    Replay,
    MalformedPayload,
}

impl EnvelopeError {
    /// Metric label and counter slot, in `MeshStats::rejected` order.
    pub const LABELS: [&'static str; 5] = [
        "unknown_sender",
        "bad_signature",
        "stale_timestamp",
        "replay",
        "malformed_payload",
    ];

    fn slot(&self) -> usize {
        match self {
            Self::UnknownSender => 0,
            Self::BadSignature => 1,
            Self::StaleTimestamp => 2,
            Self::Replay => 3,
            Self::MalformedPayload => 4,
        }
    }
}

pub fn seal(
    crypto: &NodeCrypto,
    sender_id: u64,
    message: &NetworkMessage,
) -> Result<SecureEnvelope> {
    let payload = serde_json::to_vec(message)?;
    let payload_str = std::str::from_utf8(&payload).context("Payload is not valid UTF-8")?;
    check_canonical(payload_str)
        .map_err(|e| anyhow::anyhow!("Canonical validation failed: {:?}", e))?;

    let timestamp_ms = now_ms();
    let nonce: u64 = rand::random();
    let signature = crypto.sign(&unsigned_bytes(
        WIRE_VERSION_MAX,
        sender_id,
        timestamp_ms,
        nonce,
        &payload,
    ))?;

    Ok(SecureEnvelope {
        version: WIRE_VERSION_MAX,
        sender_id,
        timestamp_ms,
        nonce,
        payload,
        signature,
    })
}

/// Authenticates an envelope and decodes its message. Checks run cheapest-first, and the
/// replay cache is only written after the signature verified, so unknown senders cannot fill it.
pub fn open(
    trust: &TrustStore,
    replay: &mut ReplayGuard,
    envelope: &SecureEnvelope,
    now: u64,
) -> Result<NetworkMessage, EnvelopeError> {
    let keys = trust
        .get(envelope.sender_id)
        .ok_or(EnvelopeError::UnknownSender)?;

    let signature = Signature::<MlDsa65>::try_from(envelope.signature.as_slice())
        .map_err(|_| EnvelopeError::BadSignature)?;
    let signed = unsigned_bytes(
        envelope.version,
        envelope.sender_id,
        envelope.timestamp_ms,
        envelope.nonce,
        &envelope.payload,
    );
    if !keys
        .iter()
        .any(|key| key.verify_with_context(&signed, SIGNATURE_CONTEXT, &signature))
    {
        return Err(EnvelopeError::BadSignature);
    }

    if envelope.timestamp_ms.abs_diff(now) > MAX_CLOCK_SKEW_MS {
        return Err(EnvelopeError::StaleTimestamp);
    }

    if !replay.check_and_record(
        envelope.sender_id,
        envelope.nonce,
        envelope.timestamp_ms,
        now,
    ) {
        return Err(EnvelopeError::Replay);
    }

    let payload_str =
        std::str::from_utf8(&envelope.payload).map_err(|_| EnvelopeError::MalformedPayload)?;
    check_canonical(payload_str).map_err(|_| EnvelopeError::MalformedPayload)?;
    serde_json::from_slice(&envelope.payload).map_err(|_| EnvelopeError::MalformedPayload)
}

/// Objects must pass the strict duplicate-key check. Unit variants (Ping, Pong, Ack) serialize
/// as a bare JSON string, which has no keys to duplicate; requiring an object here rejected
/// every heartbeat, so idle connections were torn down by the 30 s read timeout.
fn check_canonical(payload: &str) -> Result<(), common::canonical::CanonicalError> {
    let trimmed = payload.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        return Ok(());
    }
    CanonicalParser::validate_strict_json_object(payload)
}

/// addr -> (writer, node id, connection id). The connection id lets a connection that ends
/// remove only its own entry: a stale connection timing out after the peer already reconnected
/// from the same address must not unregister the new one.
/// A connected peer's two outgoing queues. The writer empties `urgent` first: block decisions,
/// their repairs and keepalives; `bulk` carries telemetry, digests and alerts and is what a full
/// link drops first.
#[derive(Clone)]
pub struct PeerLink {
    pub urgent: mpsc::Sender<SecureEnvelope>,
    pub bulk: mpsc::Sender<SecureEnvelope>,
}

pub const URGENT_QUEUE: usize = 256;
pub const BULK_QUEUE: usize = 64;

impl PeerLink {
    fn for_command(&self, command: &MeshCommand) -> &mpsc::Sender<SecureEnvelope> {
        if command.urgent() {
            &self.urgent
        } else {
            &self.bulk
        }
    }
}

/// addr -> (queues, node id, connection id).
pub type PeerMap = Arc<RwLock<HashMap<SocketAddr, (PeerLink, u64, u64)>>>;

static NEXT_CONNECTION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Clone)]
pub struct PeerRegistry {
    peers: PeerMap,
    /// Told the address of every peer that completes its handshake.
    peer_up: Arc<std::sync::Mutex<Option<mpsc::UnboundedSender<SocketAddr>>>>,
    /// Swapped as a whole by `reload`, so a message is checked against one consistent store.
    trust: Arc<std::sync::RwLock<Arc<TrustStore>>>,
    replay: Arc<std::sync::Mutex<ReplayGuard>>,
    pub stats: Arc<MeshStats>,
    /// Frames per second and burst allowed to one authenticated peer (ADR-0013).
    frame_limit: (f64, f64),
}

impl PeerRegistry {
    pub fn new(trust: TrustStore) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_up: Arc::new(std::sync::Mutex::new(None)),
            trust: Arc::new(std::sync::RwLock::new(Arc::new(trust))),
            replay: Arc::new(std::sync::Mutex::new(ReplayGuard::default())),
            stats: Arc::new(MeshStats::default()),
            frame_limit: (FRAMES_PER_SEC, FRAME_BURST),
        }
    }

    /// Another per-peer frame rate (tests: reach the pacing path with a few frames).
    #[cfg(test)]
    fn with_frame_limit(mut self, per_sec: f64, burst: f64) -> Self {
        self.frame_limit = (per_sec, burst);
        self
    }

    pub async fn add_peer(&self, addr: SocketAddr, link: PeerLink, node_id: u64, conn_id: u64) {
        let mut peers = self.peers.write().await;
        peers.insert(addr, (link, node_id, conn_id));
        info!(
            "[P2P] Registered authenticated peer: {} [Node ID: {}]",
            addr, node_id
        );
        if let Some(tx) = self
            .peer_up
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            let _ = tx.send(addr);
        }
    }

    pub fn on_peer_up(&self, tx: mpsc::UnboundedSender<SocketAddr>) {
        *self.peer_up.lock().unwrap_or_else(|p| p.into_inner()) = Some(tx);
    }

    /// Sends one command to one connected peer.
    /// Address of the live connection authenticated as `node_id`, if any.
    pub async fn addr_of(&self, node_id: u64) -> Option<SocketAddr> {
        self.peers
            .read()
            .await
            .iter()
            .find(|(_, (_, id, _))| *id == node_id)
            .map(|(addr, _)| *addr)
    }

    pub async fn send_to(
        &self,
        addr: SocketAddr,
        command: &MeshCommand,
        node_id: u64,
        crypto: &NodeCrypto,
    ) -> Result<()> {
        let envelope = seal(crypto, node_id, &NetworkMessage::Command(command.clone()))?;
        let tx = self
            .peers
            .read()
            .await
            .get(&addr)
            .map(|(link, _, _)| link.for_command(command).clone())
            .ok_or_else(|| anyhow::anyhow!("peer {} is not connected", addr))?;
        match timeout(Duration::from_secs(2), tx.send(envelope)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(anyhow::anyhow!("peer {} writer closed", addr)),
            Err(_) => Err(anyhow::anyhow!("peer {} queue stayed full for 2 s", addr)),
        }
    }

    /// Replaces the trust store. Connections of peers whose key was removed are closed on
    /// their next envelope, which no longer verifies.
    /// Whether `node_id` is trusted now.
    pub fn trusts(&self, node_id: u64) -> bool {
        self.trust
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(node_id)
            .is_some()
    }

    /// Refuses a candidate trust store that lists a peer trusted now with an ML-DSA key with
    /// only a legacy key: a mistake, not an upgrade (R27-02). Checked before anything changes.
    pub fn check_candidate(&self, candidate: &TrustStore) -> Result<()> {
        if let Some(id) = candidate.legacy_peers().iter().find(|id| self.trusts(**id)) {
            bail!(
                "peer {} is trusted with an ML-DSA key but listed with only a legacy key",
                id
            );
        }
        Ok(())
    }

    pub fn reload(&self, trust: TrustStore) -> usize {
        let pinned = trust.len();
        *self.trust.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(trust);
        pinned
    }

    pub fn pinned_peers(&self) -> usize {
        self.trust.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Authenticated nodes connected now. Two nodes that list each other as seeds hold two
    /// connections, one dialed by each; they count once.
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        let nodes: std::collections::HashSet<u64> = peers.values().map(|(_, id, _)| *id).collect();
        nodes.len()
    }

    pub async fn remove_peer(&self, addr: &SocketAddr, conn_id: u64) {
        let mut peers = self.peers.write().await;
        if peers.get(addr).is_some_and(|(_, _, id)| *id != conn_id) {
            return;
        }
        if let Some((_, node_id, _)) = peers.remove(addr) {
            info!(
                "[P2P] Unregistered peer from registry: {} [Node ID: {}]",
                addr, node_id
            );
        }
    }

    pub fn open(&self, envelope: &SecureEnvelope) -> Result<NetworkMessage, EnvelopeError> {
        self.open_at(envelope, now_ms())
    }

    fn open_at(
        &self,
        envelope: &SecureEnvelope,
        now: u64,
    ) -> Result<NetworkMessage, EnvelopeError> {
        let mut replay = self.replay.lock().unwrap_or_else(|p| p.into_inner());
        let trust = self.trust.read().unwrap_or_else(|p| p.into_inner()).clone();
        let opened = open(&trust, &mut replay, envelope, now);
        if let Err(e) = &opened {
            if let Some(counter) = self.stats.rejected.get(e.slot()) {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        opened
    }

    pub async fn broadcast(
        &self,
        command: &MeshCommand,
        node_id: u64,
        crypto: &NodeCrypto,
    ) -> Result<()> {
        let envelope = seal(crypto, node_id, &NetworkMessage::Command(command.clone()))?;

        // Never wait for a slow or dead peer: a full queue would stall the caller (the main
        // tick, IPC handling) behind one bad link. A peer that misses a block catches up through
        // BlockSync when it reconnects.
        // Once per node: its newest connection first, an older one if that queue is full.
        let peers = self.peers.read().await;
        let mut by_node: HashMap<u64, Vec<(u64, &SocketAddr, &PeerLink)>> = HashMap::new();
        for (addr, (link, id, conn)) in peers.iter() {
            by_node.entry(*id).or_default().push((*conn, addr, link));
        }
        let urgent = command.urgent();
        for mut links in by_node.into_values() {
            links.sort_unstable_by_key(|(conn, _, _)| std::cmp::Reverse(*conn));
            let mut last = None;
            for (_, addr, link) in &links {
                match link.for_command(command).try_send(envelope.clone()) {
                    Ok(()) => {
                        last = None;
                        break;
                    }
                    Err(e) => last = Some((*addr, e)),
                }
            }
            if let Some((addr, e)) = last {
                let counter = if urgent {
                    &self.stats.dropped_urgent
                } else {
                    &self.stats.dropped_bulk
                };
                // The first drop of a class is logged; the counters show the rest.
                if counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                    warn!("[P2P] Dropping broadcast for peer {}: {}", addr, e);
                }
            }
        }
        Ok(())
    }
}

pub struct P2PNetwork {
    bind_addr: SocketAddr,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    cmd_tx: mpsc::Sender<MeshCommand>,
    max_connections: usize,
    shutdown_rx: watch::Receiver<bool>,
    registry: PeerRegistry,
}

impl P2PNetwork {
    pub fn new(
        bind_addr: SocketAddr,
        node_id: u64,
        crypto: Arc<NodeCrypto>,
        cmd_tx: mpsc::Sender<MeshCommand>,
        max_connections: usize,
        shutdown_rx: watch::Receiver<bool>,
        registry: PeerRegistry,
    ) -> Self {
        Self {
            bind_addr,
            node_id,
            crypto,
            cmd_tx,
            max_connections,
            shutdown_rx,
            registry,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .context("Failed to bind P2P listener")?;
        self.serve(listener).await
    }

    pub async fn serve(&self, listener: TcpListener) -> Result<()> {
        info!(
            "[P2P] Mesh listener active on {} ({} pinned peers)",
            listener.local_addr()?,
            self.registry.pinned_peers()
        );

        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        let admission = Admission::default();
        let mut shutdown_rx = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("[P2P] Shutdown signal received. Stopping P2P listener.");
                        break;
                    }
                }

                accept_result = listener.accept() => {
                    let (stream, peer_addr) = match accept_result {
                        Ok(val) => val,
                        Err(e) => {
                            error!("[P2P] Failed to accept peer connection: {}", e);
                            continue;
                        }
                    };

                    let Some(ticket) = admission.admit(peer_addr.ip()) else {
                        self.registry.stats.handshakes_refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        debug!("[P2P] Too many unauthenticated connections; refusing {}", peer_addr);
                        continue;
                    };
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!("[P2P] Max connections ({}) reached. Rejecting peer {}", self.max_connections, peer_addr);
                            continue;
                        }
                    };

                    debug!("[P2P] Accepted connection from {}", peer_addr);
                    let node_id = self.node_id;
                    let crypto = self.crypto.clone();
                    let cmd_tx = self.cmd_tx.clone();
                    let registry = self.registry.clone();

                    tokio::spawn(async move {
                        if let Err(e) = run_connection(stream, peer_addr, node_id, crypto, cmd_tx, registry, Some(ticket)).await {
                            warn!("[P2P] Connection with {} closed: {:#}", peer_addr, e);
                        }
                        drop(permit);
                    });
                }
            }
        }

        info!("[P2P] P2P network listener stopped gracefully.");
        Ok(())
    }
}

pub async fn connect_to_peer(
    peer_addr: SocketAddr,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    registry: PeerRegistry,
    cmd_tx: mpsc::Sender<MeshCommand>,
) -> Result<()> {
    let stream = TcpStream::connect(peer_addr)
        .await
        .context(format!("Failed to connect to outbound peer {}", peer_addr))?;
    info!("[P2P] Connected to outbound peer: {}", peer_addr);
    run_connection(stream, peer_addr, node_id, crypto, cmd_tx, registry, None).await
}

/// Delay before the next dial: doubles from 1 s up to 30 s, and starts over after a connection
/// that stayed up for at least 30 s.
pub fn next_backoff(previous: Duration, connection_lived: Duration) -> Duration {
    const MIN: Duration = Duration::from_secs(1);
    const MAX: Duration = Duration::from_secs(30);
    if connection_lived >= MAX {
        MIN
    } else {
        (previous * 2).clamp(MIN, MAX)
    }
}

/// Keeps a connection to a seed peer for the life of the process: dials, and after a failed
/// dial or a dropped connection dials again with back-off. Without this a peer that was not up
/// yet at start, or a link that failed once, stayed disconnected for good.
pub async fn maintain_peer_connection(
    peer_addr: SocketAddr,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    registry: PeerRegistry,
    cmd_tx: mpsc::Sender<MeshCommand>,
) {
    let mut backoff = Duration::ZERO;
    loop {
        let started = std::time::Instant::now();
        match connect_to_peer(
            peer_addr,
            node_id,
            crypto.clone(),
            registry.clone(),
            cmd_tx.clone(),
        )
        .await
        {
            Ok(()) => info!("[P2P] Connection to seed peer {} closed", peer_addr),
            Err(e) => debug!("[P2P] Seed peer {} unreachable: {:#}", peer_addr, e),
        }
        backoff = next_backoff(backoff, started.elapsed());
        tokio::time::sleep(backoff).await;
    }
}

/// Both sides announce themselves with a signed handshake. The peer is registered for
/// broadcasts only once its own handshake authenticated against the trust store.
async fn run_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    cmd_tx: mpsc::Sender<MeshCommand>,
    registry: PeerRegistry,
    ticket: Option<HandshakeTicket>,
) -> Result<()> {
    // Mesh messages are small and latency-sensitive.
    let _ = stream.set_nodelay(true);
    let (mut reader, writer) = stream.into_split();
    let (tx, rx) = mpsc::channel::<SecureEnvelope>(URGENT_QUEUE);
    let (bulk_tx, bulk_rx) = mpsc::channel::<SecureEnvelope>(BULK_QUEUE);
    let link = PeerLink {
        urgent: tx.clone(),
        bulk: bulk_tx,
    };

    let handshake = seal(&crypto, node_id, &NetworkMessage::handshake(node_id))?;
    tx.send(handshake).await?;

    let conn_id = NEXT_CONNECTION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut writer_task =
        spawn_peer_writer(rx, bulk_rx, writer, peer_addr, registry.clone(), conn_id);

    // The connection ends as a whole, whichever side stops first. Reader done (EOF, a rejected
    // envelope): stop the writer too, which drops its half of the socket, so the peer sees the
    // end and redials. Left running, the writer and the ping loop kept the socket open and the
    // peer never noticed. Writer done (a write timed out): stop reading from a dead link.
    let result = tokio::select! {
        r = handle_reader_loop(
            &mut reader,
            peer_addr,
            node_id,
            crypto.clone(),
            cmd_tx,
            registry.clone(),
            link,
            conn_id,
            ticket,
        ) => r,
        _ = &mut writer_task => Err(anyhow::anyhow!("writing to {} stopped", peer_addr)),
    };
    writer_task.abort();
    registry.remove_peer(&peer_addr, conn_id).await;
    result
}

fn spawn_peer_writer(
    mut rx: mpsc::Receiver<SecureEnvelope>,
    mut bulk_rx: mpsc::Receiver<SecureEnvelope>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    peer_addr: SocketAddr,
    registry: PeerRegistry,
    conn_id: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // Urgent first; bulk only when nothing urgent is waiting.
            let envelope = tokio::select! {
                biased;
                Some(e) = rx.recv() => e,
                Some(e) = bulk_rx.recv() => e,
                else => break,
            };
            let payload = envelope.encode();

            // One write per frame: a separate write of the 4-byte length made the payload wait
            // for the peer's (delayed) ACK under Nagle, adding a round trip to every message.
            let mut frame = Vec::with_capacity(4 + payload.len());
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(&payload);
            if !matches!(
                timeout(Duration::from_secs(5), writer.write_all(&frame)).await,
                Ok(Ok(()))
            ) {
                warn!("[P2P] Write failed to peer {}", peer_addr);
                break;
            }
        }
        registry.remove_peer(&peer_addr, conn_id).await;
    })
}

fn spawn_ping_loop(ping_tx: mpsc::Sender<SecureEnvelope>, node_id: u64, crypto: Arc<NodeCrypto>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            match seal(&crypto, node_id, &NetworkMessage::Ping) {
                Ok(env) => {
                    if ping_tx.send(env).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("[P2P] Failed to seal ping: {:#}", e);
                    break;
                }
            }
        }
    });
}

async fn handle_reader_loop(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    peer_addr: SocketAddr,
    local_node_id: u64,
    crypto: Arc<NodeCrypto>,
    cmd_tx: mpsc::Sender<MeshCommand>,
    registry: PeerRegistry,
    link: PeerLink,
    conn_id: u64,
    mut ticket: Option<HandshakeTicket>,
) -> Result<()> {
    let writer_tx = link.urgent.clone();
    use std::sync::atomic::Ordering;
    let mut len_buf = [0u8; 4];
    let mut authenticated_peer: Option<u64> = None;
    let handshake_deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let (mut frames, mut bytes) = (
        Bucket::new(registry.frame_limit.0, registry.frame_limit.1),
        Bucket::new(BYTES_PER_SEC, BYTE_BURST),
    );

    loop {
        // Until it authenticates, a connection gets HANDSHAKE_TIMEOUT in all; after, 30 s of
        // silence (heartbeats come every 10 s).
        let deadline = match authenticated_peer {
            None => handshake_deadline,
            Some(_) => tokio::time::Instant::now() + Duration::from_secs(30),
        };
        match tokio::time::timeout_at(deadline, reader.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e))
                if e.kind() == ErrorKind::UnexpectedEof
                    || e.kind() == ErrorKind::ConnectionReset =>
            {
                debug!("[P2P] Peer {} disconnected", peer_addr);
                return Ok(());
            }
            Ok(Err(e)) => bail!("read error: {}", e),
            Err(_) if authenticated_peer.is_none() => {
                registry
                    .stats
                    .handshake_timeouts
                    .fetch_add(1, Ordering::Relaxed);
                bail!("no handshake within {:?}", HANDSHAKE_TIMEOUT)
            }
            Err(_) => bail!("heartbeat/read timeout"),
        }

        let payload_len = u32::from_be_bytes(len_buf) as usize;
        if payload_len > MAX_FRAME_BYTES {
            bail!("frame of {} bytes exceeds limit", payload_len);
        }

        // An authenticated peer is paced: past its budget the reader waits (TCP slows the peer).
        if authenticated_peer.is_some() {
            let now = std::time::Instant::now();
            let wait = frames
                .take(1.0, now)
                .max(bytes.take(payload_len as f64, now));
            if !wait.is_zero() {
                registry
                    .stats
                    .frames_delayed
                    .fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(wait).await;
            }
        }

        let mut payload = vec![0u8; payload_len];
        let frame_deadline = match authenticated_peer {
            None => handshake_deadline,
            Some(_) => tokio::time::Instant::now() + Duration::from_secs(5),
        };
        match tokio::time::timeout_at(frame_deadline, reader.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => bail!("read error: {}", e),
            Err(_) => bail!("timeout reading frame"),
        }

        let envelope = match SecureEnvelope::decode(&payload) {
            Ok(envelope) => envelope,
            Err(e) => {
                error!("[P2P] Closing connection from {}: {}", peer_addr, e);
                bail!("{}", e);
            }
        };

        if let Some(peer_id) = authenticated_peer {
            if envelope.sender_id != peer_id {
                bail!(
                    "connection authenticated as node {} sent an envelope claiming node {}",
                    peer_id,
                    envelope.sender_id
                );
            }
        }

        let net_msg = match registry.open(&envelope) {
            Ok(msg) => msg,
            Err(EnvelopeError::Replay) => {
                warn!(
                    "[P2P] Replayed envelope from {} (node {}, nonce {}) ignored",
                    peer_addr, envelope.sender_id, envelope.nonce
                );
                continue;
            }
            Err(e) => {
                error!(
                    "[SECURITY ALERT] Rejected envelope from {} claiming node {}: {:?}",
                    peer_addr, envelope.sender_id, e
                );
                bail!("unauthenticated envelope: {:?}", e);
            }
        };

        match (authenticated_peer, net_msg) {
            (
                None,
                NetworkMessage::Handshake {
                    node_id,
                    wire_min,
                    wire_max,
                },
            ) => {
                let version = match negotiate(wire_min, wire_max) {
                    Ok(v) => v,
                    Err(why) => {
                        error!(
                            "[P2P] Closing connection from {} (node {}): {}",
                            peer_addr, node_id, why
                        );
                        bail!("{}", why);
                    }
                };
                debug!(
                    "[P2P] Node {} at {}: mesh protocol v{}",
                    node_id, peer_addr, version
                );
                // Authenticated: its handshake slot goes back to the pool.
                drop(ticket.take());
                if node_id != envelope.sender_id {
                    bail!(
                        "handshake node_id {} differs from signer {}",
                        node_id,
                        envelope.sender_id
                    );
                }
                if node_id == local_node_id {
                    bail!("peer presented this node's own identity");
                }
                authenticated_peer = Some(node_id);
                registry
                    .add_peer(peer_addr, link.clone(), node_id, conn_id)
                    .await;
                spawn_ping_loop(writer_tx.clone(), local_node_id, crypto.clone());
            }
            (None, _) => bail!("first message was not a handshake"),
            (Some(_), NetworkMessage::Handshake { .. }) => {
                debug!("[P2P] Ignoring repeated handshake from {}", peer_addr);
            }
            (Some(peer_id), NetworkMessage::Command(command)) => {
                // A peer speaks only for itself: its own load (else it could fake other nodes
                // and tip the cluster into or out of a storm), its own block decisions and its
                // own retractions (ADR-1: nobody takes back another node's decision).
                if let Some(claimed) = command.claimed_sender() {
                    if claimed != peer_id {
                        bail!("node {} sent a command claiming node {}", peer_id, claimed);
                    }
                }
                // R26-01: a snapshot carries only the sender's own claims; a relay could
                // otherwise present claims (and quorum votes) in other nodes' names.
                if let MeshCommand::BlockSync { claims, .. } = &command {
                    if let Some(c) = claims.iter().find(|c| c.issuer != peer_id) {
                        bail!(
                            "node {} sent a snapshot carrying a claim of node {}",
                            peer_id,
                            c.issuer
                        );
                    }
                }
                // Only this node's own storm latch may switch its defense mode.
                if matches!(
                    command,
                    MeshCommand::LocalDetection { .. }
                        | MeshCommand::EngageDefense
                        | MeshCommand::DisengageDefense
                ) {
                    bail!("node {} sent a local-only command", peer_id);
                }
                if let Err(e) = cmd_tx.send(command).await {
                    bail!("local orchestrator channel closed: {}", e);
                }
            }
            (Some(_), NetworkMessage::Ping) => {
                let pong = seal(&crypto, local_node_id, &NetworkMessage::Pong)?;
                let _ = writer_tx.send(pong).await;
            }
            (Some(_), NetworkMessage::Pong) => debug!("[P2P] Received Pong from {}", peer_addr),
            (Some(_), NetworkMessage::Ack) => debug!("[P2P] Received ACK from {}", peer_addr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command that names no sender, for transport tests.
    fn alert(text: &str) -> MeshCommand {
        MeshCommand::Alert {
            level: crate::mesh_sync::AlertLevel::Info,
            message: text.to_string(),
        }
    }

    fn block_cmd(ip: &str) -> NetworkMessage {
        NetworkMessage::Command(alert(ip))
    }

    /// Both classes into one queue (tests that do not care about priority).
    fn one_queue(tx: mpsc::Sender<SecureEnvelope>) -> PeerLink {
        PeerLink {
            urgent: tx.clone(),
            bulk: tx,
        }
    }

    fn trust_with(node_id: u64, crypto: &NodeCrypto) -> TrustStore {
        let mut trust = TrustStore::default();
        trust.insert(node_id, crypto.public_key.clone());
        trust
    }

    #[test]
    fn peers_file_envelopes_are_parsed_and_checked() {
        let dir = std::env::temp_dir().join(format!("sokol-envelope-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = NodeCrypto::generate().public_key_hex();
        let path = dir.join("peers.json");
        let write = |body: String| std::fs::write(&path, body).unwrap();
        write(format!(
            r#"[{{"node_id": 2, "public_key": "{k}", "envelope": {{"max_active": 10, "min_prefix_v4": 24}}}},
               {{"node_id": 3, "public_key": "{k}"}}]"#,
            k = key
        ));
        let store = TrustStore::load(&path).unwrap();
        assert_eq!(
            store.envelopes().get(&2),
            Some(&EnvelopeSpec {
                max_active: Some(10),
                min_prefix_v4: Some(24),
                ..Default::default()
            })
        );
        assert!(!store.envelopes().contains_key(&3));
        write(format!(
            r#"[{{"node_id": 2, "public_key": "{}", "envelope": {{"max_actve": 10}}}}]"#,
            key
        ));
        assert!(
            TrustStore::load(&path).is_err(),
            "a misspelt limit must not be ignored"
        );
        write(format!(
            r#"[{{"node_id": 2, "public_key": "{}", "envelope": {{"min_prefix_v4": 33}}}}]"#,
            key
        ));
        assert!(TrustStore::load(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn pinned_peer_envelope_opens() {
        let peer = NodeCrypto::generate();
        let trust = trust_with(7, &peer);
        let env = seal(&peer, 7, &block_cmd("10.0.0.9")).unwrap();
        let msg = open(&trust, &mut ReplayGuard::default(), &env, now_ms()).unwrap();
        assert!(matches!(
            msg,
            NetworkMessage::Command(MeshCommand::Alert { .. })
        ));
    }

    /// ADR-6: only this node's own storm latch may switch its defense mode; a pinned peer that
    /// sends EngageDefense is disconnected before the command reaches the node.
    #[tokio::test]
    async fn a_peer_cannot_switch_this_nodes_defense_mode() {
        let server = Arc::new(NodeCrypto::generate());
        let friend = Arc::new(NodeCrypto::generate());
        let mut trust = TrustStore::default();
        trust.insert(2, friend.public_key.clone());
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            cmd_tx,
            8,
            shutdown_rx,
            PeerRegistry::new(trust),
        );
        tokio::spawn(async move { net.serve(listener).await });
        for (msg, delivered) in [
            (NetworkMessage::Command(MeshCommand::EngageDefense), false),
            (
                NetworkMessage::Command(MeshCommand::DisengageDefense),
                false,
            ),
            (block_cmd("still heard"), true),
        ] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            for m in [NetworkMessage::handshake(2), msg] {
                let env = seal(&friend, 2, &m).unwrap();
                let bytes = env.encode();
                let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
                let _ = stream.write_all(&bytes).await;
            }
            let got = timeout(Duration::from_millis(500), cmd_rx.recv()).await;
            match (got, delivered) {
                (Ok(Some(MeshCommand::Alert { .. })), true) => {}
                (Err(_), false) => {}
                (other, _) => panic!("unexpected delivery: {:?}", other.is_ok()),
            }
        }
    }

    /// R26-02: every snapshot message, sealed and framed for real, fits the receiver's frame
    /// limit, whatever the mix of claims (with maximal reasons) and tombstones; nothing is lost
    /// or duplicated across messages.
    #[tokio::test]
    async fn every_snapshot_frame_fits_the_frame_limit() {
        use crate::block_table::{Claim, ClaimKind, MAX_REASON_BYTES};
        use crate::mesh_sync::pack_snapshot;
        let crypto = NodeCrypto::generate();
        let claim = |i: u32| Claim {
            issuer: 1,
            kind: ClaimKind::Detector,
            target: format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
            issued_ms: 1_700_000_000_000 + i as u64,
            expires_ms: Some(1_800_000_000_000),
            reason: "r".repeat(MAX_REASON_BYTES),
        };
        let cases: Vec<(Vec<Claim>, Vec<String>)> = vec![
            (vec![], vec![]),
            (vec![claim(1)], vec![]),
            (vec![], (0..2500).map(|i| format!("{:064x}", i)).collect()),
            (
                (0..3000).map(claim).collect(),
                (0..3000).map(|i| format!("{:064x}", i)).collect(),
            ),
        ];
        for (claims, ids) in cases {
            let msgs = pack_snapshot(1, claims.clone(), ids.clone());
            assert!(!msgs.is_empty());
            let (mut got_claims, mut got_ids) = (Vec::new(), Vec::new());
            for m in msgs {
                let env = seal(&crypto, 1, &NetworkMessage::Command(m.clone())).unwrap();
                let frame = env.encode();
                assert!(
                    frame.len() <= MAX_FRAME_BYTES,
                    "frame of {} bytes over the {} limit",
                    frame.len(),
                    MAX_FRAME_BYTES
                );
                if let MeshCommand::BlockSync {
                    claims, retracted, ..
                } = m
                {
                    got_claims.extend(claims);
                    got_ids.extend(retracted);
                }
            }
            assert_eq!(got_claims, claims);
            assert_eq!(got_ids, ids);
        }
    }

    /// R26-01 at the ingress boundary: one pinned peer cannot present claims in other nodes'
    /// names in a snapshot (it would forge quorum votes); its own snapshot is delivered.
    #[tokio::test]
    async fn a_snapshot_with_claims_of_other_nodes_is_refused() {
        use crate::block_table::{Claim, ClaimKind};
        let server = Arc::new(NodeCrypto::generate());
        let friend = Arc::new(NodeCrypto::generate());
        let mut trust = TrustStore::default();
        trust.insert(2, friend.public_key.clone());
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            cmd_tx,
            8,
            shutdown_rx,
            PeerRegistry::new(trust),
        );
        tokio::spawn(async move { net.serve(listener).await });

        let claim = |issuer: u64| Claim {
            issuer,
            kind: ClaimKind::Detector,
            target: "198.51.96.0/20".into(),
            issued_ms: 1,
            expires_ms: Some(2),
            reason: "t".into(),
        };
        let forged: Vec<Claim> = (3..103).map(claim).collect();
        for (claims, delivered) in [(forged, false), (vec![claim(2)], true)] {
            let msg = NetworkMessage::Command(MeshCommand::BlockSync {
                issuer: 2,
                claims,
                retracted: vec![],
            });
            let mut stream = TcpStream::connect(addr).await.unwrap();
            for m in [NetworkMessage::handshake(2), msg] {
                let env = seal(&friend, 2, &m).unwrap();
                let bytes = env.encode();
                let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
                let _ = stream.write_all(&bytes).await;
            }
            let got = timeout(Duration::from_millis(500), cmd_rx.recv()).await;
            match (got, delivered) {
                (Ok(Some(MeshCommand::BlockSync { claims, .. })), true) => {
                    assert!(claims.iter().all(|c| c.issuer == 2))
                }
                (Err(_), false) => {}
                (other, _) => panic!("delivered={}: unexpected {:?}", delivered, other.is_ok()),
            }
        }
    }

    /// ADR-1 at the transport: a pinned peer may send its own block decisions, not another
    /// node's; a claim naming someone else closes the connection before it reaches the node.
    #[tokio::test]
    async fn a_peer_cannot_send_claims_in_another_nodes_name() {
        use crate::block_table::{Claim, ClaimKind};
        let server = Arc::new(NodeCrypto::generate());
        let friend = Arc::new(NodeCrypto::generate());
        let mut trust = TrustStore::default();
        trust.insert(2, friend.public_key.clone());
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            cmd_tx,
            8,
            shutdown_rx,
            PeerRegistry::new(trust),
        );
        tokio::spawn(async move { net.serve(listener).await });

        let claim = |issuer: u64| {
            NetworkMessage::Command(MeshCommand::Claim {
                claim: Claim {
                    issuer,
                    kind: ClaimKind::Detector,
                    target: "203.0.113.9".into(),
                    issued_ms: 1,
                    expires_ms: Some(2),
                    reason: "t".into(),
                },
            })
        };
        for (issuer, delivered) in [(3, false), (2, true)] {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            for msg in [NetworkMessage::handshake(2), claim(issuer)] {
                let env = seal(&friend, 2, &msg).unwrap();
                let bytes = env.encode();
                let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
                let _ = stream.write_all(&bytes).await;
            }
            let got = timeout(Duration::from_millis(500), cmd_rx.recv()).await;
            match (got, delivered) {
                (Ok(Some(MeshCommand::Claim { claim })), true) => assert_eq!(claim.issuer, 2),
                (Err(_), false) => {}
                (other, _) => panic!("issuer {}: unexpected {:?}", issuer, other.is_ok()),
            }
        }
    }

    #[tokio::test]
    async fn stranger_key_is_rejected_even_with_valid_signature() {
        let pinned = NodeCrypto::generate();
        let stranger = NodeCrypto::generate();
        let trust = trust_with(7, &pinned);
        let env = seal(&stranger, 7, &block_cmd("10.0.0.9")).unwrap();
        assert_eq!(
            open(&trust, &mut ReplayGuard::default(), &env, now_ms()).unwrap_err(),
            EnvelopeError::BadSignature
        );
        let env = seal(&stranger, 666, &block_cmd("10.0.0.9")).unwrap();
        assert_eq!(
            open(&trust, &mut ReplayGuard::default(), &env, now_ms()).unwrap_err(),
            EnvelopeError::UnknownSender
        );
    }

    #[tokio::test]
    async fn header_fields_are_covered_by_the_signature() {
        let peer = NodeCrypto::generate();
        let trust = trust_with(7, &peer);
        let env = seal(&peer, 7, &block_cmd("10.0.0.9")).unwrap();

        let mut new_nonce = env.clone();
        new_nonce.nonce ^= 1;
        let mut new_time = env.clone();
        new_time.timestamp_ms += 1;
        let mut new_payload = env.clone();
        new_payload.payload = serde_json::to_vec(&block_cmd("10.0.0.10")).unwrap();

        for tampered in [new_nonce, new_time, new_payload] {
            assert_eq!(
                open(&trust, &mut ReplayGuard::default(), &tampered, now_ms()).unwrap_err(),
                EnvelopeError::BadSignature
            );
        }
    }

    #[tokio::test]
    async fn replay_and_stale_envelopes_are_rejected() {
        let peer = NodeCrypto::generate();
        let trust = trust_with(7, &peer);
        let env = seal(&peer, 7, &block_cmd("10.0.0.9")).unwrap();
        let mut guard = ReplayGuard::default();
        assert!(open(&trust, &mut guard, &env, now_ms()).is_ok());
        assert_eq!(
            open(&trust, &mut guard, &env, now_ms()).unwrap_err(),
            EnvelopeError::Replay
        );

        let later = env.timestamp_ms + MAX_CLOCK_SKEW_MS + 1;
        assert_eq!(
            open(&trust, &mut ReplayGuard::default(), &env, later).unwrap_err(),
            EnvelopeError::StaleTimestamp
        );
    }

    /// Every refusal is counted under its reason: a peer whose clock is out of the window shows
    /// up as `stale_timestamp`, not only in the log.
    #[tokio::test]
    async fn refused_envelopes_are_counted_by_reason() {
        use std::sync::atomic::Ordering;
        let peer = NodeCrypto::generate();
        let registry = PeerRegistry::new(trust_with(7, &peer));
        let count = |label: &str| {
            let slot = EnvelopeError::LABELS
                .iter()
                .position(|l| *l == label)
                .unwrap();
            registry.stats.rejected[slot].load(Ordering::Relaxed)
        };
        let env = seal(&peer, 7, &block_cmd("10.0.0.9")).unwrap();
        let later = env.timestamp_ms + MAX_CLOCK_SKEW_MS + 1;
        assert_eq!(
            registry.open_at(&env, later).unwrap_err(),
            EnvelopeError::StaleTimestamp
        );
        assert!(registry.open_at(&env, env.timestamp_ms).is_ok());
        assert_eq!(
            registry.open_at(&env, env.timestamp_ms).unwrap_err(),
            EnvelopeError::Replay
        );
        let stranger = seal(&NodeCrypto::generate(), 9, &block_cmd("10.0.0.9")).unwrap();
        assert!(registry.open(&stranger).is_err());
        assert_eq!(
            (
                count("stale_timestamp"),
                count("replay"),
                count("unknown_sender")
            ),
            (1, 1, 1)
        );
        assert_eq!(count("bad_signature") + count("malformed_payload"), 0);
    }

    #[test]
    fn key_file_round_trips_and_rejects_loose_permissions() {
        let dir = std::env::temp_dir().join(format!("sokol-key-test-{}", rand::random::<u64>()));
        let path = dir.join("node.key");
        let created = NodeCrypto::load_or_create(&path).unwrap();
        let loaded = NodeCrypto::load_or_create(&path).unwrap();
        assert_eq!(created.public_key.encode(), loaded.public_key.encode());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(NodeCrypto::load_or_create(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn trust_store_parses_hex_keys_and_rejects_duplicates() {
        let peer = NodeCrypto::generate();
        let dir = std::env::temp_dir().join(format!("sokol-peers-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");

        let one = format!(
            r#"[{{"node_id": 2, "public_key": "{}"}}]"#,
            peer.public_key_hex()
        );
        std::fs::write(&path, &one).unwrap();
        let store = TrustStore::load(&path).unwrap();
        assert_eq!(store.get(2).unwrap()[0].encode(), peer.public_key.encode());

        let dup = format!(
            r#"[{{"node_id": 2, "public_key": "{0}"}}, {{"node_id": 2, "public_key": "{0}"}}]"#,
            peer.public_key_hex()
        );
        std::fs::write(&path, dup).unwrap();
        assert!(TrustStore::load(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn rotation_accepts_old_and_new_keys_then_revokes_the_old_one() {
        let old = NodeCrypto::generate();
        let new = NodeCrypto::generate();
        let dir = std::env::temp_dir().join(format!("sokol-rotate-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");

        std::fs::write(
            &path,
            format!(
                r#"[{{"node_id": 2, "public_keys": ["{}", "{}"]}}]"#,
                old.public_key_hex(),
                new.public_key_hex()
            ),
        )
        .unwrap();
        let registry = PeerRegistry::new(TrustStore::load(&path).unwrap());
        for signer in [&old, &new] {
            let env = seal(signer, 2, &block_cmd("10.0.0.2")).unwrap();
            assert!(
                registry.open(&env).is_ok(),
                "both keys are valid during the rotation"
            );
        }

        std::fs::write(
            &path,
            format!(
                r#"[{{"node_id": 2, "public_key": "{}"}}]"#,
                new.public_key_hex()
            ),
        )
        .unwrap();
        assert_eq!(registry.reload(TrustStore::load(&path).unwrap()), 1);
        let env = seal(&old, 2, &block_cmd("10.0.0.2")).unwrap();
        assert_eq!(
            registry.open(&env).unwrap_err(),
            EnvelopeError::BadSignature,
            "old key revoked"
        );
        let env = seal(&new, 2, &block_cmd("10.0.0.2")).unwrap();
        assert!(registry.open(&env).is_ok());

        std::fs::write(&path, r#"[{"node_id": 3}]"#).unwrap();
        assert!(
            TrustStore::load(&path).is_err(),
            "an entry needs at least one key"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// End-to-end over TCP: a stranger that signs its own handshake and command must not reach
    /// the orchestrator, while a pinned peer's command must.
    #[tokio::test]
    async fn only_pinned_peers_can_deliver_commands_over_the_network() {
        let server = Arc::new(NodeCrypto::generate());
        let friend = Arc::new(NodeCrypto::generate());
        let stranger = Arc::new(NodeCrypto::generate());

        let mut trust = TrustStore::default();
        trust.insert(2, friend.public_key.clone());
        let registry = PeerRegistry::new(trust);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(addr, 1, server, cmd_tx, 8, shutdown_rx, registry);
        tokio::spawn(async move { net.serve(listener).await });

        async fn send_as(crypto: &NodeCrypto, id: u64, addr: SocketAddr, ip: &str) {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            for msg in [NetworkMessage::handshake(id), block_cmd(ip)] {
                let bytes = seal(crypto, id, &msg).unwrap().encode();
                let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
                let _ = stream.write_all(&bytes).await;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        send_as(&stranger, 666, addr, "10.0.0.66").await;
        send_as(&stranger, 2, addr, "10.0.0.67").await;
        assert!(
            cmd_rx.try_recv().is_err(),
            "stranger's command reached the orchestrator"
        );

        send_as(&friend, 2, addr, "10.0.0.2").await;
        match timeout(Duration::from_secs(2), cmd_rx.recv()).await {
            Ok(Some(MeshCommand::Alert { message, .. })) => assert_eq!(message, "10.0.0.2"),
            other => panic!(
                "pinned peer's command was not delivered: {:?}",
                other.is_ok()
            ),
        }
    }

    /// Two pinned nodes, one dialing the other: broadcasts must flow in both directions.
    #[tokio::test]
    async fn outbound_connection_carries_broadcasts_both_ways() {
        let n1 = Arc::new(NodeCrypto::generate());
        let n2 = Arc::new(NodeCrypto::generate());
        let registry_for = |peer_id: u64, peer: &NodeCrypto| {
            let mut trust = TrustStore::default();
            trust.insert(peer_id, peer.public_key.clone());
            PeerRegistry::new(trust)
        };
        let (reg1, reg2) = (registry_for(2, &n2), registry_for(1, &n1));
        let (tx1, mut rx1) = mpsc::channel(8);
        let (tx2, mut rx2) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(addr, 1, n1.clone(), tx1, 8, shutdown_rx, reg1.clone());
        tokio::spawn(async move { net.serve(listener).await });
        let (n2c, reg2c) = (n2.clone(), reg2.clone());
        tokio::spawn(async move { connect_to_peer(addr, 2, n2c, reg2c, tx2).await });
        tokio::time::sleep(Duration::from_millis(500)).await;

        let cmd = alert;
        reg1.broadcast(&cmd("10.0.0.21"), 1, &n1).await.unwrap();
        reg2.broadcast(&cmd("10.0.0.12"), 2, &n2).await.unwrap();

        for (rx, want) in [(&mut rx2, "10.0.0.21"), (&mut rx1, "10.0.0.12")] {
            match timeout(Duration::from_secs(2), rx.recv()).await {
                Ok(Some(MeshCommand::Alert { message, .. })) => assert_eq!(message, want),
                _ => panic!("broadcast for {} was not delivered", want),
            }
        }
    }

    #[tokio::test]
    async fn a_stale_connection_cannot_unregister_its_replacement() {
        let registry = PeerRegistry::new(TrustStore::default());
        let addr: SocketAddr = "127.0.0.1:7946".parse().unwrap();
        let (old_tx, _old_rx) = mpsc::channel(1);
        let (new_tx, _new_rx) = mpsc::channel(1);
        registry.add_peer(addr, one_queue(old_tx), 2, 1).await;
        registry.add_peer(addr, one_queue(new_tx), 2, 2).await;
        registry.remove_peer(&addr, 1).await;
        assert_eq!(
            registry.peer_count().await,
            1,
            "old connection 1 must not remove connection 2"
        );
        registry.remove_peer(&addr, 2).await;
        assert_eq!(registry.peer_count().await, 0);
    }

    /// Two nodes that list each other as seeds hold two connections, one dialed by each. That is
    /// still one peer: counted once, and sent each broadcast once.
    #[tokio::test]
    async fn two_connections_to_one_node_are_one_peer() {
        let registry = PeerRegistry::new(TrustStore::default());
        let crypto = NodeCrypto::generate();
        let (in_tx, mut in_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel(8);
        registry
            .add_peer("10.0.0.2:41000".parse().unwrap(), one_queue(in_tx), 2, 1)
            .await;
        registry
            .add_peer("10.0.0.2:7946".parse().unwrap(), one_queue(out_tx), 2, 2)
            .await;
        assert_eq!(registry.peer_count().await, 1, "one node, two connections");

        registry
            .broadcast(&alert("203.0.113.1"), 1, &crypto)
            .await
            .unwrap();
        let mut delivered = 0;
        while in_rx.try_recv().is_ok() || out_rx.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, 1, "the node gets the broadcast once");
    }

    /// When one of a node's connections is stuck, its broadcast goes over the other.
    #[tokio::test]
    async fn broadcast_uses_another_connection_when_one_is_stuck() {
        let registry = PeerRegistry::new(TrustStore::default());
        let crypto = NodeCrypto::generate();
        let (ok_tx, mut ok_rx) = mpsc::channel(8);
        let (stuck_tx, _stuck_rx) = mpsc::channel(1);
        stuck_tx
            .try_send(seal(&crypto, 1, &NetworkMessage::Ping).unwrap())
            .unwrap();
        for (port, link, conn) in [(41000, ok_tx, 1), (7946, stuck_tx, 2)] {
            registry
                .add_peer(
                    format!("10.0.0.2:{port}").parse().unwrap(),
                    one_queue(link),
                    2,
                    conn,
                )
                .await;
        }
        registry
            .broadcast(&alert("203.0.113.1"), 1, &crypto)
            .await
            .unwrap();
        assert!(
            ok_rx.try_recv().is_ok(),
            "delivered over the healthy connection"
        );
        assert_eq!(
            registry
                .stats
                .dropped_bulk
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "not counted as dropped"
        );
    }

    /// A peer whose queue is full must not block a broadcast to everyone else.
    #[tokio::test]
    async fn broadcast_does_not_wait_for_a_stuck_peer() {
        let registry = PeerRegistry::new(TrustStore::default());
        let crypto = NodeCrypto::generate();
        let (stuck_tx, _stuck_rx) = mpsc::channel(1);
        let (ok_tx, mut ok_rx) = mpsc::channel(8);
        registry
            .add_peer("127.0.0.1:1".parse().unwrap(), one_queue(stuck_tx), 2, 1)
            .await;
        registry
            .add_peer("127.0.0.1:2".parse().unwrap(), one_queue(ok_tx), 3, 2)
            .await;
        let cmd = alert("203.0.113.1");
        for _ in 0..3 {
            timeout(
                Duration::from_millis(500),
                registry.broadcast(&cmd, 1, &crypto),
            )
            .await
            .expect("broadcast blocked on a stuck peer")
            .unwrap();
        }
        let mut delivered = 0;
        while ok_rx.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, 3, "the healthy peer still gets every message");
    }

    /// One pinned peer sending as fast as its frame limit allows must not fill the replay memory
    /// for everyone: before, one shared 100 000-entry cache refused every sender once full.
    #[test]
    fn one_sender_cannot_crowd_out_another_in_the_replay_memory() {
        let mut guard = ReplayGuard::default();
        let now = 1_000_000_000;
        let mut accepted = 0usize;
        for nonce in 0..100_000u64 {
            if guard.check_and_record(7, nonce, now, now) {
                accepted += 1;
            }
        }
        assert!(
            guard.check_and_record(8, 1, now, now),
            "another sender is still accepted"
        );
        assert!(
            accepted < 100_000,
            "a single sender is bounded ({accepted} accepted)"
        );
        assert!(
            !guard.check_and_record(8, 1, now, now),
            "a resend is still refused"
        );
    }

    /// Entries leave the window oldest first, a resend inside the window is refused, and memory
    /// empties once the window has passed.
    #[test]
    fn replay_memory_expires_by_arrival_and_keeps_its_window() {
        let mut guard = ReplayGuard::default();
        let t = 1_000_000_000;
        assert!(guard.check_and_record(7, 1, t, t));
        assert!(
            !guard.check_and_record(7, 1, t, t + 59_000),
            "a resend within the window"
        );
        assert!(guard.check_and_record(7, 2, t + 30_000, t + 30_000));
        // 60 s after its arrival the first entry is gone; the second is not yet.
        assert!(guard.check_and_record(7, 1, t + 60_000, t + 60_000));
        assert!(!guard.check_and_record(7, 2, t + 60_000, t + 60_000));
        assert!(guard.check_and_record(7, 9, t + 200_000, t + 200_000));
        assert_eq!(
            guard.remembered(),
            1,
            "only the last one is still remembered"
        );
    }

    #[tokio::test]
    async fn heartbeat_messages_seal_and_open() {
        let peer = NodeCrypto::generate();
        let trust = trust_with(7, &peer);
        let mut guard = ReplayGuard::default();
        for msg in [
            NetworkMessage::Ping,
            NetworkMessage::Pong,
            NetworkMessage::Ack,
        ] {
            let env = seal(&peer, 7, &msg).expect("heartbeats must be sealable");
            assert!(open(&trust, &mut guard, &env, now_ms()).is_ok());
        }
    }

    /// A pinned peer that pings gets a pong back over the same connection.
    #[tokio::test]
    async fn ping_is_answered_with_pong() {
        let server = Arc::new(NodeCrypto::generate());
        let peer = NodeCrypto::generate();
        let mut trust = TrustStore::default();
        trust.insert(2, peer.public_key.clone());
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server.clone(),
            cmd_tx,
            8,
            shutdown_rx,
            PeerRegistry::new(trust),
        );
        tokio::spawn(async move { net.serve(listener).await });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        for msg in [NetworkMessage::handshake(2), NetworkMessage::Ping] {
            let bytes = seal(&peer, 2, &msg).unwrap().encode();
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&bytes).await.unwrap();
        }
        let mut server_trust = TrustStore::default();
        server_trust.insert(1, server.public_key.clone());
        let mut guard = ReplayGuard::default();
        for _ in 0..3 {
            let mut len = [0u8; 4];
            timeout(Duration::from_secs(2), stream.read_exact(&mut len))
                .await
                .unwrap()
                .unwrap();
            let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
            stream.read_exact(&mut buf).await.unwrap();
            let env = SecureEnvelope::decode(&buf).unwrap();
            if let Ok(NetworkMessage::Pong) = open(&server_trust, &mut guard, &env, now_ms()) {
                return;
            }
        }
        panic!("no pong after the ping");
    }

    #[test]
    fn backoff_grows_to_a_cap_and_resets_after_a_stable_connection() {
        let s = Duration::from_secs;
        let mut b = Duration::ZERO;
        let mut seen = Vec::new();
        for _ in 0..7 {
            b = next_backoff(b, s(0));
            seen.push(b.as_secs());
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(
            next_backoff(s(30), s(45)),
            s(1),
            "a connection that lived resets the delay"
        );
    }

    /// A dialer started before its peer keeps trying and connects once the peer is up.
    #[tokio::test]
    async fn seed_connection_is_retried_until_the_peer_comes_up() {
        let a = Arc::new(NodeCrypto::generate());
        let b = Arc::new(NodeCrypto::generate());
        let mut trust_a = TrustStore::default();
        trust_a.insert(2, b.public_key.clone());
        let mut trust_b = TrustStore::default();
        trust_b.insert(1, a.public_key.clone());
        let reg_a = PeerRegistry::new(trust_a);

        // Reserve a port, then free it: the peer is "not up yet".
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let (tx_a, _rx_a) = mpsc::channel(8);
        tokio::spawn(maintain_peer_connection(
            addr,
            1,
            a.clone(),
            reg_a.clone(),
            tx_a,
        ));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(reg_a.peer_count().await, 0);

        let listener = TcpListener::bind(addr).await.unwrap();
        let (tx_b, _rx_b) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let net = P2PNetwork::new(addr, 2, b, tx_b, 8, shutdown_rx, PeerRegistry::new(trust_b));
        tokio::spawn(async move { net.serve(listener).await });

        for _ in 0..60 {
            if reg_a.peer_count().await == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the dialer never reconnected after the peer came up");
    }

    /// A peer may report only its own telemetry.
    #[tokio::test]
    async fn telemetry_must_describe_the_sender() {
        let server = Arc::new(NodeCrypto::generate());
        let peer = NodeCrypto::generate();
        let mut trust = TrustStore::default();
        trust.insert(2, peer.public_key.clone());
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            cmd_tx,
            8,
            shutdown_rx,
            PeerRegistry::new(trust),
        );
        tokio::spawn(async move { net.serve(listener).await });

        let report = |node_id| {
            NetworkMessage::Command(MeshCommand::Telemetry {
                node_id,
                rx_pps: 1,
                drops_per_sec: 5000,
                under_attack: true,
                blocks_active: 0,
            })
        };
        let mut stream = TcpStream::connect(addr).await.unwrap();
        for msg in [NetworkMessage::handshake(2), report(2), report(9)] {
            let bytes = seal(&peer, 2, &msg).unwrap().encode();
            let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
            let _ = stream.write_all(&bytes).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        match cmd_rx.try_recv() {
            Ok(MeshCommand::Telemetry { node_id: 2, .. }) => {}
            other => panic!("own telemetry should arrive: {:?}", other.is_ok()),
        }
        assert!(
            cmd_rx.try_recv().is_err(),
            "telemetry for node 9 from node 2 must be rejected"
        );
    }

    /// A connection authenticated as one pinned peer cannot carry another peer's envelopes.
    #[tokio::test]
    async fn connection_is_bound_to_its_handshake_identity() {
        let server = Arc::new(NodeCrypto::generate());
        let a = NodeCrypto::generate();
        let b = NodeCrypto::generate();
        let mut trust = TrustStore::default();
        trust.insert(2, a.public_key.clone());
        trust.insert(3, b.public_key.clone());
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            cmd_tx,
            8,
            shutdown_rx,
            PeerRegistry::new(trust),
        );
        tokio::spawn(async move { net.serve(listener).await });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let frames = [
            seal(&a, 2, &NetworkMessage::handshake(2)).unwrap(),
            seal(&b, 3, &block_cmd("10.0.0.3")).unwrap(),
        ];
        for env in frames {
            let bytes = env.encode();
            let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
            let _ = stream.write_all(&bytes).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            cmd_rx.try_recv().is_err(),
            "envelope from node 3 accepted on node 2's connection"
        );
    }

    // ---- Wire format v2 and ML-DSA ----

    #[tokio::test]
    async fn every_byte_of_a_v2_envelope_is_covered() {
        // Flipping any single byte of the frame (magic, version, header, payload or signature)
        // must never yield an accepted message.
        let peer = NodeCrypto::generate();
        let trust = trust_with(7, &peer);
        let frame = seal(&peer, 7, &NetworkMessage::Ping).unwrap().encode();
        let accepted = |bytes: &[u8]| {
            SecureEnvelope::decode(bytes)
                .ok()
                .and_then(|env| open(&trust, &mut ReplayGuard::default(), &env, now_ms()).ok())
                .is_some()
        };
        assert!(accepted(&frame), "control: the untouched frame opens");
        for i in 0..frame.len() {
            let mut bad = frame.clone();
            bad[i] ^= 0x01;
            assert!(
                !accepted(&bad),
                "byte {} of {} is not covered",
                i,
                frame.len()
            );
        }
        assert!(!accepted(&frame[..frame.len() - 1]), "truncated signature");
    }

    #[tokio::test]
    async fn a_signature_made_for_another_context_does_not_verify() {
        use ml_dsa::Signer;
        let peer = NodeCrypto::generate();
        let trust = trust_with(7, &peer);
        let mut env = seal(&peer, 7, &NetworkMessage::Ping).unwrap();
        let unsigned = unsigned_bytes(
            env.version,
            env.sender_id,
            env.timestamp_ms,
            env.nonce,
            &env.payload,
        );
        // The same bytes signed with the empty context (what a generic Signer does).
        let plain: Signature<MlDsa65> = peer.signing_key.sign(&unsigned);
        env.signature = plain.encode().to_vec();
        assert_eq!(
            open(&trust, &mut ReplayGuard::default(), &env, now_ms()).unwrap_err(),
            EnvelopeError::BadSignature
        );
    }

    #[test]
    fn frames_of_other_protocol_versions_are_named() {
        // A v1 frame is a bincode envelope: it starts with the sender id (u64 LE).
        let mut v1 = 2u64.to_le_bytes().to_vec();
        v1.extend_from_slice(&[0u8; 64]);
        assert_eq!(SecureEnvelope::decode(&v1), Err(WireError::Legacy));
        assert_eq!(SecureEnvelope::decode(b""), Err(WireError::Legacy));
        assert_eq!(
            SecureEnvelope::decode(b"SKM\x03rest"),
            Err(WireError::Unsupported(3))
        );
        assert_eq!(
            SecureEnvelope::decode(b"SKM\x02short"),
            Err(WireError::Malformed("short header"))
        );
        let mut long_payload = b"SKM\x02".to_vec();
        long_payload.extend_from_slice(&[0u8; 24]);
        long_payload.extend_from_slice(&1000u32.to_le_bytes());
        assert_eq!(
            SecureEnvelope::decode(&long_payload),
            Err(WireError::Malformed("payload longer than the frame"))
        );
        assert!(WireError::Legacy.to_string().contains("upgrade the peer"));
    }

    #[test]
    fn the_highest_common_version_is_chosen_or_the_peer_refused() {
        assert_eq!(negotiate(2, 2), Ok(2));
        assert_eq!(negotiate(1, 9), Ok(WIRE_VERSION_MAX));
        assert!(negotiate(WIRE_VERSION_MAX + 1, WIRE_VERSION_MAX + 3).is_err());
        assert!(negotiate(0, WIRE_VERSION_MIN - 1).is_err());
        assert!(negotiate(3, 2).is_err(), "an empty range");
        let why = negotiate(7, 8).unwrap_err();
        assert!(why.contains("peer speaks v7..v8"), "{}", why);
    }

    #[tokio::test]
    async fn a_peer_without_a_common_version_is_disconnected() {
        let server = Arc::new(NodeCrypto::generate());
        let peer = NodeCrypto::generate();
        let mut trust = TrustStore::default();
        trust.insert(2, peer.public_key.clone());
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server.clone(),
            cmd_tx,
            8,
            shutdown_rx,
            PeerRegistry::new(trust),
        );
        tokio::spawn(async move { net.serve(listener).await });

        // Speaks only v3..v4, then pings; a node that accepted it would answer with a pong.
        let future = NetworkMessage::Handshake {
            node_id: 2,
            wire_min: WIRE_VERSION_MAX + 1,
            wire_max: WIRE_VERSION_MAX + 2,
        };
        let mut stream = TcpStream::connect(addr).await.unwrap();
        for msg in [future, NetworkMessage::Ping] {
            let bytes = seal(&peer, 2, &msg).unwrap().encode();
            let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
            let _ = stream.write_all(&bytes).await;
        }
        let mut server_trust = TrustStore::default();
        server_trust.insert(1, server.public_key.clone());
        let mut guard = ReplayGuard::default();
        loop {
            let mut len = [0u8; 4];
            match timeout(Duration::from_secs(3), stream.read_exact(&mut len)).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => return, // closed by the node: refused
                Err(_) => panic!("the connection stayed open"),
            }
            let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
            if stream.read_exact(&mut buf).await.is_err() {
                return;
            }
            let env = SecureEnvelope::decode(&buf).unwrap();
            assert!(
                !matches!(
                    open(&server_trust, &mut guard, &env, now_ms()),
                    Ok(NetworkMessage::Pong)
                ),
                "a peer without a common version was served"
            );
        }
    }

    #[test]
    fn a_legacy_key_file_is_retired_and_a_new_identity_created() {
        let dir = std::env::temp_dir().join(format!("sokol-legacy-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key");
        std::fs::write(&path, vec![7u8; LEGACY_KEY_FILE_LEN]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let created = NodeCrypto::load_or_create(&path).unwrap();
        let retired = dir.join("node.key.dilithium3.retired");
        assert_eq!(
            std::fs::read(&retired).unwrap(),
            vec![7u8; LEGACY_KEY_FILE_LEN]
        );
        let stored = std::fs::read(&path).unwrap();
        assert_eq!(&stored[..4], KEY_FILE_MAGIC, "the new key file is v2");
        assert_eq!(stored.len(), 36);
        let again = NodeCrypto::load_or_create(&path).unwrap();
        assert_eq!(
            created.public_key_hex(),
            again.public_key_hex(),
            "same identity after"
        );
        assert!(created.public_key_hex().starts_with(KEY_PREFIX));

        std::fs::write(&path, b"SKK2short").unwrap();
        assert!(
            NodeCrypto::load_or_create(&path).is_err(),
            "a malformed file is an error"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_peer_keys_are_not_trusted_but_do_not_stop_the_node() {
        let a = NodeCrypto::generate();
        let dir = std::env::temp_dir().join(format!("sokol-legacy-peers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");
        let legacy = "ab".repeat(1952);
        std::fs::write(
            &path,
            format!(
                r#"[{{"node_id": 2, "public_key": "{legacy}"}},
                    {{"node_id": 3, "public_keys": ["{legacy}", "{a}"]}}]"#,
                legacy = legacy,
                a = a.public_key_hex()
            ),
        )
        .unwrap();
        let store = TrustStore::load(&path).unwrap();
        assert!(store.get(2).is_none(), "a legacy-only peer is not trusted");
        assert_eq!(store.legacy_peers(), &[2]);
        assert_eq!(
            store.get(3).map(|k| k.len()),
            Some(1),
            "its ML-DSA key is used"
        );

        std::fs::write(
            &path,
            format!(r#"[{{"node_id": 4, "public_key": "{}ab"}}]"#, KEY_PREFIX),
        )
        .unwrap();
        assert!(
            TrustStore::load(&path).is_err(),
            "a malformed v2 key is still an error"
        );
        assert!(parse_public_key(&a.public_key_hex()).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cost of one seal and one open (ML-DSA-65 sign and verify); run with --ignored --nocapture.
    #[tokio::test]
    #[ignore]
    async fn measure_seal_and_open() {
        let peer = NodeCrypto::generate();
        let trust = trust_with(7, &peer);
        let msg = block_cmd("10.0.0.9");
        let n = 500;
        let t = std::time::Instant::now();
        let mut envs = Vec::new();
        for _ in 0..n {
            envs.push(seal(&peer, 7, &msg).unwrap());
        }
        let sealed = t.elapsed();
        let t = std::time::Instant::now();
        let mut guard = ReplayGuard::default();
        for env in &envs {
            open(&trust, &mut guard, env, now_ms()).unwrap();
        }
        let opened = t.elapsed();
        println!(
            "seal {:.0} us, open {:.0} us (mean of {})",
            sealed.as_micros() as f64 / n as f64,
            opened.as_micros() as f64 / n as f64,
            n
        );
    }

    // ---- R27-01/02/06 ----

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4096))]
        /// R27-01: any text in a key position is an error or a key, never a panic.
        #[test]
        fn no_key_text_panics(text in proptest::prelude::any::<String>(), prefixed in proptest::prelude::any::<bool>()) {
            let text = if prefixed { format!("{}{}", KEY_PREFIX, text) } else { text };
            let _ = parse_public_key(&text);
            let _ = classify_key(&text);
            let _ = from_hex(&text);
        }
    }

    #[test]
    fn multibyte_characters_in_a_key_are_an_error() {
        for text in ["mldsa65:a€", "mldsa65:€€", "mldsa65:ab\u{e9}\u{e9}", "€€"] {
            assert!(parse_public_key(text).is_err(), "{}", text);
            assert!(classify_key(text).is_err(), "{}", text);
        }
        assert!(from_hex("a€").is_err());
        assert_eq!(from_hex("0aFf").unwrap(), vec![0x0a, 0xff]);
    }

    fn peers_file(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sokol-r27-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn a_mistyped_prefix_is_an_error_not_a_legacy_key() {
        let a = NodeCrypto::generate();
        let typo = a.public_key_hex().replacen("mldsa65:", "mldsa6S:", 1);
        let path = peers_file(
            "typo",
            &format!(r#"[{{"node_id": 2, "public_key": "{}"}}]"#, typo),
        );
        assert!(
            TrustStore::load(&path).is_err(),
            "R27-02: a typo was taken for a legacy key"
        );
        let path = peers_file("garbage", r#"[{"node_id": 2, "public_key": "abcd"}]"#);
        assert!(TrustStore::load(&path).is_err());
    }

    #[test]
    fn duplicate_ids_are_refused_even_when_one_is_legacy() {
        let a = NodeCrypto::generate();
        let legacy = "ab".repeat(1952);
        let path = peers_file(
            "dup",
            &format!(
                r#"[{{"node_id": 2, "public_key": "{}"}}, {{"node_id": 2, "public_key": "{}"}}]"#,
                legacy,
                a.public_key_hex()
            ),
        );
        assert!(TrustStore::load(&path).is_err());
    }

    #[test]
    fn a_reload_cannot_demote_a_trusted_peer_to_a_legacy_key() {
        let a = NodeCrypto::generate();
        let registry = PeerRegistry::new(trust_with(2, &a));
        let path = peers_file(
            "demote",
            &format!(
                r#"[{{"node_id": 2, "public_key": "{}"}}]"#,
                "ab".repeat(1952)
            ),
        );
        let candidate = TrustStore::load(&path).unwrap();
        assert!(registry.check_candidate(&candidate).is_err());
        assert!(registry.trusts(2), "the refused candidate changed nothing");
        let path = peers_file(
            "new-legacy",
            &format!(
                r#"[{{"node_id": 9, "public_key": "{}"}}]"#,
                "ab".repeat(1952)
            ),
        );
        assert!(
            registry
                .check_candidate(&TrustStore::load(&path).unwrap())
                .is_ok(),
            "an untrusted peer may still be listed with its old key during an upgrade"
        );
    }

    #[test]
    fn migration_never_overwrites_an_existing_backup() {
        let dir = std::env::temp_dir().join(format!("sokol-r27-06-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key");
        let backup = dir.join("node.key.dilithium3.retired");
        std::fs::write(&backup, b"an earlier backup").unwrap();
        std::fs::write(
            dir.join("node.key.new"),
            b"left by an interrupted migration",
        )
        .unwrap();
        std::fs::write(&path, vec![5u8; LEGACY_KEY_FILE_LEN]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let created = NodeCrypto::load_or_create(&path).unwrap();
        assert_eq!(
            std::fs::read(&backup).unwrap(),
            b"an earlier backup",
            "R27-06: backup clobbered"
        );
        assert_eq!(
            std::fs::read(dir.join("node.key.dilithium3.retired.1")).unwrap(),
            vec![5u8; LEGACY_KEY_FILE_LEN],
            "the legacy key is kept under the next free name"
        );
        assert!(!dir.join("node.key.new").exists());
        assert_eq!(
            NodeCrypto::load_or_create(&path).unwrap().public_key_hex(),
            created.public_key_hex()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- Resource limits ----

    #[test]
    fn a_bucket_allows_its_burst_then_paces() {
        let t0 = std::time::Instant::now();
        let mut b = Bucket::new(10.0, 3.0);
        for _ in 0..3 {
            assert_eq!(b.take(1.0, t0), Duration::ZERO);
        }
        let wait = b.take(1.0, t0);
        assert!((wait.as_secs_f64() - 0.1).abs() < 1e-6, "{:?}", wait);
        assert_eq!(
            b.take(0.0, t0 + Duration::from_millis(100)),
            Duration::ZERO,
            "repaid"
        );
        assert_eq!(
            Bucket::new(10.0, 3.0).take(0.0, t0 + Duration::from_secs(60)),
            Duration::ZERO,
            "idle time refills only up to the burst"
        );
    }

    #[test]
    fn pending_handshakes_are_bounded_per_address_and_in_total() {
        let a: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let admission = Admission::new(3);
        let t1 = admission.admit(a).unwrap();
        let _t2 = admission.admit(a).unwrap();
        assert!(admission.admit(a).is_none(), "a third from one address");
        let _t3 = admission.admit("192.0.2.2".parse().unwrap()).unwrap();
        assert!(
            admission.admit("192.0.2.3".parse().unwrap()).is_none(),
            "total reached"
        );
        drop(t1);
        assert!(
            admission.admit(a).is_some(),
            "an authenticated (or closed) one frees its slot"
        );
    }

    async fn listening_node() -> (
        SocketAddr,
        PeerRegistry,
        NodeCrypto,
        mpsc::Receiver<MeshCommand>,
        watch::Sender<bool>,
    ) {
        listening_node_with(|r| r).await
    }

    async fn listening_node_with(
        configure: impl FnOnce(PeerRegistry) -> PeerRegistry,
    ) -> (
        SocketAddr,
        PeerRegistry,
        NodeCrypto,
        mpsc::Receiver<MeshCommand>,
        watch::Sender<bool>,
    ) {
        let server = Arc::new(NodeCrypto::generate());
        let peer = NodeCrypto::generate();
        let registry = configure(PeerRegistry::new(trust_with(2, &peer)));
        let (cmd_tx, cmd_rx) = mpsc::channel(10_000);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(addr, 1, server, cmd_tx, 100, shutdown_rx, registry.clone());
        tokio::spawn(async move { net.serve(listener).await });
        (addr, registry, peer, cmd_rx, shutdown_tx)
    }

    /// A connection whose peer sent an envelope that does not authenticate is closed in both
    /// directions. Before, only the reader stopped: the writer and its ping loop kept the socket
    /// open, the peer kept receiving pings and never redialled, and only noticed when its own
    /// writes backed up minutes later (seen as a node not rejoining after its clock was fixed).
    #[tokio::test]
    async fn a_rejected_envelope_closes_the_connection_both_ways() {
        let (addr, _registry, peer, _rx, _stop) = listening_node().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let send = |env: SecureEnvelope| {
            let bytes = env.encode();
            let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&bytes);
            frame
        };
        let hello = seal(&peer, 2, &NetworkMessage::handshake(2)).unwrap();
        stream.write_all(&send(hello)).await.unwrap();
        let mut bad = seal(&peer, 2, &block_cmd("10.0.0.9")).unwrap();
        if let Some(b) = bad.signature.first_mut() {
            *b ^= 1;
        }
        stream.write_all(&send(bad)).await.unwrap();
        // The node's handshake and pings may arrive first; then the stream must end.
        let mut buf = [0u8; 8192];
        let closed = timeout(Duration::from_secs(5), async {
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => continue,
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "the node kept the rejected connection open");
    }

    #[tokio::test]
    async fn silent_connections_cannot_hold_the_node() {
        use std::sync::atomic::Ordering;
        let (addr, registry, _peer, _rx, _stop) = listening_node().await;
        let silent1 = TcpStream::connect(addr).await.unwrap();
        let silent2 = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        // A third from the same address is refused at once: the node closes it.
        let mut third = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let closed = timeout(Duration::from_secs(2), third.read(&mut buf)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "the third was served"
        );
        assert_eq!(registry.stats.handshakes_refused.load(Ordering::Relaxed), 1);
        // The silent ones are closed after HANDSHAKE_TIMEOUT.
        let started = std::time::Instant::now();
        for mut s in [silent1, silent2] {
            loop {
                match timeout(HANDSHAKE_TIMEOUT * 2, s.read(&mut [0u8; 8192])).await {
                    Ok(Ok(0)) | Ok(Err(_)) => break,
                    Ok(Ok(_)) => continue, // the node's own handshake
                    Err(_) => panic!("a silent connection stayed open"),
                }
            }
        }
        assert!(started.elapsed() < HANDSHAKE_TIMEOUT + Duration::from_secs(2));
        assert_eq!(registry.stats.handshake_timeouts.load(Ordering::Relaxed), 2);
    }

    /// Past its burst a peer is paced, not cut off or dropped: every frame arrives, some late.
    /// Run with a small limit, so the pacing path is reached on any machine (with the real
    /// 500/s and 5 000 burst, a slow debug build verified frames slower than the refill and
    /// never paced them; signing thousands of frames also outlasted their freshness window).
    #[tokio::test]
    async fn a_fast_peer_is_paced_not_dropped() {
        use std::sync::atomic::Ordering;
        assert_eq!(
            PeerRegistry::new(TrustStore::default()).frame_limit,
            (FRAMES_PER_SEC, FRAME_BURST),
            "production nodes use the ADR-0013 limit"
        );
        let (per_sec, burst, n) = (20.0, 20.0, 60usize);
        let (addr, registry, peer, mut rx, _stop) =
            listening_node_with(|r| r.with_frame_limit(per_sec, burst)).await;
        let mut frames = vec![seal(&peer, 2, &NetworkMessage::handshake(2))
            .unwrap()
            .encode()];
        for i in 0..n {
            let target = format!("10.1.0.{}", i);
            frames.push(seal(&peer, 2, &block_cmd(&target)).unwrap().encode());
        }
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let started = std::time::Instant::now();
        let writer = tokio::spawn(async move {
            for bytes in frames {
                let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
                frame.extend_from_slice(&bytes);
                stream.write_all(&frame).await.unwrap();
            }
            stream
        });
        let mut got = 0;
        while got < n {
            match timeout(Duration::from_secs(10), rx.recv()).await {
                Ok(Some(_)) => got += 1,
                _ => panic!("only {} of {} commands arrived", got, n),
            }
        }
        let took = started.elapsed();
        let _stream = writer.await.unwrap();
        assert!(
            registry.stats.frames_delayed.load(Ordering::Relaxed) > 0,
            "past the burst, frames must be paced"
        );
        // 61 frames (with the handshake) against a burst of 20 at 20/s: about 2 s.
        assert!(
            took >= Duration::from_millis(1_500),
            "paced frames take their time ({:?})",
            took
        );
    }

    /// Costs behind the resource contract (ADR-0013); run with --ignored --nocapture.
    #[test]
    #[ignore]
    fn measure_resource_costs() {
        use crate::block_table::{Claim, ClaimKind, MAX_REASON_BYTES};
        use crate::mesh_sync::pack_snapshot;
        let peer = NodeCrypto::generate();
        let trust = trust_with(1, &peer);
        let claim = |i: u32, reason: usize| Claim {
            issuer: 1,
            kind: ClaimKind::Detector,
            target: format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
            issued_ms: now_ms(),
            expires_ms: Some(now_ms() + 3_600_000),
            reason: "r".repeat(reason),
        };
        // 1. The largest frame an authenticated peer can send: a full snapshot frame.
        let big = pack_snapshot(
            1,
            (0..3000).map(|i| claim(i, MAX_REASON_BYTES)).collect(),
            vec![],
        );
        let env = seal(&peer, 1, &NetworkMessage::Command(big[0].clone())).unwrap();
        let frame = env.encode();
        let n = 50;
        let t = std::time::Instant::now();
        for _ in 0..n {
            let e = SecureEnvelope::decode(&frame).unwrap();
            let _ = open(&trust, &mut ReplayGuard::default(), &e, now_ms()).unwrap();
        }
        println!(
            "open of a {} KiB snapshot frame: {:.2} ms",
            frame.len() / 1024,
            t.elapsed().as_secs_f64() * 1000.0 / n as f64
        );
        // 2. One answer to SyncRequest at the claim cap: pack and seal every frame.
        for count in [1_000u32, 65_536] {
            let claims: Vec<Claim> = (0..count).map(|i| claim(i, 40)).collect();
            let t = std::time::Instant::now();
            let msgs = pack_snapshot(1, claims, vec![]);
            let mut bytes = 0;
            for m in &msgs {
                bytes += seal(&peer, 1, &NetworkMessage::Command(m.clone()))
                    .unwrap()
                    .encode()
                    .len();
            }
            println!(
                "snapshot of {} claims: {} frames, {} KiB, {:.1} ms to pack and sign",
                count,
                msgs.len(),
                bytes / 1024,
                t.elapsed().as_secs_f64() * 1000.0
            );
        }
        // 3. A stranger's 128 KiB frame: decoded, refused on the unknown sender.
        let mut stranger = env.clone();
        stranger.sender_id = 99;
        stranger.payload = vec![b' '; MAX_FRAME_BYTES - 4000];
        let frame = stranger.encode();
        let n = 1000;
        let t = std::time::Instant::now();
        for _ in 0..n {
            let e = SecureEnvelope::decode(&frame).unwrap();
            assert!(open(&trust, &mut ReplayGuard::default(), &e, now_ms()).is_err());
        }
        println!(
            "refusing a stranger's {} KiB frame: {:.1} us",
            frame.len() / 1024,
            t.elapsed().as_secs_f64() * 1e6 / n as f64
        );
    }

    #[tokio::test]
    async fn claims_go_first_and_reports_are_dropped_first() {
        use crate::block_table::{Claim, ClaimKind};
        use std::sync::atomic::Ordering;
        let registry = PeerRegistry::new(TrustStore::default());
        let crypto = NodeCrypto::generate();
        let (urgent, mut urgent_rx) = mpsc::channel(4);
        let (bulk, mut bulk_rx) = mpsc::channel(2);
        registry
            .add_peer(
                "127.0.0.1:9".parse().unwrap(),
                PeerLink { urgent, bulk },
                2,
                1,
            )
            .await;
        // The link is saturated with reports: the bulk queue is full, further ones are dropped.
        for i in 0..5 {
            registry
                .broadcast(&alert(&format!("report {}", i)), 1, &crypto)
                .await
                .unwrap();
        }
        assert_eq!(registry.stats.dropped_bulk.load(Ordering::Relaxed), 3);
        // A block decision still gets through, in its own queue.
        let claim = MeshCommand::Claim {
            claim: Claim {
                issuer: 1,
                kind: ClaimKind::Detector,
                target: "203.0.113.9".into(),
                issued_ms: now_ms(),
                expires_ms: Some(now_ms() + 60_000),
                reason: "x".into(),
            },
        };
        registry.broadcast(&claim, 1, &crypto).await.unwrap();
        assert_eq!(registry.stats.dropped_urgent.load(Ordering::Relaxed), 0);
        assert!(
            urgent_rx.try_recv().is_ok(),
            "the claim is queued as urgent"
        );
        assert_eq!(bulk_rx.try_recv().map(|_| ()), Ok(()));
    }

    #[tokio::test]
    async fn the_writer_empties_the_urgent_queue_first() {
        let crypto = NodeCrypto::generate();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let (_r, w) = client.into_split();
        let (urgent, urgent_rx) = mpsc::channel(8);
        let (bulk, bulk_rx) = mpsc::channel(8);
        // Queue bulk first, then urgent, before the writer starts.
        for text in ["bulk 1", "bulk 2"] {
            bulk.send(seal(&crypto, 1, &block_cmd(text)).unwrap())
                .await
                .unwrap();
        }
        urgent
            .send(seal(&crypto, 1, &NetworkMessage::Ping).unwrap())
            .await
            .unwrap();
        let registry = PeerRegistry::new(TrustStore::default());
        spawn_peer_writer(urgent_rx, bulk_rx, w, addr, registry, 1);
        let mut len = [0u8; 4];
        server.read_exact(&mut len).await.unwrap();
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        server.read_exact(&mut buf).await.unwrap();
        let first = SecureEnvelope::decode(&buf).unwrap();
        let msg: NetworkMessage = serde_json::from_slice(&first.payload).unwrap();
        assert!(
            matches!(msg, NetworkMessage::Ping),
            "bulk went before urgent: {:?}",
            msg
        );
    }
}
