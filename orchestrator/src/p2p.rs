#![allow(clippy::too_many_arguments)]
//! Sovereign mesh transport.
//!
//! Trust model: a node accepts messages only from peers whose ML-DSA/Dilithium public key is
//! pinned in its trust store (`--peers-file`). Every envelope is signed over its full header
//! (sender, timestamp, nonce) and payload, must fall inside a clock-skew window and is accepted
//! at most once. A connection is bound to the identity announced in its first (handshake)
//! envelope; any later envelope from a different sender closes the connection.
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
use tokio::sync::{mpsc, watch, Mutex, RwLock, Semaphore};
use tokio::time::timeout;

use pqcrypto_dilithium::dilithium3::{
    detached_sign, keypair as dilithium_keypair, verify_detached_signature,
    DetachedSignature as DilithiumSignature, PublicKey as DilithiumPublic,
    SecretKey as DilithiumSecret,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

use crate::MeshCommand;
use common::canonical::CanonicalParser;

const ENVELOPE_DOMAIN: &[u8] = b"sokol-mesh-envelope-v1\0";
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;
const MAX_REPLAY_ENTRIES: usize = 100_000;
pub const MAX_FRAME_BYTES: usize = 128 * 1024;

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
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        bail!("hex string has odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex digit"))
        .collect()
}

pub struct NodeCrypto {
    pub public_key: DilithiumPublic,
    secret_key: DilithiumSecret,
}

impl NodeCrypto {
    pub fn generate() -> Self {
        let (pk, sk) = dilithium_keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Loads the node identity from `path`, creating it (mode 0600) on first start so the
    /// node keeps the same identity across restarts and stays pinned in its peers' trust stores.
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
                Self::from_key_bytes(&bytes)
                    .with_context(|| format!("node key file {} is malformed", path.display()))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let crypto = Self::generate();
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .with_context(|| {
                        format!("failed to create node key file {}", path.display())
                    })?;
                file.write_all(crypto.public_key.as_bytes())?;
                file.write_all(crypto.secret_key.as_bytes())?;
                file.sync_all()?;
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

    fn from_key_bytes(bytes: &[u8]) -> Result<Self> {
        let pk_len = pqcrypto_dilithium::dilithium3::public_key_bytes();
        let sk_len = pqcrypto_dilithium::dilithium3::secret_key_bytes();
        if bytes.len() != pk_len + sk_len {
            bail!("expected {} bytes, found {}", pk_len + sk_len, bytes.len());
        }
        let (public, secret) = bytes
            .split_at_checked(pk_len)
            .ok_or_else(|| anyhow::anyhow!("key file too short"))?;
        let public_key = DilithiumPublic::from_bytes(public)
            .map_err(|e| anyhow::anyhow!("invalid public key: {:?}", e))?;
        let secret_key = DilithiumSecret::from_bytes(secret)
            .map_err(|e| anyhow::anyhow!("invalid secret key: {:?}", e))?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    pub fn public_key_hex(&self) -> String {
        to_hex(self.public_key.as_bytes())
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        detached_sign(message, &self.secret_key).as_bytes().to_vec()
    }
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
    keys: HashMap<u64, Vec<DilithiumPublic>>,
    envelopes: HashMap<u64, EnvelopeSpec>,
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
        for entry in entries {
            let id = entry.node_id;
            if store.keys.contains_key(&id) {
                bail!("peers file lists node_id {} more than once", id);
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
            for hex in hexes {
                let bytes =
                    from_hex(hex).with_context(|| format!("peer {}: public key is not hex", id))?;
                let key = DilithiumPublic::from_bytes(&bytes)
                    .map_err(|e| anyhow::anyhow!("peer {}: invalid public key: {:?}", id, e))?;
                keys.push(key);
            }
            store.keys.insert(id, keys);
            if let Some(spec) = entry.envelope {
                if spec.min_prefix_v4.is_some_and(|p| p > 32)
                    || spec.min_prefix_v6.is_some_and(|p| p > 128)
                {
                    bail!("peer {}: envelope prefix length out of range", id);
                }
                store.envelopes.insert(id, spec);
            }
        }
        Ok(store)
    }

    pub fn insert(&mut self, node_id: u64, key: DilithiumPublic) {
        self.keys.entry(node_id).or_default().push(key);
    }

    pub fn get(&self, node_id: u64) -> Option<&[DilithiumPublic]> {
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

    /// Number of pinned nodes.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// Remembers `(sender, nonce)` pairs for as long as their timestamp could still be accepted.
#[derive(Default)]
pub struct ReplayGuard {
    seen: HashMap<(u64, u64), u64>,
}

impl ReplayGuard {
    fn check_and_record(
        &mut self,
        sender_id: u64,
        nonce: u64,
        timestamp_ms: u64,
        now: u64,
    ) -> bool {
        if self.seen.len() >= MAX_REPLAY_ENTRIES / 2 {
            let horizon = now.saturating_sub(2 * MAX_CLOCK_SKEW_MS);
            self.seen.retain(|_, ts| *ts >= horizon);
        }
        if self.seen.len() >= MAX_REPLAY_ENTRIES {
            return false;
        }
        match self.seen.entry((sender_id, nonce)) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(timestamp_ms);
                true
            }
        }
    }
}

pub struct DagTracker {
    tips: std::collections::VecDeque<[u8; 32]>,
}

impl DagTracker {
    pub fn new() -> Self {
        let mut tips = std::collections::VecDeque::new();
        tips.push_back([0u8; 32]);
        Self { tips }
    }

    pub fn get_latest_parents(&self) -> Vec<[u8; 32]> {
        self.tips.iter().take(2).cloned().collect()
    }

    pub fn register_event(&mut self, payload: &[u8]) -> [u8; 32] {
        let hash = *blake3::hash(payload).as_bytes();
        self.tips.push_front(hash);
        if self.tips.len() > 16 {
            self.tips.pop_back();
        }
        hash
    }

    pub fn get_parents_and_register(&mut self, payload: &[u8]) -> (Vec<[u8; 32]>, [u8; 32]) {
        let parents = self.get_latest_parents();
        let hash = self.register_event(payload);
        (parents, hash)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecureEnvelope {
    pub sender_id: u64,
    pub timestamp_ms: u64,
    pub nonce: u64,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub dag_parents: Vec<[u8; 32]>,
}

fn signing_bytes(sender_id: u64, timestamp_ms: u64, nonce: u64, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ENVELOPE_DOMAIN.len() + 32 + payload.len());
    msg.extend_from_slice(ENVELOPE_DOMAIN);
    msg.extend_from_slice(&sender_id.to_le_bytes());
    msg.extend_from_slice(&timestamp_ms.to_le_bytes());
    msg.extend_from_slice(&nonce.to_le_bytes());
    msg.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    msg.extend_from_slice(payload);
    msg
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkMessage {
    Command(MeshCommand),
    Ack,
    Ping,
    Pong,
    Handshake { node_id: u64 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    UnknownSender,
    BadSignature,
    StaleTimestamp,
    Replay,
    MalformedPayload,
}

pub async fn seal(
    crypto: &NodeCrypto,
    sender_id: u64,
    message: &NetworkMessage,
    dag: &Mutex<DagTracker>,
) -> Result<SecureEnvelope> {
    let payload = serde_json::to_vec(message)?;
    let payload_str = std::str::from_utf8(&payload).context("Payload is not valid UTF-8")?;
    check_canonical(payload_str)
        .map_err(|e| anyhow::anyhow!("Canonical validation failed: {:?}", e))?;

    let dag_parents = dag.lock().await.get_parents_and_register(&payload).0;
    let timestamp_ms = now_ms();
    let nonce: u64 = rand::random();
    let signature = crypto.sign(&signing_bytes(sender_id, timestamp_ms, nonce, &payload));

    Ok(SecureEnvelope {
        sender_id,
        timestamp_ms,
        nonce,
        payload,
        signature,
        dag_parents,
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

    let signature = DilithiumSignature::from_bytes(&envelope.signature)
        .map_err(|_| EnvelopeError::BadSignature)?;
    let signed = signing_bytes(
        envelope.sender_id,
        envelope.timestamp_ms,
        envelope.nonce,
        &envelope.payload,
    );
    if !keys
        .iter()
        .any(|key| verify_detached_signature(&signature, &signed, key).is_ok())
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
pub type PeerMap = Arc<RwLock<HashMap<SocketAddr, (mpsc::Sender<SecureEnvelope>, u64, u64)>>>;

static NEXT_CONNECTION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Clone)]
pub struct PeerRegistry {
    peers: PeerMap,
    /// Told the address of every peer that completes its handshake.
    peer_up: Arc<std::sync::Mutex<Option<mpsc::UnboundedSender<SocketAddr>>>>,
    /// Swapped as a whole by `reload`, so a message is checked against one consistent store.
    trust: Arc<std::sync::RwLock<Arc<TrustStore>>>,
    replay: Arc<std::sync::Mutex<ReplayGuard>>,
}

impl PeerRegistry {
    pub fn new(trust: TrustStore) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_up: Arc::new(std::sync::Mutex::new(None)),
            trust: Arc::new(std::sync::RwLock::new(Arc::new(trust))),
            replay: Arc::new(std::sync::Mutex::new(ReplayGuard::default())),
        }
    }

    pub async fn add_peer(
        &self,
        addr: SocketAddr,
        tx: mpsc::Sender<SecureEnvelope>,
        node_id: u64,
        conn_id: u64,
    ) {
        let mut peers = self.peers.write().await;
        peers.insert(addr, (tx, node_id, conn_id));
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
        dag: &Arc<Mutex<DagTracker>>,
    ) -> Result<()> {
        let envelope = seal(
            crypto,
            node_id,
            &NetworkMessage::Command(command.clone()),
            dag,
        )
        .await?;
        let tx = self
            .peers
            .read()
            .await
            .get(&addr)
            .map(|(tx, _, _)| tx.clone())
            .ok_or_else(|| anyhow::anyhow!("peer {} is not connected", addr))?;
        match timeout(Duration::from_secs(2), tx.send(envelope)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(anyhow::anyhow!("peer {} writer closed", addr)),
            Err(_) => Err(anyhow::anyhow!("peer {} queue stayed full for 2 s", addr)),
        }
    }

    /// Replaces the trust store. Connections of peers whose key was removed are closed on
    /// their next envelope, which no longer verifies.
    pub fn reload(&self, trust: TrustStore) -> usize {
        let pinned = trust.len();
        *self.trust.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(trust);
        pinned
    }

    pub fn pinned_peers(&self) -> usize {
        self.trust.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
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
        let mut replay = self.replay.lock().unwrap_or_else(|p| p.into_inner());
        let trust = self.trust.read().unwrap_or_else(|p| p.into_inner()).clone();
        open(&trust, &mut replay, envelope, now_ms())
    }

    pub async fn broadcast(
        &self,
        command: &MeshCommand,
        node_id: u64,
        crypto: &NodeCrypto,
        dag: &Arc<Mutex<DagTracker>>,
    ) -> Result<()> {
        let envelope = seal(
            crypto,
            node_id,
            &NetworkMessage::Command(command.clone()),
            dag,
        )
        .await?;

        // Never wait for a slow or dead peer: a full queue would stall the caller (the main
        // tick, IPC handling) behind one bad link. A peer that misses a block catches up through
        // BlockSync when it reconnects.
        let peers = self.peers.read().await;
        for (addr, (tx, _, _)) in peers.iter() {
            if let Err(e) = tx.try_send(envelope.clone()) {
                warn!("[P2P] Dropping broadcast for peer {}: {}", addr, e);
            }
        }
        Ok(())
    }
}

pub struct P2PNetwork {
    bind_addr: SocketAddr,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    dag: Arc<Mutex<DagTracker>>,
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
        dag: Arc<Mutex<DagTracker>>,
        cmd_tx: mpsc::Sender<MeshCommand>,
        max_connections: usize,
        shutdown_rx: watch::Receiver<bool>,
        registry: PeerRegistry,
    ) -> Self {
        Self {
            bind_addr,
            node_id,
            crypto,
            dag,
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
                    let dag = self.dag.clone();
                    let cmd_tx = self.cmd_tx.clone();
                    let registry = self.registry.clone();

                    tokio::spawn(async move {
                        if let Err(e) = run_connection(stream, peer_addr, node_id, crypto, dag, cmd_tx, registry).await {
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
    dag: Arc<Mutex<DagTracker>>,
    registry: PeerRegistry,
    cmd_tx: mpsc::Sender<MeshCommand>,
) -> Result<()> {
    let stream = TcpStream::connect(peer_addr)
        .await
        .context(format!("Failed to connect to outbound peer {}", peer_addr))?;
    info!("[P2P] Connected to outbound peer: {}", peer_addr);
    run_connection(stream, peer_addr, node_id, crypto, dag, cmd_tx, registry).await
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
    dag: Arc<Mutex<DagTracker>>,
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
            dag.clone(),
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
    dag: Arc<Mutex<DagTracker>>,
    cmd_tx: mpsc::Sender<MeshCommand>,
    registry: PeerRegistry,
) -> Result<()> {
    // Mesh messages are small and latency-sensitive.
    let _ = stream.set_nodelay(true);
    let (mut reader, writer) = stream.into_split();
    let (tx, rx) = mpsc::channel::<SecureEnvelope>(100);

    let handshake = seal(
        &crypto,
        node_id,
        &NetworkMessage::Handshake { node_id },
        &dag,
    )
    .await?;
    tx.send(handshake).await?;

    let conn_id = NEXT_CONNECTION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    spawn_peer_writer(rx, writer, peer_addr, registry.clone(), conn_id);

    let result = handle_reader_loop(
        &mut reader,
        peer_addr,
        node_id,
        crypto.clone(),
        dag.clone(),
        cmd_tx,
        registry.clone(),
        tx,
        conn_id,
    )
    .await;
    registry.remove_peer(&peer_addr, conn_id).await;
    result
}

fn spawn_peer_writer(
    mut rx: mpsc::Receiver<SecureEnvelope>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    peer_addr: SocketAddr,
    registry: PeerRegistry,
    conn_id: u64,
) {
    tokio::spawn(async move {
        while let Some(envelope) = rx.recv().await {
            let payload = match bincode::serialize(&envelope) {
                Ok(p) => p,
                Err(e) => {
                    error!("[P2P] Serialization error for peer {}: {}", peer_addr, e);
                    break;
                }
            };

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
    });
}

fn spawn_ping_loop(
    ping_tx: mpsc::Sender<SecureEnvelope>,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    dag: Arc<Mutex<DagTracker>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            match seal(&crypto, node_id, &NetworkMessage::Ping, &dag).await {
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
    dag: Arc<Mutex<DagTracker>>,
    cmd_tx: mpsc::Sender<MeshCommand>,
    registry: PeerRegistry,
    writer_tx: mpsc::Sender<SecureEnvelope>,
    conn_id: u64,
) -> Result<()> {
    let mut len_buf = [0u8; 4];
    let mut authenticated_peer: Option<u64> = None;

    loop {
        match timeout(Duration::from_secs(30), reader.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e))
                if e.kind() == ErrorKind::UnexpectedEof
                    || e.kind() == ErrorKind::ConnectionReset =>
            {
                debug!("[P2P] Peer {} disconnected", peer_addr);
                return Ok(());
            }
            Ok(Err(e)) => bail!("read error: {}", e),
            Err(_) => bail!("heartbeat/read timeout"),
        }

        let payload_len = u32::from_be_bytes(len_buf) as usize;
        if payload_len > MAX_FRAME_BYTES {
            bail!("frame of {} bytes exceeds limit", payload_len);
        }

        let mut payload = vec![0u8; payload_len];
        match timeout(Duration::from_secs(5), reader.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => bail!("read error: {}", e),
            Err(_) => bail!("timeout reading frame"),
        }

        let envelope: SecureEnvelope =
            bincode::deserialize(&payload).context("undecodable envelope")?;

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
            (None, NetworkMessage::Handshake { node_id }) => {
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
                    .add_peer(peer_addr, writer_tx.clone(), node_id, conn_id)
                    .await;
                spawn_ping_loop(
                    writer_tx.clone(),
                    local_node_id,
                    crypto.clone(),
                    dag.clone(),
                );
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
                let pong = seal(&crypto, local_node_id, &NetworkMessage::Pong, &dag).await?;
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

    fn dag() -> Mutex<DagTracker> {
        Mutex::new(DagTracker::new())
    }

    fn trust_with(node_id: u64, crypto: &NodeCrypto) -> TrustStore {
        let mut trust = TrustStore::default();
        trust.insert(node_id, crypto.public_key);
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
        let env = seal(&peer, 7, &block_cmd("10.0.0.9"), &dag())
            .await
            .unwrap();
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
        trust.insert(2, friend.public_key);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            Arc::new(dag()),
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
            let d = dag();
            for m in [NetworkMessage::Handshake { node_id: 2 }, msg] {
                let env = seal(&friend, 2, &m, &d).await.unwrap();
                let bytes = bincode::serialize(&env).unwrap();
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
        let d = dag();
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
                let env = seal(&crypto, 1, &NetworkMessage::Command(m.clone()), &d)
                    .await
                    .unwrap();
                let frame = bincode::serialize(&env).unwrap();
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
        trust.insert(2, friend.public_key);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            Arc::new(dag()),
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
            let d = dag();
            for m in [NetworkMessage::Handshake { node_id: 2 }, msg] {
                let env = seal(&friend, 2, &m, &d).await.unwrap();
                let bytes = bincode::serialize(&env).unwrap();
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
        trust.insert(2, friend.public_key);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            Arc::new(dag()),
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
            let d = dag();
            for msg in [NetworkMessage::Handshake { node_id: 2 }, claim(issuer)] {
                let env = seal(&friend, 2, &msg, &d).await.unwrap();
                let bytes = bincode::serialize(&env).unwrap();
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
        let env = seal(&stranger, 7, &block_cmd("10.0.0.9"), &dag())
            .await
            .unwrap();
        assert_eq!(
            open(&trust, &mut ReplayGuard::default(), &env, now_ms()).unwrap_err(),
            EnvelopeError::BadSignature
        );
        let env = seal(&stranger, 666, &block_cmd("10.0.0.9"), &dag())
            .await
            .unwrap();
        assert_eq!(
            open(&trust, &mut ReplayGuard::default(), &env, now_ms()).unwrap_err(),
            EnvelopeError::UnknownSender
        );
    }

    #[tokio::test]
    async fn header_fields_are_covered_by_the_signature() {
        let peer = NodeCrypto::generate();
        let trust = trust_with(7, &peer);
        let env = seal(&peer, 7, &block_cmd("10.0.0.9"), &dag())
            .await
            .unwrap();

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
        let env = seal(&peer, 7, &block_cmd("10.0.0.9"), &dag())
            .await
            .unwrap();
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

    #[test]
    fn key_file_round_trips_and_rejects_loose_permissions() {
        let dir = std::env::temp_dir().join(format!("sokol-key-test-{}", rand::random::<u64>()));
        let path = dir.join("node.key");
        let created = NodeCrypto::load_or_create(&path).unwrap();
        let loaded = NodeCrypto::load_or_create(&path).unwrap();
        assert_eq!(created.public_key.as_bytes(), loaded.public_key.as_bytes());

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
        assert_eq!(
            store.get(2).unwrap()[0].as_bytes(),
            peer.public_key.as_bytes()
        );

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
            let env = seal(signer, 2, &block_cmd("10.0.0.2"), &dag())
                .await
                .unwrap();
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
        let env = seal(&old, 2, &block_cmd("10.0.0.2"), &dag()).await.unwrap();
        assert_eq!(
            registry.open(&env).unwrap_err(),
            EnvelopeError::BadSignature,
            "old key revoked"
        );
        let env = seal(&new, 2, &block_cmd("10.0.0.2"), &dag()).await.unwrap();
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
        trust.insert(2, friend.public_key);
        let registry = PeerRegistry::new(trust);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            Arc::new(dag()),
            cmd_tx,
            8,
            shutdown_rx,
            registry,
        );
        tokio::spawn(async move { net.serve(listener).await });

        async fn send_as(crypto: &NodeCrypto, id: u64, addr: SocketAddr, ip: &str) {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let d = dag();
            for msg in [NetworkMessage::Handshake { node_id: id }, block_cmd(ip)] {
                let bytes = bincode::serialize(&seal(crypto, id, &msg, &d).await.unwrap()).unwrap();
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
            trust.insert(peer_id, peer.public_key);
            PeerRegistry::new(trust)
        };
        let (reg1, reg2) = (registry_for(2, &n2), registry_for(1, &n1));
        let (tx1, mut rx1) = mpsc::channel(8);
        let (tx2, mut rx2) = mpsc::channel(8);
        let (dag1, dag2) = (Arc::new(dag()), Arc::new(dag()));
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            n1.clone(),
            dag1.clone(),
            tx1,
            8,
            shutdown_rx,
            reg1.clone(),
        );
        tokio::spawn(async move { net.serve(listener).await });
        let (n2c, dag2c, reg2c) = (n2.clone(), dag2.clone(), reg2.clone());
        tokio::spawn(async move { connect_to_peer(addr, 2, n2c, dag2c, reg2c, tx2).await });
        tokio::time::sleep(Duration::from_millis(500)).await;

        let cmd = alert;
        reg1.broadcast(&cmd("10.0.0.21"), 1, &n1, &dag1)
            .await
            .unwrap();
        reg2.broadcast(&cmd("10.0.0.12"), 2, &n2, &dag2)
            .await
            .unwrap();

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
        registry.add_peer(addr, old_tx, 2, 1).await;
        registry.add_peer(addr, new_tx, 2, 2).await;
        registry.remove_peer(&addr, 1).await;
        assert_eq!(
            registry.peer_count().await,
            1,
            "old connection 1 must not remove connection 2"
        );
        registry.remove_peer(&addr, 2).await;
        assert_eq!(registry.peer_count().await, 0);
    }

    /// A peer whose queue is full must not block a broadcast to everyone else.
    #[tokio::test]
    async fn broadcast_does_not_wait_for_a_stuck_peer() {
        let registry = PeerRegistry::new(TrustStore::default());
        let crypto = NodeCrypto::generate();
        let d = Arc::new(dag());
        let (stuck_tx, _stuck_rx) = mpsc::channel(1);
        let (ok_tx, mut ok_rx) = mpsc::channel(8);
        registry
            .add_peer("127.0.0.1:1".parse().unwrap(), stuck_tx, 2, 1)
            .await;
        registry
            .add_peer("127.0.0.1:2".parse().unwrap(), ok_tx, 3, 2)
            .await;
        let cmd = alert("203.0.113.1");
        for _ in 0..3 {
            timeout(
                Duration::from_millis(500),
                registry.broadcast(&cmd, 1, &crypto, &d),
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
            let env = seal(&peer, 7, &msg, &dag())
                .await
                .expect("heartbeats must be sealable");
            assert!(open(&trust, &mut guard, &env, now_ms()).is_ok());
        }
    }

    /// A pinned peer that pings gets a pong back over the same connection.
    #[tokio::test]
    async fn ping_is_answered_with_pong() {
        let server = Arc::new(NodeCrypto::generate());
        let peer = NodeCrypto::generate();
        let mut trust = TrustStore::default();
        trust.insert(2, peer.public_key);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server.clone(),
            Arc::new(dag()),
            cmd_tx,
            8,
            shutdown_rx,
            PeerRegistry::new(trust),
        );
        tokio::spawn(async move { net.serve(listener).await });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let d = dag();
        for msg in [
            NetworkMessage::Handshake { node_id: 2 },
            NetworkMessage::Ping,
        ] {
            let bytes = bincode::serialize(&seal(&peer, 2, &msg, &d).await.unwrap()).unwrap();
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&bytes).await.unwrap();
        }
        let mut server_trust = TrustStore::default();
        server_trust.insert(1, server.public_key);
        let mut guard = ReplayGuard::default();
        for _ in 0..3 {
            let mut len = [0u8; 4];
            timeout(Duration::from_secs(2), stream.read_exact(&mut len))
                .await
                .unwrap()
                .unwrap();
            let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
            stream.read_exact(&mut buf).await.unwrap();
            let env: SecureEnvelope = bincode::deserialize(&buf).unwrap();
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
        trust_a.insert(2, b.public_key);
        let mut trust_b = TrustStore::default();
        trust_b.insert(1, a.public_key);
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
            Arc::new(dag()),
            reg_a.clone(),
            tx_a,
        ));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(reg_a.peer_count().await, 0);

        let listener = TcpListener::bind(addr).await.unwrap();
        let (tx_b, _rx_b) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let net = P2PNetwork::new(
            addr,
            2,
            b,
            Arc::new(dag()),
            tx_b,
            8,
            shutdown_rx,
            PeerRegistry::new(trust_b),
        );
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
        trust.insert(2, peer.public_key);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            Arc::new(dag()),
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
        let d = dag();
        for msg in [
            NetworkMessage::Handshake { node_id: 2 },
            report(2),
            report(9),
        ] {
            let bytes = bincode::serialize(&seal(&peer, 2, &msg, &d).await.unwrap()).unwrap();
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
        trust.insert(2, a.public_key);
        trust.insert(3, b.public_key);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = P2PNetwork::new(
            addr,
            1,
            server,
            Arc::new(dag()),
            cmd_tx,
            8,
            shutdown_rx,
            PeerRegistry::new(trust),
        );
        tokio::spawn(async move { net.serve(listener).await });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let d = dag();
        let frames = [
            seal(&a, 2, &NetworkMessage::Handshake { node_id: 2 }, &d)
                .await
                .unwrap(),
            seal(&b, 3, &block_cmd("10.0.0.3"), &d).await.unwrap(),
        ];
        for env in frames {
            let bytes = bincode::serialize(&env).unwrap();
            let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes()).await;
            let _ = stream.write_all(&bytes).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            cmd_rx.try_recv().is_err(),
            "envelope from node 3 accepted on node 2's connection"
        );
    }
}
