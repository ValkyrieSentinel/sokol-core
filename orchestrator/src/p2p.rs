#![allow(clippy::too_many_arguments)]
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, RwLock, Semaphore};
use tokio::time::timeout;

use pqcrypto_dilithium::dilithium3::{
    detached_sign, keypair as dilithium_keypair, verify_detached_signature,
    DetachedSignature as DilithiumSignature, PublicKey as DilithiumPublic,
    SecretKey as DilithiumSecret,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

use common::canonical::CanonicalParser;
use crate::MeshCommand;

pub fn extract_ip_bytes(addr: SocketAddr) -> [u8; 16] {
    match addr.ip() {
        std::net::IpAddr::V6(v6) => v6.octets(),
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
    }
}

pub struct NodeCrypto {
    pub public_key: DilithiumPublic,
    secret_key: DilithiumSecret,
}

impl NodeCrypto {
    pub fn new() -> Self {
        let (pk, sk) = dilithium_keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    pub fn sign_payload(&self, payload: &[u8]) -> Vec<u8> {
        let sig = detached_sign(payload, &self.secret_key);
        sig.as_bytes().to_vec()
    }
}

pub struct DagTracker {
    tips: VecDeque<[u8; 32]>,
}

impl DagTracker {
    pub fn new() -> Self {
        let mut tips = VecDeque::new();
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
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub dag_parents: Vec<[u8; 32]>,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NetworkMessage {
    Command(MeshCommand),
    Ack,
    Ping,
    Pong,
    Handshake { node_id: u64, pqc_public_key: Vec<u8> },
}

pub type PeerMap = Arc<RwLock<HashMap<SocketAddr, (mpsc::Sender<SecureEnvelope>, u64)>>>;

#[derive(Clone)]
pub struct PeerRegistry {
    peers: PeerMap,
    public_keys: Arc<RwLock<HashMap<u64, DilithiumPublic>>>,
    seen_nonces: Arc<RwLock<HashSet<u64>>>,
    nonce_queue: Arc<RwLock<VecDeque<u64>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            public_keys: Arc::new(RwLock::new(HashMap::new())),
            seen_nonces: Arc::new(RwLock::new(HashSet::new())),
            nonce_queue: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    pub async fn add_peer(
        &self,
        addr: SocketAddr,
        tx: mpsc::Sender<SecureEnvelope>,
        node_id: u64,
        pk: Option<DilithiumPublic>,
    ) {
        let mut peers = self.peers.write().await;
        peers.insert(addr, (tx, node_id));
        if let Some(key) = pk {
            let mut pks = self.public_keys.write().await;
            pks.insert(node_id, key);
        }
        info!(
            "[P2P] Registered production peer in registry: {} [Node ID: {}]",
            addr, node_id
        );
    }

    pub async fn remove_peer(&self, addr: &SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some((_, node_id)) = peers.remove(addr) {
            info!(
                "[P2P] Unregistered peer from registry: {} [Node ID: {}]",
                addr, node_id
            );
        }
    }

    pub async fn register_public_key(&self, node_id: u64, pk: DilithiumPublic) {
        let mut pks = self.public_keys.write().await;
        pks.insert(node_id, pk);
    }

    pub async fn get_peer_public_key(&self, node_id: u64) -> Result<DilithiumPublic> {
        let pks = self.public_keys.read().await;
        pks.get(&node_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("PQC public key not found for node ID {}", node_id))
    }

    pub async fn validate_and_register_nonce(&self, nonce: u64) -> bool {
        let mut nonces = self.seen_nonces.write().await;
        let mut queue = self.nonce_queue.write().await;
        if nonces.contains(&nonce) {
            return false;
        }
        if queue.len() >= 10_000 {
            if let Some(oldest) = queue.pop_front() {
                nonces.remove(&oldest);
            }
        }
        nonces.insert(nonce);
        queue.push_back(nonce);
        true
    }

    pub async fn broadcast(
        &self,
        command: &MeshCommand,
        node_id: u64,
        crypto: &NodeCrypto,
        dag: &Arc<tokio::sync::Mutex<DagTracker>>,
    ) -> Result<()> {
        let raw_msg = NetworkMessage::Command(command.clone());
        let serialized_payload = serde_json::to_vec(&raw_msg)?;

        let payload_str =
            std::str::from_utf8(&serialized_payload).context("Payload is not valid UTF-8")?;

        CanonicalParser::validate_strict_json_object(payload_str)
            .map_err(|e| anyhow::anyhow!("Canonical validation failed: {:?}", e))?;

        let (parents, _) = {
            let mut dag_lock = dag.lock().await;
            dag_lock.get_parents_and_register(&serialized_payload)
        };

        let signature = crypto.sign_payload(&serialized_payload);

        let envelope = SecureEnvelope {
            sender_id: node_id,
            payload: serialized_payload,
            signature,
            dag_parents: parents,
            nonce: rand::random(),
        };

        let peers = self.peers.read().await;
        for (addr, (tx, _)) in peers.iter() {
            if let Err(e) = tx.send(envelope.clone()).await {
                warn!(
                    "[P2P] Failed to queue secure broadcast message for peer {}: {}",
                    addr, e
                );
            }
        }
        Ok(())
    }
}

pub struct P2PNetwork {
    bind_addr: SocketAddr,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    dag: Arc<tokio::sync::Mutex<DagTracker>>,
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
        dag: Arc<tokio::sync::Mutex<DagTracker>>,
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
        info!(
            "[P2P] Sovereign production mesh listener active on {} (IPv6 enabled)",
            self.bind_addr
        );

        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        let mut shutdown_rx = self.shutdown_rx.clone();
        let node_id = self.node_id;
        let crypto = self.crypto.clone();
        let dag = self.dag.clone();
        let registry = self.registry.clone();

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

                    info!("[P2P] Accepted encrypted connection from peer: {}", peer_addr);

                    let cmd_tx = self.cmd_tx.clone();
                    let sem_clone = semaphore.clone();
                    let reg_clone = registry.clone();
                    let crypto_clone = crypto.clone();
                    let dag_clone = dag.clone();

                    match sem_clone.acquire_owned().await {
                        Ok(permit) => {
                            tokio::spawn(async move {
                                if let Err(e) = handle_inbound_peer(stream, peer_addr, node_id, crypto_clone, dag_clone, cmd_tx, reg_clone).await {
                                    error!("[P2P] Error handling peer {}: {:?}", peer_addr, e);
                                }
                                drop(permit);
                            });
                        }
                        Err(_) => {
                            warn!("[P2P] Max connections ({}) reached. Rejecting peer {}", self.max_connections, peer_addr);
                        }
                    }
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
    dag: Arc<tokio::sync::Mutex<DagTracker>>,
    registry: PeerRegistry,
    cmd_tx: mpsc::Sender<MeshCommand>,
) -> Result<()> {
    let stream = TcpStream::connect(peer_addr)
        .await
        .context(format!("Failed to connect to outbound peer {}", peer_addr))?;

    info!("[P2P] Connected to outbound secure peer: {}", peer_addr);

    let (mut reader, mut writer) = stream.into_split();
    let (tx, rx) = mpsc::channel::<SecureEnvelope>(100);

    let handshake_msg = NetworkMessage::Handshake {
        node_id,
        pqc_public_key: crypto.public_key.as_bytes().to_vec(),
    };
    let hs_payload = serde_json::to_vec(&handshake_msg)?;
    let hs_sig = crypto.sign_payload(&hs_payload);

    let parents = {
        let mut dag_lock = dag.lock().await;
        dag_lock.get_parents_and_register(&hs_payload)
    }
    .0;

    let hs_env = SecureEnvelope {
        sender_id: node_id,
        payload: hs_payload,
        signature: hs_sig,
        dag_parents: parents,
        nonce: rand::random(),
    };

    let hs_bytes = bincode::serialize(&hs_env)?;
    let len_buf = (hs_bytes.len() as u32).to_be_bytes();
    writer.write_all(&len_buf).await?;
    writer.write_all(&hs_bytes).await?;

    registry
        .add_peer(peer_addr, tx.clone(), node_id, None)
        .await;

    spawn_writer_and_ping_loops(
        peer_addr,
        node_id,
        crypto.clone(),
        dag.clone(),
        tx.clone(),
        rx,
        registry.clone(),
        writer,
    );

    handle_reader_loop(
        &mut reader,
        peer_addr,
        node_id,
        crypto,
        dag,
        cmd_tx,
        registry,
        tx,
    )
    .await
}

async fn handle_inbound_peer(
    stream: TcpStream,
    peer_addr: SocketAddr,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    dag: Arc<tokio::sync::Mutex<DagTracker>>,
    cmd_tx: mpsc::Sender<MeshCommand>,
    registry: PeerRegistry,
) -> Result<()> {
    let (mut reader, writer) = stream.into_split();
    let (tx, rx) = mpsc::channel::<SecureEnvelope>(100);

    spawn_writer_and_ping_loops(
        peer_addr,
        node_id,
        crypto.clone(),
        dag.clone(),
        tx.clone(),
        rx,
        registry.clone(),
        writer,
    );

    handle_reader_loop(
        &mut reader,
        peer_addr,
        node_id,
        crypto,
        dag,
        cmd_tx,
        registry,
        tx,
    )
    .await
}

fn spawn_writer_and_ping_loops(
    peer_addr: SocketAddr,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    dag: Arc<tokio::sync::Mutex<DagTracker>>,
    tx: mpsc::Sender<SecureEnvelope>,
    rx: mpsc::Receiver<SecureEnvelope>,
    registry: PeerRegistry,
    writer: tokio::net::tcp::OwnedWriteHalf,
) {
    spawn_peer_writer(rx, writer, peer_addr, registry.clone());
    spawn_ping_loop(tx, node_id, crypto, dag);
}

fn spawn_peer_writer(
    mut rx: mpsc::Receiver<SecureEnvelope>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    peer_addr: SocketAddr,
    registry: PeerRegistry,
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

            let len_buf = (payload.len() as u32).to_be_bytes();
            if timeout(Duration::from_secs(5), writer.write_all(&len_buf))
                .await
                .is_err()
                || timeout(Duration::from_secs(5), writer.write_all(&payload))
                    .await
                    .is_err()
            {
                warn!("[P2P] Write failed to peer {}", peer_addr);
                break;
            }
        }
        registry.remove_peer(&peer_addr).await;
    });
}

fn spawn_ping_loop(
    ping_tx: mpsc::Sender<SecureEnvelope>,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    dag: Arc<tokio::sync::Mutex<DagTracker>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let ping_msg = NetworkMessage::Ping;
            if let Ok(serialized) = serde_json::to_vec(&ping_msg) {
                let sig = crypto.sign_payload(&serialized);
                let parents = {
                    let mut dag_lock = dag.lock().await;
                    dag_lock.get_parents_and_register(&serialized)
                }
                .0;

                let env = SecureEnvelope {
                    sender_id: node_id,
                    payload: serialized,
                    signature: sig,
                    dag_parents: parents,
                    nonce: rand::random(),
                };
                if ping_tx.send(env).await.is_err() {
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
    dag: Arc<tokio::sync::Mutex<DagTracker>>,
    cmd_tx: mpsc::Sender<MeshCommand>,
    registry: PeerRegistry,
    writer_tx: mpsc::Sender<SecureEnvelope>,
) -> Result<()> {
    let mut len_buf = [0u8; 4];
    let _ip_bytes = extract_ip_bytes(peer_addr);

    loop {
        let read_len_res =
            timeout(Duration::from_secs(30), reader.read_exact(&mut len_buf)).await;

        match read_len_res {
            Ok(Ok(_)) => {}
            Ok(Err(e))
                if e.kind() == ErrorKind::UnexpectedEof
                    || e.kind() == ErrorKind::ConnectionReset =>
            {
                debug!("[P2P] Peer {} disconnected gracefully", peer_addr);
                break;
            }
            Ok(Err(e)) => {
                warn!("[P2P] Read error from peer {}: {}", peer_addr, e);
                break;
            }
            Err(_) => {
                warn!(
                    "[P2P] Heartbeat/Read timeout from peer {}. Disconnecting.",
                    peer_addr
                );
                break;
            }
        }

        let payload_len = u32::from_be_bytes(len_buf) as usize;
        if payload_len > 128 * 1024 {
            warn!(
                "[P2P] Payload from {} exceeds size limit: {} bytes",
                peer_addr, payload_len
            );
            break;
        }

        let mut payload = vec![0u8; payload_len];
        if timeout(Duration::from_secs(5), reader.read_exact(&mut payload))
            .await
            .is_err()
        {
            warn!("[P2P] Timeout reading payload from {}", peer_addr);
            break;
        }

        let envelope: SecureEnvelope = match bincode::deserialize(&payload) {
            Ok(env) => env,
            Err(e) => {
                warn!(
                    "[P2P] Failed to deserialize SecureEnvelope from {}: {:?}",
                    peer_addr, e
                );
                continue;
            }
        };

        if !registry.validate_and_register_nonce(envelope.nonce).await {
            warn!(
                "[P2P] Replay attack detected from {}! Nonce {} already processed.",
                peer_addr, envelope.nonce
            );
            continue;
        }

        let payload_str = match std::str::from_utf8(&envelope.payload) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "[P2P] Invalid UTF-8 in envelope payload from {}: {}",
                    peer_addr, e
                );
                continue;
            }
        };

        if let Err(e) = CanonicalParser::validate_strict_json_object(payload_str) {
            warn!(
                "[P2P] Canonical structure validation failed for peer {}: {:?}",
                peer_addr, e
            );
            continue;
        }

        let net_msg: NetworkMessage = match serde_json::from_slice(&envelope.payload) {
            Ok(msg) => msg,
            Err(e) => {
                warn!(
                    "[P2P] Failed to deserialize inner NetworkMessage from {}: {:?}",
                    peer_addr, e
                );
                continue;
            }
        };

        match &net_msg {
            NetworkMessage::Handshake {
                node_id,
                pqc_public_key,
            } => {
                let pk = match DilithiumPublic::from_bytes(pqc_public_key) {
                    Ok(key) => key,
                    Err(_) => {
                        warn!(
                            "[P2P] Invalid public key bytes received in handshake from node ID: {}",
                            node_id
                        );
                        continue;
                    }
                };

                let sig = match DilithiumSignature::from_bytes(&envelope.signature) {
                    Ok(s) => s,
                    Err(_) => {
                        warn!(
                            "[P2P] Malformed handshake signature format from node ID: {}",
                            node_id
                        );
                        continue;
                    }
                };

                if verify_detached_signature(&sig, &envelope.payload, &pk).is_err() {
                    error!(
                        "[SECURITY ALERT] Handshake signature verification failed for node {}!",
                        node_id
                    );
                    continue;
                }

                if let Ok(existing_pk) = registry.get_peer_public_key(*node_id).await {
                    if existing_pk.as_bytes() != pk.as_bytes() {
                        warn!(
                            "[SECURITY ALERT] Node ID {} attempted to overwrite registered public key from peer {}. Rejecting handshake.",
                            node_id, peer_addr
                        );
                        continue;
                    }
                } else {
                    registry.register_public_key(*node_id, pk).await;
                }
                registry
                    .add_peer(peer_addr, writer_tx.clone(), *node_id, Some(pk))
                    .await;
                info!(
                    "[P2P] Successfully verified and registered PQC Dilithium public key for node ID: {}",
                    node_id
                );
            }
            _ => {
                let sig_bytes = &envelope.signature;
                match registry.get_peer_public_key(envelope.sender_id).await {
                    Ok(pk) => {
                        if let Ok(sig) = DilithiumSignature::from_bytes(sig_bytes) {
                            if verify_detached_signature(&sig, &envelope.payload, &pk).is_err() {
                                error!(
                                    "[SECURITY ALERT] PQC ML-DSA/Dilithium signature verification failed for node {}!",
                                    envelope.sender_id
                                );
                                continue;
                            }
                        } else {
                            warn!(
                                "[P2P] Malformed signature format from node ID: {}",
                                envelope.sender_id
                            );
                            continue;
                        }
                    }
                    Err(_) => {
                        warn!(
                            "[P2P] Public key unknown for sender node ID: {}. Dropping packet.",
                            envelope.sender_id
                        );
                        continue;
                    }
                }
            }
        }

        match net_msg {
            NetworkMessage::Command(command) => {
                if let Err(e) = cmd_tx.send(command).await {
                    error!(
                        "[P2P] Failed to send command to local orchestrator: {}",
                        e
                    );
                    break;
                }
            }
            NetworkMessage::Ack => {
                debug!("[P2P] Received ACK from {}", peer_addr);
            }
            NetworkMessage::Ping => {
                let pong_msg = NetworkMessage::Pong;
                if let Ok(serialized) = serde_json::to_vec(&pong_msg) {
                    let sig = crypto.sign_payload(&serialized);
                    let parents = {
                        let mut dag_lock = dag.lock().await;
                        dag_lock.get_parents_and_register(&serialized)
                    }
                    .0;

                    let env = SecureEnvelope {
                        sender_id: local_node_id,
                        payload: serialized,
                        signature: sig,
                        dag_parents: parents,
                        nonce: rand::random(),
                    };
                    let _ = writer_tx.send(env).await;
                }
            }
            NetworkMessage::Pong => {
                debug!("[P2P] Received Pong from {}", peer_addr);
            }
            NetworkMessage::Handshake { .. } => {}
        }
    }

    Ok(())
}