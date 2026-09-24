#![allow(dead_code)]
pub use mesh_sync::{AlertLevel, MeshCommand, MeshOrchestrator};
pub mod cluster_state;
mod block_policy;
mod mesh_sync;
mod p2p;
mod sokol;

use aya::maps::lpm_trie::Key;
use aya::maps::{Array, LpmTrie, MapData, PerCpuArray, RingBuf};
use aya::programs::Xdp;
use aya::{include_bytes_aligned, Bpf, Pod};
use clap::Parser;
use sokol::SokolEngine;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch};

use common::atp::AtpBudgetController;
use common::audit_log::AuditLog;
use common::canonical::CanonicalParser;
use common::{DropEvent, NodeTelemetry};

use crate::block_policy::BlockPolicy;
use crate::cluster_state::BirdEyeView;
use crate::p2p::{connect_to_peer, DagTracker, NodeCrypto, P2PNetwork, PeerRegistry, TrustStore};

/// Audit trail writer. Records are queued (bounded, so a flood cannot exhaust memory) and
/// written by one thread, fsynced every 100 ms or 64 records: a crash loses at most that window.
pub struct SentinelDb {
    tx: std::sync::mpsc::SyncSender<String>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl SentinelDb {
    const QUEUE_CAPACITY: usize = 10_000;
    const SYNC_INTERVAL: Duration = Duration::from_millis(100);
    const SYNC_BATCH: usize = 64;

    pub fn init(path: &str) -> anyhow::Result<Self> {
        let mut log = AuditLog::open(std::path::Path::new(path))
            .map_err(|e| anyhow::anyhow!("{} ({})", e, path))?;
        log::info!("Audit log {} opened: {} records verified", path, log.len());

        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(Self::QUEUE_CAPACITY);
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped_writer = dropped.clone();

        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            use std::sync::mpsc::RecvTimeoutError;
            loop {
                match rx.recv_timeout(Self::SYNC_INTERVAL) {
                    Ok(payload) => {
                        let lost = dropped_writer.swap(0, Ordering::Relaxed);
                        if lost > 0 {
                            let note = format!("AUDIT_QUEUE_OVERFLOW|Dropped:{}", lost);
                            if let Err(e) = log.append(note.as_bytes()) {
                                log::error!("[Audit] Failed to record queue overflow: {}", e);
                            }
                        }
                        if let Err(e) = log.append(payload.as_bytes()) {
                            log::error!("[Audit] Failed to append record: {}", e);
                        }
                        if log.unsynced() >= Self::SYNC_BATCH {
                            if let Err(e) = log.sync() {
                                log::error!("[Audit] fsync failed: {}", e);
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if let Err(e) = log.sync() {
                            log::error!("[Audit] fsync failed: {}", e);
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            let _ = log.sync();
            log::info!("SentinelDb persistence thread terminated.");
        });

        Ok(Self { tx, dropped })
    }

    pub fn append(&self, data: String) {
        match self.tx.try_send(data) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                log::error!("Audit writer thread is gone; record lost");
            }
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct BpfPacketStats(common::PacketStats);

unsafe impl Pod for BpfPacketStats {}

#[derive(Parser, Debug)]
#[command(author, version, about = "Sokol-Core Sovereign Orchestrator - Production Node")]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    #[arg(long, value_name = "IP")]
    block: Vec<String>,

    #[arg(long, value_name = "PORT")]
    trap_port: Vec<u16>,

    #[arg(long, default_value = "/var/lib/sokol/audit.log")]
    db_path: String,

    #[arg(long, default_value = "1")]
    node_id: u64,

    #[arg(long, default_value = "[::]:8080")]
    p2p_bind: String,

    #[arg(long, value_name = "PEER")]
    seed_peer: Vec<String>,

    #[arg(long, default_value = "[2001:db8:ffff::1]:179")]
    upstream_router: String,

    #[arg(long, default_value = "2001:db8:1000::/64")]
    ipv6_prefix: String,

    /// Node identity key (ML-DSA/Dilithium3). Created with mode 0600 on first start.
    #[arg(long, default_value = "/var/lib/sokol/node.key")]
    key_file: std::path::PathBuf,

    /// JSON list of pinned mesh peers: [{"node_id": 2, "public_key": "<hex>"}].
    /// Without it the mesh accepts no peers.
    #[arg(long)]
    peers_file: Option<std::path::PathBuf>,

    /// Print this node's public key (hex) for other nodes' peers files, then exit.
    #[arg(long)]
    print_public_key: bool,

    /// Address or CIDR that must never be blocked (operator/bastion networks, mesh peers).
    /// Loopback, this node's addresses, default gateways and seed peers are always protected.
    #[arg(long, value_name = "CIDR")]
    never_block: Vec<String>,

    /// Group allowed to send commands on the control socket (mode 0660).
    /// Without it the socket is root-only (0600).
    #[arg(long)]
    ipc_group: Option<String>,

    /// Drop all IPv4 fragments in XDP (default: fragments pass, subject to the blocklist).
    #[arg(long)]
    drop_ipv4_fragments: bool,
}

const IPC_SOCKET_PATH: &str = "/run/sokol.sock";
const MAX_IPC_LINE: u64 = 4096;

fn build_block_policy(args: &Args) -> anyhow::Result<BlockPolicy> {
    let mut policy = BlockPolicy::builtin();
    policy.protect_host_addresses();
    for seed in &args.seed_peer {
        if let Ok(addr) = seed.trim().parse::<std::net::SocketAddr>() {
            policy.protect_ip(addr.ip(), "mesh seed peer");
        }
    }
    for raw in &args.never_block {
        let raw = raw.trim();
        let net = match raw.parse::<ipnet::IpNet>() {
            Ok(net) => net,
            Err(_) => raw
                .parse::<IpAddr>()
                .map(ipnet::IpNet::from)
                .map_err(|_| anyhow::anyhow!("--never-block '{}' is not an IP address or CIDR", raw))?,
        };
        policy.protect(net, "operator never-block range");
    }
    Ok(policy)
}

fn resolve_group(name: &str) -> anyhow::Result<u32> {
    let c_name = std::ffi::CString::new(name)?;
    // SAFETY: getgrnam returns a pointer into static storage; we only read gr_gid before any
    // other call could overwrite it.
    let group = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if group.is_null() {
        anyhow::bail!("--ipc-group '{}' does not exist", name);
    }
    Ok(unsafe { (*group).gr_gid })
}

async fn push_telemetry(msg: &str) {
    let telemetry_socket = "/run/sokol_telemetry.sock";
    if let Ok(mut stream) = tokio::net::UnixStream::connect(telemetry_socket).await {
        let _ = stream.write_all(msg.as_bytes()).await;
        let _ = stream.flush().await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn enforce_block_local(
    ip: IpAddr,
    reason: &str,
    blocklist_v4: &Arc<tokio::sync::Mutex<LpmTrie<MapData, [u8; 4], u32>>>,
    blocklist_v6: &Arc<tokio::sync::Mutex<LpmTrie<MapData, [u8; 16], u32>>>,
    sntl_db: &Arc<SentinelDb>,
    registry: &PeerRegistry,
    node_id: u64,
    node_crypto: &Arc<NodeCrypto>,
    dag_tracker: &Arc<tokio::sync::Mutex<DagTracker>>,
    policy: &BlockPolicy,
) {
    let ip = ip.to_canonical();
    if let Err(why) = policy.check(ip) {
        log::error!("[Local Security] Refusing to block {} ({}) | Requested for: {}", ip, why, reason);
        sntl_db.append(format!("BLOCK_REFUSED|IP:{}|Protected:{}|Reason:{}", ip, why, reason));
        return;
    }
    match ip {
        IpAddr::V4(v4) => {
            let key = Key::new(32, v4.octets());
            let insert_result = {
                let mut map_guard = blocklist_v4.lock().await;
                map_guard.insert(&key, 1u32, 0)
            };

            match insert_result {
                Ok(_) => {
                    log::warn!("[Local Security] Dynamic IPv4 block enforced in XDP: {} | Reason: {}", v4, reason);
                    sntl_db.append(format!("DYNAMIC_BLOCK_V4|IP:{}|Reason:{}|Enforced", v4, reason));
                    
                    let telemetry_msg = format!("DROP_IMMEDIATE:{}\nDB_LOG:NODE={}|TIER=Tier1BotTarpit|IP={}|VEC={}\n", v4, node_id, v4, reason);
                    push_telemetry(&telemetry_msg).await;

                    let broadcast_cmd = MeshCommand::BlockIp {
                        ip: v4.to_string(),
                        reason: reason.to_string(),
                    };
                    let _ = registry.broadcast(&broadcast_cmd, node_id, node_crypto, dag_tracker).await;
                }
                Err(e) => {
                    log::error!("[Local Security] Failed to insert IPv4 {} into eBPF: {:?}", v4, e);
                }
            }
        }
        IpAddr::V6(v6) => {
            let key = Key::new(128, v6.octets());
            let insert_result = {
                let mut map_guard = blocklist_v6.lock().await;
                map_guard.insert(&key, 1u32, 0)
            };

            match insert_result {
                Ok(_) => {
                    log::warn!("[Local Security] Dynamic IPv6 block enforced in XDP: {} | Reason: {}", v6, reason);
                    sntl_db.append(format!("DYNAMIC_BLOCK_V6|IP:{}|Reason:{}|Enforced", v6, reason));

                    let telemetry_msg = format!("DROP_IMMEDIATE:{}\nDB_LOG:NODE={}|TIER=Tier1BotTarpit|IP={}|VEC={}\n", v6, node_id, v6, reason);
                    push_telemetry(&telemetry_msg).await;

                    let broadcast_cmd = MeshCommand::BlockIp {
                        ip: v6.to_string(),
                        reason: reason.to_string(),
                    };
                    let _ = registry.broadcast(&broadcast_cmd, node_id, node_crypto, dag_tracker).await;
                }
                Err(e) => {
                    log::error!("[Local Security] Failed to insert IPv6 {} into eBPF: {:?}", v6, e);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let node_crypto = Arc::new(NodeCrypto::load_or_create(&args.key_file)?);
    if args.print_public_key {
        println!("{}", node_crypto.public_key_hex());
        return Ok(());
    }

    let trust_store = match &args.peers_file {
        Some(path) => TrustStore::load(path)?,
        None => {
            log::warn!("[P2P] No --peers-file given: mesh messages from all peers will be rejected.");
            TrustStore::default()
        }
    };

    let block_policy = Arc::new(build_block_policy(&args)?);
    let ipc_gid = args.ipc_group.as_deref().map(resolve_group).transpose()?;

    log::info!("Initializing Sokol-Core Production Daemon on interface: {} [Node ID: {}]", args.interface, args.node_id);

    let  atp_controller = AtpBudgetController::new(10_000_000);

    let sntl_db = Arc::new(SentinelDb::init(&args.db_path)?);

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/debug/ebpf-probe"
    )))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/bpfel-unknown-none/release/ebpf-probe"
    )))?;

    let prog_mut = bpf
        .program_mut("sentinel_vfr_filter")
        .ok_or_else(|| anyhow::anyhow!("Critical: Program sentinel_vfr_filter not found in ELF"))?;
    let program: &mut Xdp = prog_mut.try_into()?;
    program.load()?;

    let mut config_flags = 0u32;
    if args.drop_ipv4_fragments {
        config_flags |= common::config_flags::DROP_IPV4_FRAGMENTS;
    }
    {
        let config_map = bpf.map_mut("CONFIG").ok_or_else(|| anyhow::anyhow!("CONFIG map missing"))?;
        let mut config = Array::<_, u32>::try_from(config_map)?;
        config.set(0, config_flags, 0)?;
    }

    let prog_mut = bpf
        .program_mut("sentinel_vfr_filter")
        .ok_or_else(|| anyhow::anyhow!("Critical: Program sentinel_vfr_filter not found in ELF"))?;
    let program: &mut Xdp = prog_mut.try_into()?;
    let _link = program.attach(&args.interface, Default::default())?;
    log::info!("XDP program successfully locked and attached to interface: {}", args.interface);

    let blocklist_v4_data = bpf.take_map("BLOCKLIST_V4").ok_or_else(|| anyhow::anyhow!("BLOCKLIST_V4 missing"))?;
    let blocklist_v4_trie = LpmTrie::<MapData, [u8; 4], u32>::try_from(blocklist_v4_data)?;
    let blocklist_v4_map = Arc::new(tokio::sync::Mutex::new(blocklist_v4_trie));

    let blocklist_v6_data = bpf.take_map("BLOCKLIST_V6").ok_or_else(|| anyhow::anyhow!("BLOCKLIST_V6 missing"))?;
    let blocklist_v6_trie = LpmTrie::<MapData, [u8; 16], u32>::try_from(blocklist_v6_data)?;
    let blocklist_v6_map = Arc::new(tokio::sync::Mutex::new(blocklist_v6_trie));

    let stats_map_data = bpf.take_map("STATS").ok_or_else(|| anyhow::anyhow!("STATS map missing"))?;
    let stats_map = PerCpuArray::<MapData, BpfPacketStats>::try_from(stats_map_data)?;

    if let Some(events_map_data) = bpf.take_map("EVENTS") {
        match RingBuf::try_from(events_map_data) {
            Ok(ring_buf) => {
                match AsyncFd::new(ring_buf) {
                    Ok(mut async_fd) => {
                        let db_events = sntl_db.clone();
                        let node_id_ev = args.node_id;
                        tokio::spawn(async move {
                            log::info!("[eBPF RingBuf] Active consumer loop attached for kernel drop events.");
                            loop {
                                match async_fd.readable_mut().await {
                                    Ok(mut guard) => {
                                        let rb = guard.get_inner_mut();
                                        
                                        while let Some(item) = rb.next() {
                                            if item.len() >= std::mem::size_of::<DropEvent>() {
                                                let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const DropEvent) };
                                                let log_msg = format!(
                                                    "KERNEL_DROP_NOTIFY|Reason:{}|Proto:{}|Version:{}|PktLen:{}",
                                                    event.reason, event.protocol, event.ip_version, event.pkt_len
                                                );
                                                db_events.append(log_msg.clone());
                                                
                                                let telemetry_msg = format!("DB_LOG:NODE={}|TIER=Tier1BotTarpit|IP=0.0.0.0|VEC={}\n", node_id_ev, log_msg);
                                                push_telemetry(&telemetry_msg).await;
                                            }
                                        }
                                        guard.clear_ready();
                                    }
                                    Err(e) => {
                                        log::error!("[eBPF RingBuf] Failed to get readable guard: {}", e);
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("[eBPF RingBuf] Failed to wrap ring buffer in AsyncFd: {}", e);
                    }
                }
            }
            Err(e) => {
                log::error!("[eBPF RingBuf] Failed to create RingBuf from map data: {}", e);
            }
        }
    }

    for ip_str in &args.block {
        let clean_str = ip_str.trim();
        if let Ok(ip) = clean_str.parse::<IpAddr>() {
            let ip = ip.to_canonical();
            if let Err(why) = block_policy.check(ip) {
                anyhow::bail!("--block {} refused: address is protected ({})", ip, why);
            }
            match ip {
                IpAddr::V4(v4) => {
                    let key = Key::new(32, v4.octets());
                    blocklist_v4_map.lock().await.insert(&key, 1u32, 0)?;
                    sntl_db.append(format!("STATIC_BLOCK_V4|IP:{}|Action:XDP_DROP", v4));
                    log::info!("[STATIC BLOCK] Enforced IPv4 block for CLI IP: {}", v4);
                }
                IpAddr::V6(v6) => {
                    let key = Key::new(128, v6.octets());
                    blocklist_v6_map.lock().await.insert(&key, 1u32, 0)?;
                    sntl_db.append(format!("STATIC_BLOCK_V6|IP:{}|Action:XDP_DROP", v6));
                    log::info!("[STATIC BLOCK] Enforced IPv6 block for CLI IP: {}", v6);
                }
            }
        } else {
            log::error!("[STATIC BLOCK] Invalid CLI --block IP argument: '{}'", ip_str);
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx_ctrlc = shutdown_tx.clone();

    ctrlc::set_handler(move || {
        log::warn!("SIGINT received. Teardown initiated...");
        let _ = shutdown_tx_ctrlc.send(true);
    })?;

    let peer_registry = PeerRegistry::new(trust_store);
    let (mesh_cmd_tx, mut mesh_cmd_rx) = mpsc::channel::<MeshCommand>(1000);

    let dag_tracker = Arc::new(tokio::sync::Mutex::new(DagTracker::new()));

    let p2p_bind_addr: std::net::SocketAddr = args.p2p_bind.parse().expect("Invalid P2P bind address");

    let p2p_network = P2PNetwork::new(
        p2p_bind_addr,
        args.node_id,
        node_crypto.clone(),
        dag_tracker.clone(),
        mesh_cmd_tx.clone(),
        100,
        shutdown_rx.clone(),
        peer_registry.clone(),
    );

    tokio::spawn(async move {
        if let Err(e) = p2p_network.run().await {
            log::error!("[P2P] Network listener failed: {:?}", e);
        }
    });

    for seed in &args.seed_peer {
        if let Ok(seed_addr) = seed.trim().parse::<std::net::SocketAddr>() {
            let reg_clone = peer_registry.clone();
            let tx_clone = mesh_cmd_tx.clone();
            let crypto_clone = node_crypto.clone();
            let dag_clone = dag_tracker.clone();
            let node_id = args.node_id;

            tokio::spawn(async move {
                log::info!("[P2P] Connecting to seed peer: {}", seed_addr);
                if let Err(e) = connect_to_peer(
                    seed_addr,
                    node_id,
                    crypto_clone,
                    dag_clone,
                    reg_clone,
                    tx_clone,
                ).await {
                    log::warn!("[P2P] Failed to connect to seed peer {}: {:?}", seed_addr, e);
                }
            });
        }
    }

    let bird_eye = BirdEyeView::new(0.5, Duration::from_secs(300));
    let (_telemetry_tx, telemetry_rx) = mpsc::channel::<NodeTelemetry>(1000);

    let blocklist_v4_mesh = blocklist_v4_map.clone();
    let blocklist_v6_mesh = blocklist_v6_map.clone();
    let sntl_db_mesh = sntl_db.clone();
    let node_id_mesh = args.node_id;
    let policy_mesh = block_policy.clone();

    tokio::spawn(async move {
        while let Some(cmd) = mesh_cmd_rx.recv().await {
            match cmd {
                MeshCommand::BlockIp { ip, reason } => {
                    let clean_ip = ip.trim();
                    if let Ok(ip_addr) = clean_ip.parse::<IpAddr>() {
                        let ip_addr = ip_addr.to_canonical();
                        if let Err(why) = policy_mesh.check(ip_addr) {
                            log::error!("[Mesh] Refusing mesh BlockIp for protected {} ({}): {}", ip_addr, why, reason);
                            sntl_db_mesh.append(format!("MESH_BLOCK_REFUSED|IP:{}|Protected:{}|Reason:{}", ip_addr, why, reason));
                            continue;
                        }
                        match ip_addr {
                            IpAddr::V4(v4) => {
                                let key = Key::new(32, v4.octets());
                                let insert_res = {
                                    let mut map_guard = blocklist_v4_mesh.lock().await;
                                    map_guard.insert(&key, 1u32, 0)
                                };

                                if let Err(e) = insert_res {
                                    log::error!("[Mesh] Failed to insert IPv4 {} into eBPF: {:?}", v4, e);
                                } else {
                                    log::warn!("[Mesh] Synchronized IPv4 block for {} across mesh: {}", v4, reason);
                                    sntl_db_mesh.append(format!("MESH_BLOCK_V4|IP:{}|Reason:{}", v4, reason));
                                    
                                    let telemetry_msg = format!("DB_LOG:NODE={}|TIER=Tier1_5Revenge|IP={}|VEC={}\n", node_id_mesh, v4, reason);
                                    push_telemetry(&telemetry_msg).await;
                                }
                            }
                            IpAddr::V6(v6) => {
                                let key = Key::new(128, v6.octets());
                                let insert_res = {
                                    let mut map_guard = blocklist_v6_mesh.lock().await;
                                    map_guard.insert(&key, 1u32, 0)
                                };

                                if let Err(e) = insert_res {
                                    log::error!("[Mesh] Failed to insert IPv6 {} into eBPF: {:?}", v6, e);
                                } else {
                                    log::warn!("[Mesh] Synchronized IPv6 block for {} across mesh: {}", v6, reason);
                                    sntl_db_mesh.append(format!("MESH_BLOCK_V6|IP:{}|Reason:{}", v6, reason));

                                    let telemetry_msg = format!("DB_LOG:NODE={}|TIER=Tier1_5Revenge|IP={}|VEC={}\n", node_id_mesh, v6, reason);
                                    push_telemetry(&telemetry_msg).await;
                                }
                            }
                        }
                    } else {
                        log::error!("[Mesh] Received unparseable IP in BlockIp command: '{}'", ip);
                    }
                }
                MeshCommand::UnblockIp { ip } => {
                    let clean_ip = ip.trim();
                    if let Ok(ip_addr) = clean_ip.parse::<IpAddr>() {
                        match ip_addr {
                            IpAddr::V4(v4) => {
                                let key = Key::new(32, v4.octets());
                                let mut map_guard = blocklist_v4_mesh.lock().await;
                                let _ = map_guard.remove(&key);
                                drop(map_guard);
                                log::info!("[Mesh] Unblocked IPv4 {} per mesh command", v4);
                            }
                            IpAddr::V6(v6) => {
                                let key = Key::new(128, v6.octets());
                                let mut map_guard = blocklist_v6_mesh.lock().await;
                                let _ = map_guard.remove(&key);
                                drop(map_guard);
                                log::info!("[Mesh] Unblocked IPv6 {} per mesh command", v6);
                            }
                        }
                    } else {
                        log::error!("[Mesh] Failed to parse IP for UnblockIp: '{}'", ip);
                    }
                }
                MeshCommand::EngageDefense => {
                    log::warn!("[CRITICAL] Global mesh defense mode engaged (no enforcement is attached to this mode yet).");
                }
                MeshCommand::DisengageDefense => {
                    log::info!("[CRITICAL] Global mesh defense mode disengaged.");
                }
                MeshCommand::Alert { level, message } => {
                    log::info!("[MESH ALERT {:?}] {}", level, message);
                }
            }
        }
    });

    let upstream_router_addr: std::net::SocketAddr = args.upstream_router.parse().expect("Invalid upstream router address");
    let mesh_orchestrator = MeshOrchestrator::new(
        bird_eye,
        telemetry_rx,
        mesh_cmd_tx.clone(),
        sntl_db.clone(),
        shutdown_rx.clone(),
        upstream_router_addr,
        args.ipv6_prefix.clone(),
    );

    let mut orchestrator_task = mesh_orchestrator;
    tokio::spawn(async move {
        if let Err(e) = orchestrator_task.run_telemetry_processor().await {
            log::error!("[Mesh] Orchestrator telemetry processor failed: {}", e);
        }
    });

    for &port in &args.trap_port {
        let blocklist_v4_trap = blocklist_v4_map.clone();
        let blocklist_v6_trap = blocklist_v6_map.clone();
        let db_trap = sntl_db.clone();
        let registry_trap = peer_registry.clone();

        let crypto_trap = node_crypto.clone();
        let dag_trap = dag_tracker.clone();
        let node_id_trap = args.node_id;
        let policy_trap = block_policy.clone();

        let bind_addr = format!("0.0.0.0:{}", port);

        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    log::info!("[TRAP] Decoy TCP trap listening on port {}", port);
                    loop {
                        match listener.accept().await {
                            Ok((_stream, peer)) => {
                                let ip = peer.ip();
                                log::warn!("[TRAP HIT] Unauthorized connection on port {} from {}", port, ip);

                                let reason = format!("Decoy TCP trap hit on port {}", port);
                                enforce_block_local(
                                    ip,
                                    &reason,
                                    &blocklist_v4_trap,
                                    &blocklist_v6_trap,
                                    &db_trap,
                                    &registry_trap,
                                    node_id_trap,
                                    &crypto_trap,
                                    &dag_trap,
                                    &policy_trap,
                                ).await;
                                db_trap.append(format!("TRAP_HIT|Port:{}|IP:{}|Action:EnforcedDrop", port, ip));
                                
                                let telemetry_msg = format!("DB_LOG:NODE={}|TIER=Tier1BotTarpit|IP={}|VEC={}\n", node_id_trap, ip, reason);
                                push_telemetry(&telemetry_msg).await;
                            }
                            Err(e) => {
                                log::error!("[TRAP] Accept error on port {}: {}. Retrying...", port, e);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error!("[TRAP] Failed to bind decoy trap on port {}: {}", port, e);
                }
            }
        });
    }

    let socket_path = IPC_SOCKET_PATH;
    let _ = std::fs::remove_file(socket_path);

    let unix_listener = tokio::net::UnixListener::bind(socket_path)
        .map_err(|e| anyhow::anyhow!("Failed to bind Unix socket at {}: {}", socket_path, e))?;

    // Anyone who can write to this socket can make the node drop arbitrary sources and push
    // the block to the whole mesh, so it is root-only unless an operator group is named.
    match ipc_gid {
        Some(gid) => {
            std::os::unix::fs::chown(socket_path, None, Some(gid))?;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
        }
        None => std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?,
    }

    let blocklist_v4_unix = blocklist_v4_map.clone();
    let blocklist_v6_unix = blocklist_v6_map.clone();
    let db_unix = sntl_db.clone();
    let registry_unix = peer_registry.clone();

    let crypto_unix = node_crypto.clone();
    let dag_unix = dag_tracker.clone();
    let node_id_unix = args.node_id;
    let policy_unix = block_policy.clone();

    tokio::spawn(async move {
        log::info!("[UNIX SOCKET] Listening for trap events on {}", socket_path);
        loop {
            match unix_listener.accept().await {
                Ok((stream, _)) => {
                    let blocklist_v4 = blocklist_v4_unix.clone();
                    let blocklist_v6 = blocklist_v6_unix.clone();
                    let db = db_unix.clone();
                    let registry = registry_unix.clone();

                    let crypto_stream = crypto_unix.clone();
                    let dag_stream = dag_unix.clone();
                    let policy_stream = policy_unix.clone();
                    let peer_uid = stream.peer_cred().map(|c| c.uid()).ok();

                    tokio::spawn(async move {
                        let mut reader = BufReader::new(stream);
                        let mut line = String::new();

                        loop {
                            line.clear();
                            match (&mut reader).take(MAX_IPC_LINE).read_line(&mut line).await {
                                Ok(0) => break,
                                Ok(_) if !line.ends_with('\n') && line.len() as u64 >= MAX_IPC_LINE => {
                                    log::error!("[UNIX IPC FAULT] Line over {} bytes from uid {:?}; closing connection", MAX_IPC_LINE, peer_uid);
                                    break;
                                }
                                Ok(_) => {
                                    log::debug!("[UNIX IPC] command from uid {:?}: {}", peer_uid, line.trim());
                                    let content = line.trim();
                                    if content.is_empty() {
                                        continue;
                                    }

                                    if content.starts_with('{') {
                                        if let Err(e) = CanonicalParser::validate_strict_json_object(content) {
                                            log::error!("[CANONICAL FAULT] Rejected malformed IPC payload: {:?}", e);
                                            continue;
                                        }
                                    }

                                    if let Some(raw_ip_str) = content.strip_prefix("DROP_IMMEDIATE:") {
                                        let clean_ip_str = raw_ip_str.trim();
                                        match clean_ip_str.parse::<IpAddr>() {
                                            Ok(ip) => {
                                                log::warn!("[XDP_ACTION] Trap triggered ban for IP: {}", ip);
                                                enforce_block_local(
                                                    ip,
                                                    "Unix IPC DROP_IMMEDIATE trigger",
                                                    &blocklist_v4,
                                                    &blocklist_v6,
                                                    &db,
                                                    &registry,
                                                    node_id_unix,
                                                    &crypto_stream,
                                                    &dag_stream,
                                                    &policy_stream,
                                                ).await;
                                            }
                                            Err(e) => {
                                                log::error!(
                                                    "[UNIX IPC FAULT] Failed to parse IP from 'DROP_IMMEDIATE:{}': {}",
                                                    raw_ip_str,
                                                    e
                                                );
                                            }
                                        }
                                    } else if let Some(raw_ip_str) = content.strip_prefix("APT_HIGH_PRIORITY:") {
                                        let clean_ip_str = raw_ip_str.trim();
                                        match clean_ip_str.parse::<IpAddr>() {
                                            Ok(ip) => {
                                                log::warn!("[APT_ALERT] High-priority stager from IP: {}", ip);
                                                db.append(format!("APT_HIGH_PRIORITY|IP:{}|Enforced", ip));
                                                
                                                let telemetry_msg = format!("DB_LOG:NODE={}|TIER=Tier2AptSandbox|IP={}|VEC=APT High-Priority Stager\n", node_id_unix, ip);
                                                push_telemetry(&telemetry_msg).await;

                                                enforce_block_local(
                                                    ip,
                                                    "Unix IPC APT_HIGH_PRIORITY stager",
                                                    &blocklist_v4,
                                                    &blocklist_v6,
                                                    &db,
                                                    &registry,
                                                    node_id_unix,
                                                    &crypto_stream,
                                                    &dag_stream,
                                                    &policy_stream,
                                                ).await;
                                            }
                                            Err(e) => {
                                                log::error!(
                                                    "[UNIX IPC FAULT] Failed to parse IP from 'APT_HIGH_PRIORITY:{}': {}",
                                                    raw_ip_str,
                                                    e
                                                );
                                            }
                                        }
                                    } else if let Some(log_content) = content.strip_prefix("DB_LOG:") {
                                        db.append(log_content.trim().to_string());
                                        let telemetry_msg = format!("DB_LOG:NODE={}|{}\n", node_id_unix, log_content.trim());
                                        push_telemetry(&telemetry_msg).await;
                                    }
                                }
                                Err(e) => {
                                    log::error!("[UNIX SOCKET] Error reading IPC stream: {}", e);
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    log::error!("[UNIX SOCKET] Accept error: {}. Retrying...", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    let sokol_engine = SokolEngine::new(500.0);
    let mut prev_packets = 0;
    let mut prev_bytes = 0;
    let mut prev_dropped = 0;
    // Counters are cumulative; the first tick only establishes the baseline.
    let mut have_baseline = false;

    log::info!("Sokol-Core running with SokolEngine anomaly detection & sovereign mesh verification loops.");

    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut shutdown_rx_loop = shutdown_rx.clone();
    let node_id_hb = args.node_id;
    let p2p_bind_hb = args.p2p_bind.clone();

    loop {
        tokio::select! {
            _ = shutdown_rx_loop.changed() => {
                if *shutdown_rx_loop.borrow() {
                    log::info!("Initiating main loop shutdown sequence...");
                    break;
                }
            }

            _ = ticker.tick() => {
                atp_controller.reset();

                let hb_msg = format!("HEARTBEAT:ID={}|NAME=Sokol-Node-{}|EP={}|MODE=NORMAL\n", node_id_hb, node_id_hb, p2p_bind_hb);
                push_telemetry(&hb_msg).await;

                if !atp_controller.try_consume(250) {
                    log::warn!("[ATP THROTTLE] Execution budget exceeded for current tick, skipping heavy analytical cycle.");
                    continue;
                }

                let mut total_rx_packets = 0u64;
                let mut total_rx_bytes = 0u64;
                let mut total_dropped = 0u64;

                if let Ok(per_cpu_stats) = stats_map.get(&0u32, 0) {
                    for cpu_stat in per_cpu_stats.iter() {
                        total_rx_packets += cpu_stat.0.rx_packets;
                        total_rx_bytes += cpu_stat.0.rx_bytes;
                        total_dropped += cpu_stat.0.dropped_packets;
                    }
                }

                let delta_packets = total_rx_packets.saturating_sub(prev_packets);
                let delta_bytes = total_rx_bytes.saturating_sub(prev_bytes);
                let delta_dropped = total_dropped.saturating_sub(prev_dropped);

                let dt = 1.0;
                let is_anomaly = sokol_engine.detect_anomaly(
                    total_rx_packets as f64,
                    prev_packets as f64,
                    dt,
                ).unwrap_or_default();

                let flow_rate = SokolEngine::compute_flow_rate(delta_packets, dt);

                prev_packets = total_rx_packets;
                prev_bytes = total_rx_bytes;
                prev_dropped = total_dropped;
                let first_tick = !have_baseline;
                have_baseline = true;

                if !first_tick && (is_anomaly || delta_dropped > 0) {
                    log::warn!(
                        "[SOKOL ANOMALY DETECTED] Flow Rate: {:.2} pkts/s | Pkts/s: {} | Bytes/s: {} | Drops/s: {} | Drops total: {}",
                        flow_rate.0, delta_packets, delta_bytes, delta_dropped, total_dropped
                    );
                    
                    let anomaly_telemetry = format!(
                        "DB_LOG:NODE={}|TIER=Tier3AiAnomaly|IP=0.0.0.0|VEC=Anomaly detected, flow rate {:.2}\n",
                        node_id_hb, flow_rate.0
                    );
                    push_telemetry(&anomaly_telemetry).await;
                }

                let telemetry_stat = format!(
                    "STAT:NODE={}|RX_PKTS={}|RX_BYTES={}|DROPPED={}|FLOW={:.2}\n",
                    node_id_hb, total_rx_packets, total_rx_bytes, total_dropped, flow_rate.0
                );
                push_telemetry(&telemetry_stat).await;
            }
        }
    }

    log::info!("Sokol-Core main loop terminated gracefully. Cleaning up resources...");
    let _ = std::fs::remove_file(socket_path);

    Ok(())
}