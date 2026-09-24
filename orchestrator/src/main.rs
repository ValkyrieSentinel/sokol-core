#![allow(dead_code)]
pub use mesh_sync::{AlertLevel, MeshCommand, MeshOrchestrator};
mod block_policy;
mod block_table;
pub mod cluster_state;
mod control;
mod flowspec;
mod mesh_sync;
mod metrics;
mod p2p;
mod signal;
mod sokol;

use aya::maps::{Array, LpmTrie, MapData, PerCpuArray, RingBuf};
use aya::programs::{Xdp, XdpFlags};
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
use common::audit_log::{AuditLog, Rotation};
use common::canonical::CanonicalParser;
use common::{DropEvent, NodeTelemetry};

use crate::block_policy::BlockPolicy;
use crate::block_table::{BlockTable, Lifetime, TtlPolicy, Watermark};
use crate::cluster_state::BirdEyeView;
use crate::p2p::{connect_to_peer, DagTracker, NodeCrypto, P2PNetwork, PeerRegistry, TrustStore};

/// Audit trail writer. Records are queued (bounded, so a flood cannot exhaust memory) and
/// written by one thread, fsynced every 100 ms or 64 records: a crash loses at most that window.
enum AuditMsg {
    Record(String),
    Flush(std::sync::mpsc::SyncSender<()>),
}

pub struct SentinelDb {
    tx: std::sync::mpsc::SyncSender<AuditMsg>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
    overflow_total: std::sync::atomic::AtomicU64,
}

impl SentinelDb {
    const QUEUE_CAPACITY: usize = 10_000;
    const SYNC_INTERVAL: Duration = Duration::from_millis(100);
    const SYNC_BATCH: usize = 64;

    pub fn init(path: &str, rotation: Option<Rotation>) -> anyhow::Result<Self> {
        let mut log = AuditLog::open_with(std::path::Path::new(path), rotation)
            .map_err(|e| anyhow::anyhow!("{} ({})", e, path))?;
        log::info!("Audit log {} opened: {} records verified", path, log.len());

        let (tx, rx) = std::sync::mpsc::sync_channel::<AuditMsg>(Self::QUEUE_CAPACITY);
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped_writer = dropped.clone();

        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            use std::sync::mpsc::RecvTimeoutError;
            loop {
                match rx.recv_timeout(Self::SYNC_INTERVAL) {
                    Ok(AuditMsg::Flush(ack)) => {
                        if let Err(e) = log.sync() {
                            log::error!("[Audit] fsync failed: {}", e);
                        }
                        let _ = ack.send(());
                    }
                    Ok(AuditMsg::Record(payload)) => {
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

        Ok(Self {
            tx,
            dropped,
            overflow_total: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn overflow_total(&self) -> u64 {
        self.overflow_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Waits until everything queued so far is written and fsynced (used on shutdown).
    pub fn flush(&self, wait: Duration) {
        let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel(1);
        if self.tx.send(AuditMsg::Flush(ack_tx)).is_ok() && ack_rx.recv_timeout(wait).is_err() {
            log::error!("[Audit] Flush did not complete within {:?}", wait);
        }
    }

    pub fn append(&self, data: String) {
        match self.tx.try_send(AuditMsg::Record(data)) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.overflow_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
#[command(
    author,
    version,
    about = "Sokol-Core Sovereign Orchestrator - Production Node"
)]
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

    /// Control socket for local tools (trident_trap uses SOKOL_IPC_SOCKET to find it).
    /// Under systemd use a RuntimeDirectory, e.g. /run/sokol/sokol.sock.
    #[arg(long, default_value = "/run/sokol.sock")]
    ipc_socket: String,

    /// Lifetime of a first dynamic block (trap, IPC, mesh) in seconds; repeats within 24 h
    /// double it up to --block-ttl-max. 0 makes dynamic blocks permanent. --block is always permanent.
    #[arg(long, default_value = "900")]
    block_ttl: u64,

    #[arg(long, default_value = "86400")]
    block_ttl_max: u64,

    /// Serve Prometheus metrics at http://<addr>/metrics (e.g. 127.0.0.1:9469). Off by default.
    #[arg(long, value_name = "ADDR")]
    metrics_bind: Option<std::net::SocketAddr>,

    /// Operator control socket (BAN_IP, UNBAN_IP, FLUSH_BANS) used by sokol-operator.
    /// Kept apart from --ipc-socket so traps cannot lift bans.
    #[arg(long, default_value = "/run/sokol-control.sock")]
    control_socket: String,

    /// Group allowed to use the control socket (0660); without it root-only (0600).
    #[arg(long)]
    control_group: Option<String>,

    /// XDP attach mode: `native` (driver, fastest; fails if the NIC driver lacks XDP),
    /// `generic` (SKB mode, works everywhere, much slower), or `auto` (kernel's choice).
    #[arg(long, value_enum, default_value = "auto")]
    xdp_mode: XdpMode,

    /// Rotate the audit log when it reaches this size (bytes); 0 disables rotation.
    #[arg(long, default_value = "104857600")]
    audit_max_bytes: u64,

    /// Rotated audit segments to keep (older ones are deleted).
    #[arg(long, default_value = "10")]
    audit_keep: usize,

    /// Announce every block upstream as a BGP Flowspec "discard source" rule through this
    /// GoBGP CLI binary (the gobgpd it talks to must peer with the upstream routers).
    #[arg(long, value_name = "PATH")]
    flowspec_gobgp: Option<std::path::PathBuf>,

    /// Argument passed to the GoBGP CLI before the command (repeatable), e.g.
    /// --flowspec-gobgp-arg=-p --flowspec-gobgp-arg=50051
    #[arg(long, value_name = "ARG", allow_hyphen_values = true)]
    flowspec_gobgp_arg: Vec<String>,

    /// Drops per second at which this node reports itself under attack to the mesh.
    #[arg(long, default_value = "1000")]
    attack_drops_per_sec: u64,

    /// Share of live nodes under attack above which the cluster is in a distributed storm.
    #[arg(long, default_value = "0.5")]
    storm_threshold: f64,
}

/// How often each node reports its load to itself and its mesh peers.
const TELEMETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum XdpMode {
    Auto,
    Native,
    Generic,
}

impl XdpMode {
    fn flags(self) -> XdpFlags {
        match self {
            XdpMode::Auto => XdpFlags::default(),
            XdpMode::Native => XdpFlags::DRV_MODE,
            XdpMode::Generic => XdpFlags::SKB_MODE,
        }
    }
}

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
            Err(_) => raw.parse::<IpAddr>().map(ipnet::IpNet::from).map_err(|_| {
                anyhow::anyhow!("--never-block '{}' is not an IP address or CIDR", raw)
            })?,
        };
        policy.protect(net, "operator never-block range");
    }
    Ok(policy)
}

/// Binds a Unix socket that only root, or members of `gid`, can connect to.
fn bind_private_socket(path: &str, gid: Option<u32>) -> anyhow::Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)
        .map_err(|e| anyhow::anyhow!("Failed to bind Unix socket at {}: {}", path, e))?;
    match gid {
        Some(gid) => {
            std::os::unix::fs::chown(path, None, Some(gid))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        }
        None => std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?,
    }
    Ok(listener)
}

struct ControlCtx {
    blocks: SharedBlockTable,
    policy: Arc<BlockPolicy>,
    sntl_db: Arc<SentinelDb>,
    registry: PeerRegistry,
    peers_file: Option<std::path::PathBuf>,
}

async fn execute_control(cmd: control::ControlCommand, ctx: &ControlCtx) -> String {
    use control::ControlCommand;
    let (blocks, policy, sntl_db) = (&ctx.blocks, &ctx.policy, &ctx.sntl_db);
    match cmd {
        ControlCommand::Ban(ip) => {
            if let Err(why) = policy.check(ip) {
                return format!("ERR {} is protected ({})", ip, why);
            }
            let result =
                blocks
                    .lock()
                    .await
                    .insert(ip, Lifetime::Permanent, std::time::Instant::now());
            match result {
                Ok(_) => {
                    log::warn!("[Control] Operator ban for {}", ip);
                    sntl_db.append(format!("OPERATOR_BAN_{}|IP:{}", ip_tag(ip), ip));
                    format!("OK banned {}", ip)
                }
                Err(e) => format!("ERR kernel map update failed: {:?}", e),
            }
        }
        ControlCommand::Unban(ip) => {
            let result = blocks.lock().await.remove(ip);
            match result {
                Ok(()) => {
                    log::warn!("[Control] Operator unban for {}", ip);
                    sntl_db.append(format!("OPERATOR_UNBAN_{}|IP:{}", ip_tag(ip), ip));
                    format!("OK unbanned {}", ip)
                }
                Err(e) => format!(
                    "ERR {} was not blocked or could not be removed: {:?}",
                    ip, e
                ),
            }
        }
        ControlCommand::FlushDynamic => {
            let released = blocks.lock().await.flush_dynamic();
            log::warn!(
                "[Control] Operator flushed {} dynamic blocks",
                released.len()
            );
            sntl_db.append(format!("OPERATOR_FLUSH|Released:{}", released.len()));
            format!("OK released {} dynamic blocks", released.len())
        }
        ControlCommand::ReloadPeers => match &ctx.peers_file {
            None => "ERR no --peers-file configured".to_string(),
            Some(path) => match TrustStore::load(path) {
                Ok(trust) => {
                    let pinned = ctx.registry.reload(trust);
                    log::warn!(
                        "[Control] Reloaded {}: {} pinned peers",
                        path.display(),
                        pinned
                    );
                    sntl_db.append(format!("PEERS_RELOADED|Pinned:{}", pinned));
                    format!("OK {} pinned peers", pinned)
                }
                // A broken file must not wipe the current trust: keep it and report.
                Err(e) => format!("ERR {:#}; previous trust store kept", e),
            },
        },
        ControlCommand::Unsupported(why) => format!("ERR {}", why),
    }
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

type SharedBlockTable = Arc<tokio::sync::Mutex<BlockTable>>;

fn ip_tag(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "V4"
    } else {
        "V6"
    }
}

fn ttl_label(ttl: Option<Duration>) -> String {
    match ttl {
        Some(d) => format!("{}s", d.as_secs()),
        None => "permanent".to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn enforce_block_local(
    ip: IpAddr,
    reason: &str,
    blocks: &SharedBlockTable,
    sntl_db: &Arc<SentinelDb>,
    registry: &PeerRegistry,
    node_id: u64,
    node_crypto: &Arc<NodeCrypto>,
    dag_tracker: &Arc<tokio::sync::Mutex<DagTracker>>,
    policy: &BlockPolicy,
) {
    let ip = ip.to_canonical();
    if let Err(why) = policy.check(ip) {
        log::error!(
            "[Local Security] Refusing to block {} ({}) | Requested for: {}",
            ip,
            why,
            reason
        );
        sntl_db.append(format!(
            "BLOCK_REFUSED|IP:{}|Protected:{}|Reason:{}",
            ip, why, reason
        ));
        return;
    }
    let result = blocks
        .lock()
        .await
        .insert(ip, Lifetime::Dynamic, std::time::Instant::now());
    match result {
        Ok(ttl) => {
            log::warn!(
                "[Local Security] Dynamic block enforced in XDP: {} for {} | Reason: {}",
                ip,
                ttl_label(ttl),
                reason
            );
            sntl_db.append(format!(
                "DYNAMIC_BLOCK_{}|IP:{}|TTL:{}|Reason:{}|Enforced",
                ip_tag(ip),
                ip,
                ttl_label(ttl),
                reason
            ));

            let telemetry_msg = format!(
                "DROP_IMMEDIATE:{}\nDB_LOG:NODE={}|TIER=Tier1BotTarpit|IP={}|VEC={}\n",
                ip, node_id, ip, reason
            );
            push_telemetry(&telemetry_msg).await;

            let broadcast_cmd = MeshCommand::BlockIp {
                ip: ip.to_string(),
                reason: reason.to_string(),
            };
            let _ = registry
                .broadcast(&broadcast_cmd, node_id, node_crypto, dag_tracker)
                .await;
        }
        Err(e) => {
            log::error!(
                "[Local Security] Failed to insert {} into eBPF: {:?}",
                ip,
                e
            );
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
            log::warn!(
                "[P2P] No --peers-file given: mesh messages from all peers will be rejected."
            );
            TrustStore::default()
        }
    };

    let block_policy = Arc::new(build_block_policy(&args)?);
    let ipc_gid = args.ipc_group.as_deref().map(resolve_group).transpose()?;
    let control_gid = args
        .control_group
        .as_deref()
        .map(resolve_group)
        .transpose()?;

    log::info!(
        "Initializing Sokol-Core Production Daemon on interface: {} [Node ID: {}]",
        args.interface,
        args.node_id
    );

    let atp_controller = AtpBudgetController::new(10_000_000);

    let rotation = (args.audit_max_bytes > 0).then_some(Rotation {
        max_bytes: args.audit_max_bytes,
        keep: args.audit_keep,
    });
    let sntl_db = Arc::new(SentinelDb::init(&args.db_path, rotation)?);

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
        let config_map = bpf
            .map_mut("CONFIG")
            .ok_or_else(|| anyhow::anyhow!("CONFIG map missing"))?;
        let mut config = Array::<_, u32>::try_from(config_map)?;
        config.set(0, config_flags, 0)?;
    }

    let prog_mut = bpf
        .program_mut("sentinel_vfr_filter")
        .ok_or_else(|| anyhow::anyhow!("Critical: Program sentinel_vfr_filter not found in ELF"))?;
    let program: &mut Xdp = prog_mut.try_into()?;
    let _link = program
        .attach(&args.interface, args.xdp_mode.flags())
        .map_err(|e| {
            anyhow::anyhow!(
                "XDP attach to {} in {:?} mode failed: {}",
                args.interface,
                args.xdp_mode,
                e
            )
        })?;
    log::info!(
        "XDP program successfully locked and attached to interface: {} (mode: {:?})",
        args.interface,
        args.xdp_mode
    );

    let blocklist_v4_data = bpf
        .take_map("BLOCKLIST_V4")
        .ok_or_else(|| anyhow::anyhow!("BLOCKLIST_V4 missing"))?;
    let blocklist_v4_trie = LpmTrie::<MapData, [u8; 4], u32>::try_from(blocklist_v4_data)?;

    let blocklist_v6_data = bpf
        .take_map("BLOCKLIST_V6")
        .ok_or_else(|| anyhow::anyhow!("BLOCKLIST_V6 missing"))?;
    let blocklist_v6_trie = LpmTrie::<MapData, [u8; 16], u32>::try_from(blocklist_v6_data)?;
    let ttl_policy = TtlPolicy {
        base: Duration::from_secs(args.block_ttl),
        max: Duration::from_secs(args.block_ttl_max.max(args.block_ttl)),
    };
    let blocks: SharedBlockTable = Arc::new(tokio::sync::Mutex::new(BlockTable::new(
        blocklist_v4_trie,
        blocklist_v6_trie,
        ttl_policy,
    )));

    let stats_map_data = bpf
        .take_map("STATS")
        .ok_or_else(|| anyhow::anyhow!("STATS map missing"))?;
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
                                                let event = unsafe {
                                                    std::ptr::read_unaligned(
                                                        item.as_ptr() as *const DropEvent
                                                    )
                                                };
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
                                        log::error!(
                                            "[eBPF RingBuf] Failed to get readable guard: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log::error!(
                            "[eBPF RingBuf] Failed to wrap ring buffer in AsyncFd: {}",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "[eBPF RingBuf] Failed to create RingBuf from map data: {}",
                    e
                );
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
            blocks
                .lock()
                .await
                .insert(ip, Lifetime::Permanent, std::time::Instant::now())?;
            sntl_db.append(format!(
                "STATIC_BLOCK_{}|IP:{}|Action:XDP_DROP",
                ip_tag(ip),
                ip
            ));
            log::info!("[STATIC BLOCK] Enforced permanent block for CLI IP: {}", ip);
        } else {
            log::error!(
                "[STATIC BLOCK] Invalid CLI --block IP argument: '{}'",
                ip_str
            );
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx_ctrlc = shutdown_tx.clone();

    ctrlc::set_handler(move || {
        log::warn!("SIGINT/SIGTERM received. Teardown initiated...");
        let _ = shutdown_tx_ctrlc.send(true);
    })?;

    let peer_registry = PeerRegistry::new(trust_store);
    let (mesh_cmd_tx, mut mesh_cmd_rx) = mpsc::channel::<MeshCommand>(1000);

    let dag_tracker = Arc::new(tokio::sync::Mutex::new(DagTracker::new()));

    let p2p_bind_addr: std::net::SocketAddr =
        args.p2p_bind.parse().expect("Invalid P2P bind address");

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
                )
                .await
                {
                    log::warn!(
                        "[P2P] Failed to connect to seed peer {}: {:?}",
                        seed_addr,
                        e
                    );
                }
            });
        }
    }

    // Nodes report every TELEMETRY_INTERVAL; one missed report is tolerated, three are not.
    let bird_eye = BirdEyeView::new(args.storm_threshold, TELEMETRY_INTERVAL * 3);
    let (telemetry_tx, telemetry_rx) = mpsc::channel::<NodeTelemetry>(1000);
    let telemetry_tx_mesh = telemetry_tx.clone();
    let cluster_summary = Arc::new(std::sync::RwLock::new(mesh_sync::ClusterSummary::default()));

    let blocks_mesh = blocks.clone();
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
                            log::error!(
                                "[Mesh] Refusing mesh BlockIp for protected {} ({}): {}",
                                ip_addr,
                                why,
                                reason
                            );
                            sntl_db_mesh.append(format!(
                                "MESH_BLOCK_REFUSED|IP:{}|Protected:{}|Reason:{}",
                                ip_addr, why, reason
                            ));
                            continue;
                        }
                        let result = blocks_mesh.lock().await.insert(
                            ip_addr,
                            Lifetime::Dynamic,
                            std::time::Instant::now(),
                        );
                        match result {
                            Err(e) => log::error!(
                                "[Mesh] Failed to insert {} into eBPF: {:?}",
                                ip_addr,
                                e
                            ),
                            Ok(ttl) => {
                                log::warn!(
                                    "[Mesh] Synchronized block for {} ({}) across mesh: {}",
                                    ip_addr,
                                    ttl_label(ttl),
                                    reason
                                );
                                sntl_db_mesh.append(format!(
                                    "MESH_BLOCK_{}|IP:{}|TTL:{}|Reason:{}",
                                    ip_tag(ip_addr),
                                    ip_addr,
                                    ttl_label(ttl),
                                    reason
                                ));

                                let telemetry_msg = format!(
                                    "DB_LOG:NODE={}|TIER=Tier1_5Revenge|IP={}|VEC={}\n",
                                    node_id_mesh, ip_addr, reason
                                );
                                push_telemetry(&telemetry_msg).await;
                            }
                        }
                    } else {
                        log::error!(
                            "[Mesh] Received unparseable IP in BlockIp command: '{}'",
                            ip
                        );
                    }
                }
                MeshCommand::UnblockIp { ip } => {
                    let clean_ip = ip.trim();
                    if let Ok(ip_addr) = clean_ip.parse::<IpAddr>() {
                        let result = blocks_mesh.lock().await.remove_dynamic(ip_addr);
                        match result {
                            Ok(true) => {
                                log::info!("[Mesh] Unblocked {} per mesh command", ip_addr);
                                sntl_db_mesh.append(format!("MESH_UNBLOCK|IP:{}", ip_addr));
                            }
                            Ok(false) => log::warn!(
                                "[Mesh] Ignoring mesh UnblockIp for operator block {}",
                                ip_addr
                            ),
                            Err(e) => log::error!("[Mesh] Failed to unblock {}: {:?}", ip_addr, e),
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
                telemetry @ MeshCommand::Telemetry { .. } => {
                    if let Some(record) = telemetry.telemetry_record() {
                        let _ = telemetry_tx_mesh.try_send(record);
                    }
                }
            }
        }
    });

    let upstream_router_addr: std::net::SocketAddr = args
        .upstream_router
        .parse()
        .expect("Invalid upstream router address");
    let mesh_orchestrator = MeshOrchestrator::new(
        bird_eye,
        telemetry_rx,
        mesh_cmd_tx.clone(),
        sntl_db.clone(),
        shutdown_rx.clone(),
        upstream_router_addr,
        args.ipv6_prefix.clone(),
        Duration::from_secs(30),
        cluster_summary.clone(),
    );

    let mut orchestrator_task = mesh_orchestrator;
    tokio::spawn(async move {
        if let Err(e) = orchestrator_task.run_telemetry_processor().await {
            log::error!("[Mesh] Orchestrator telemetry processor failed: {}", e);
        }
    });

    for &port in &args.trap_port {
        let blocks_trap = blocks.clone();
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
                                log::warn!(
                                    "[TRAP HIT] Unauthorized connection on port {} from {}",
                                    port,
                                    ip
                                );

                                let reason = format!("Decoy TCP trap hit on port {}", port);
                                enforce_block_local(
                                    ip,
                                    &reason,
                                    &blocks_trap,
                                    &db_trap,
                                    &registry_trap,
                                    node_id_trap,
                                    &crypto_trap,
                                    &dag_trap,
                                    &policy_trap,
                                )
                                .await;
                                db_trap.append(format!(
                                    "TRAP_HIT|Port:{}|IP:{}|Action:EnforcedDrop",
                                    port, ip
                                ));

                                let telemetry_msg = format!(
                                    "DB_LOG:NODE={}|TIER=Tier1BotTarpit|IP={}|VEC={}\n",
                                    node_id_trap, ip, reason
                                );
                                push_telemetry(&telemetry_msg).await;
                            }
                            Err(e) => {
                                log::error!(
                                    "[TRAP] Accept error on port {}: {}. Retrying...",
                                    port,
                                    e
                                );
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

    // Anyone who can write to this socket can make the node drop arbitrary sources and push
    // the block to the whole mesh, so it is root-only unless an operator group is named.
    let socket_path = args.ipc_socket.as_str();
    let unix_listener = bind_private_socket(socket_path, ipc_gid)?;

    let control_listener = bind_private_socket(&args.control_socket, control_gid)?;
    let ctl_ctx = Arc::new(ControlCtx {
        blocks: blocks.clone(),
        policy: block_policy.clone(),
        sntl_db: sntl_db.clone(),
        registry: peer_registry.clone(),
        peers_file: args.peers_file.clone(),
    });
    tokio::spawn(async move {
        loop {
            let (stream, _) = match control_listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    log::error!("[Control] Accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let ctx = ctl_ctx.clone();
            tokio::spawn(async move {
                let (read_half, mut write_half) = stream.into_split();
                let mut reader = BufReader::new(read_half);
                let mut line = String::new();
                loop {
                    line.clear();
                    match (&mut reader)
                        .take(control::MAX_LINE)
                        .read_line(&mut line)
                        .await
                    {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let reply = match control::parse(&line) {
                        Ok(cmd) => execute_control(cmd, &ctx).await,
                        Err(e) => format!("ERR {}", e),
                    };
                    if write_half
                        .write_all(format!("{}\n", reply).as_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });

    let blocks_unix = blocks.clone();
    let db_unix = sntl_db.clone();
    let registry_unix = peer_registry.clone();

    let crypto_unix = node_crypto.clone();
    let dag_unix = dag_tracker.clone();
    let node_id_unix = args.node_id;
    let policy_unix = block_policy.clone();

    let socket_path_log = socket_path.to_string();
    tokio::spawn(async move {
        log::info!(
            "[UNIX SOCKET] Listening for trap events on {}",
            socket_path_log
        );
        loop {
            match unix_listener.accept().await {
                Ok((stream, _)) => {
                    let blocks_stream = blocks_unix.clone();
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
                                Ok(_)
                                    if !line.ends_with('\n')
                                        && line.len() as u64 >= MAX_IPC_LINE =>
                                {
                                    log::error!("[UNIX IPC FAULT] Line over {} bytes from uid {:?}; closing connection", MAX_IPC_LINE, peer_uid);
                                    break;
                                }
                                Ok(_) => {
                                    log::debug!(
                                        "[UNIX IPC] command from uid {:?}: {}",
                                        peer_uid,
                                        line.trim()
                                    );
                                    let content = line.trim();
                                    if content.is_empty() {
                                        continue;
                                    }

                                    if content.starts_with('{') {
                                        if let Err(e) =
                                            CanonicalParser::validate_strict_json_object(content)
                                        {
                                            log::error!("[CANONICAL FAULT] Rejected malformed IPC payload: {:?}", e);
                                            continue;
                                        }
                                    }

                                    if let Some(raw_ip_str) =
                                        content.strip_prefix("DROP_IMMEDIATE:")
                                    {
                                        let clean_ip_str = raw_ip_str.trim();
                                        match clean_ip_str.parse::<IpAddr>() {
                                            Ok(ip) => {
                                                log::warn!(
                                                    "[XDP_ACTION] Trap triggered ban for IP: {}",
                                                    ip
                                                );
                                                enforce_block_local(
                                                    ip,
                                                    "Unix IPC DROP_IMMEDIATE trigger",
                                                    &blocks_stream,
                                                    &db,
                                                    &registry,
                                                    node_id_unix,
                                                    &crypto_stream,
                                                    &dag_stream,
                                                    &policy_stream,
                                                )
                                                .await;
                                            }
                                            Err(e) => {
                                                log::error!(
                                                    "[UNIX IPC FAULT] Failed to parse IP from 'DROP_IMMEDIATE:{}': {}",
                                                    raw_ip_str,
                                                    e
                                                );
                                            }
                                        }
                                    } else if let Some(raw_ip_str) =
                                        content.strip_prefix("APT_HIGH_PRIORITY:")
                                    {
                                        let clean_ip_str = raw_ip_str.trim();
                                        match clean_ip_str.parse::<IpAddr>() {
                                            Ok(ip) => {
                                                log::warn!(
                                                    "[APT_ALERT] High-priority stager from IP: {}",
                                                    ip
                                                );
                                                db.append(format!(
                                                    "APT_HIGH_PRIORITY|IP:{}|Enforced",
                                                    ip
                                                ));

                                                let telemetry_msg = format!("DB_LOG:NODE={}|TIER=Tier2AptSandbox|IP={}|VEC=APT High-Priority Stager\n", node_id_unix, ip);
                                                push_telemetry(&telemetry_msg).await;

                                                enforce_block_local(
                                                    ip,
                                                    "Unix IPC APT_HIGH_PRIORITY stager",
                                                    &blocks_stream,
                                                    &db,
                                                    &registry,
                                                    node_id_unix,
                                                    &crypto_stream,
                                                    &dag_stream,
                                                    &policy_stream,
                                                )
                                                .await;
                                            }
                                            Err(e) => {
                                                log::error!(
                                                    "[UNIX IPC FAULT] Failed to parse IP from 'APT_HIGH_PRIORITY:{}': {}",
                                                    raw_ip_str,
                                                    e
                                                );
                                            }
                                        }
                                    } else if let Some(payload) = content.strip_prefix("SIGNAL:") {
                                        match signal::parse(payload) {
                                            Ok(sig) => match signal::target(&sig, &policy_stream) {
                                                Ok(ip) => {
                                                    db.append(format!(
                                                        "SIGNAL|Source:{}|Src:{}|Dst:{}|Target:{}|Reason:{}",
                                                        sig.source,
                                                        sig.src,
                                                        sig.dst.map(|d| d.to_string()).unwrap_or_else(|| "-".into()),
                                                        ip,
                                                        sig.reason
                                                    ));
                                                    let reason =
                                                        format!("{}: {}", sig.source, sig.reason);
                                                    enforce_block_local(
                                                        ip,
                                                        &reason,
                                                        &blocks_stream,
                                                        &db,
                                                        &registry,
                                                        node_id_unix,
                                                        &crypto_stream,
                                                        &dag_stream,
                                                        &policy_stream,
                                                    )
                                                    .await;
                                                }
                                                Err(why) => {
                                                    log::warn!(
                                                        "[Signal] {} signal not enforced: {}",
                                                        sig.source,
                                                        why
                                                    );
                                                    db.append(format!(
                                                        "SIGNAL_REFUSED|Source:{}|Src:{}|Why:{}",
                                                        sig.source, sig.src, why
                                                    ));
                                                }
                                            },
                                            Err(e) => log::error!(
                                                "[UNIX IPC FAULT] Bad SIGNAL line: {}",
                                                e
                                            ),
                                        }
                                    } else if let Some(log_content) =
                                        content.strip_prefix("DB_LOG:")
                                    {
                                        db.append(log_content.trim().to_string());
                                        let telemetry_msg = format!(
                                            "DB_LOG:NODE={}|{}\n",
                                            node_id_unix,
                                            log_content.trim()
                                        );
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

    let metrics_snapshot = Arc::new(std::sync::RwLock::new(metrics::Snapshot::default()));
    if let Some(addr) = args.metrics_bind {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind metrics endpoint {}: {}", addr, e))?;
        let snapshot = metrics_snapshot.clone();
        let app = axum::Router::new().route(
            "/metrics",
            axum::routing::get(move || {
                let snapshot = snapshot.clone();
                async move {
                    let body = metrics::render(&snapshot.read().unwrap_or_else(|p| p.into_inner()));
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "text/plain; version=0.0.4",
                        )],
                        body,
                    )
                }
            }),
        );
        log::info!("[Metrics] Prometheus endpoint on http://{}/metrics", addr);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                log::error!("[Metrics] server stopped: {}", e);
            }
        });
    }

    log::info!("Sokol-Core running with SokolEngine anomaly detection & sovereign mesh verification loops.");

    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut shutdown_rx_loop = shutdown_rx.clone();
    let node_id_hb = args.node_id;
    let p2p_bind_hb = args.p2p_bind.clone();
    let control_socket_hb = args.control_socket.clone();
    let mut watermark = Watermark::default();
    let mut telemetry_window_start = std::time::Instant::now();
    let mut window_rx = 0u64;
    let mut window_dropped = 0u64;
    let flowspec_cli = args.flowspec_gobgp.clone().map(|bin| flowspec::GobgpCli {
        bin,
        args: args.flowspec_gobgp_arg.clone(),
    });
    let mut flowspec_state = flowspec::Reconciler::default();

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

                let released = blocks.lock().await.expire(std::time::Instant::now());
                for ip in released {
                    log::info!("[BlockTable] Block for {} expired; traffic allowed again", ip);
                    sntl_db.append(format!("BLOCK_EXPIRED_{}|IP:{}", ip_tag(ip), ip));
                }

                let hb_msg = format!("HEARTBEAT:ID={}|NAME=Sokol-Node-{}|EP={}|MODE=NORMAL|CTL={}\n", node_id_hb, node_id_hb, p2p_bind_hb, control_socket_hb);
                push_telemetry(&hb_msg).await;

                if !atp_controller.try_consume(250) {
                    log::warn!("[ATP THROTTLE] Execution budget exceeded for current tick, skipping heavy analytical cycle.");
                    continue;
                }

                let mut total_rx_packets = 0u64;
                let mut total_rx_bytes = 0u64;
                let mut total_dropped = 0u64;
                let mut snapshot = metrics::Snapshot::default();

                if let Ok(per_cpu_stats) = stats_map.get(&0u32, 0) {
                    for cpu_stat in per_cpu_stats.iter() {
                        total_rx_packets += cpu_stat.0.rx_packets;
                        total_rx_bytes += cpu_stat.0.rx_bytes;
                        total_dropped += cpu_stat.0.dropped_packets;
                        snapshot.events_suppressed += cpu_stat.0.events_suppressed;
                        for (sum, n) in snapshot.drops_by_reason.iter_mut().zip(cpu_stat.0.drops_by_reason) {
                            *sum += n;
                        }
                    }
                }
                snapshot.rx_packets = total_rx_packets;
                snapshot.rx_bytes = total_rx_bytes;
                snapshot.dropped_packets = total_dropped;
                let (v4_active, v6_active) = blocks.lock().await.active_by_family();
                snapshot.blocks_active_v4 = v4_active;
                snapshot.blocks_active_v6 = v6_active;
                snapshot.blocks_capacity = common::BLOCKLIST_CAPACITY as usize;
                for message in watermark.update((v4_active, v6_active), common::BLOCKLIST_CAPACITY as usize) {
                    log::warn!("[BlockTable] {}", message);
                    sntl_db.append(format!("BLOCKLIST_WATERMARK|{}", message));
                }
                snapshot.p2p_peers = peer_registry.peer_count().await;
                snapshot.audit_queue_overflow = sntl_db.overflow_total();

                if telemetry_window_start.elapsed() >= TELEMETRY_INTERVAL {
                    let secs = telemetry_window_start.elapsed().as_secs_f64().max(1.0);
                    let rx_pps = (total_rx_packets.saturating_sub(window_rx) as f64 / secs) as u64;
                    let drops_per_sec = (total_dropped.saturating_sub(window_dropped) as f64 / secs) as u64;
                    let report = MeshCommand::Telemetry {
                        node_id: node_id_hb,
                        rx_pps,
                        drops_per_sec,
                        under_attack: drops_per_sec >= args.attack_drops_per_sec,
                        blocks_active: (v4_active + v6_active) as u64,
                    };
                    if let Some(record) = report.telemetry_record() {
                        let _ = telemetry_tx.try_send(record);
                    }
                    if let Err(e) = peer_registry.broadcast(&report, node_id_hb, &node_crypto, &dag_tracker).await {
                        log::warn!("[Mesh] Telemetry broadcast failed: {:#}", e);
                    }
                    telemetry_window_start = std::time::Instant::now();
                    window_rx = total_rx_packets;
                    window_dropped = total_dropped;
                }
                let cluster = *cluster_summary.read().unwrap_or_else(|p| p.into_inner());
                snapshot.cluster_status = cluster.status_code;
                snapshot.cluster_nodes = cluster.nodes;
                snapshot.cluster_attacked = cluster.attacked;
                snapshot.cluster_storm_engaged = cluster.storm_engaged;

                if let Some(cli) = &flowspec_cli {
                    let active = blocks.lock().await.active_ips();
                    let (announce, withdraw) = flowspec_state.plan(&active);
                    for (is_announce, ip) in withdraw.into_iter().map(|ip| (false, ip)).chain(announce.into_iter().map(|ip| (true, ip))) {
                        match cli.apply(is_announce, ip).await {
                            Ok(()) => {
                                let verb = if is_announce { "announced" } else { "withdrew" };
                                log::info!("[Flowspec] {} discard rule for {}", verb, ip);
                                sntl_db.append(format!("FLOWSPEC_{}|IP:{}", if is_announce { "ANNOUNCE" } else { "WITHDRAW" }, ip));
                                if is_announce { flowspec_state.announced(ip) } else { flowspec_state.withdrawn(ip) }
                            }
                            Err(e) => {
                                log::error!("[Flowspec] gobgp failed for {}: {}; retrying next tick", ip, e);
                                break;
                            }
                        }
                    }
                    snapshot.flowspec_announced = flowspec_state.announced_count();
                }
                *metrics_snapshot.write().unwrap_or_else(|p| p.into_inner()) = snapshot;

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
    if let Some(cli) = &flowspec_cli {
        // The node's blocks vanish with it; do not leave its rules behind upstream.
        'withdraw_all: loop {
            let (_, withdraw) = flowspec_state.plan(&std::collections::HashSet::new());
            if withdraw.is_empty() {
                break;
            }
            for ip in withdraw {
                if let Err(e) = cli.apply(false, ip).await {
                    log::error!("[Flowspec] Could not withdraw {} on shutdown: {}", ip, e);
                    break 'withdraw_all;
                }
                flowspec_state.withdrawn(ip);
            }
        }
    }
    sntl_db.append("NODE_SHUTDOWN".to_string());
    sntl_db.flush(Duration::from_secs(2));
    let _ = std::fs::remove_file(socket_path);
    let _ = std::fs::remove_file(&args.control_socket);

    Ok(())
}
