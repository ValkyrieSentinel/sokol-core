#![allow(dead_code)]
// Release builds abort on panic (panic = "abort"), so a panic reachable from input (a peer's
// frame, an IPC line, a trap connection, a file) stops the node. Outside tests, code must not
// be able to panic: no unwrap/expect, no unchecked indexing or slicing, no panic!-family macros.
// A provably safe exception is allowed locally, with its reason.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
pub use mesh_sync::{AlertLevel, MeshCommand, MeshOrchestrator};
mod attack_reports;
mod block_policy;
mod block_table;
mod clock_watch;
pub mod cluster_state;
mod control;
mod defense;
mod flowspec;
mod kernel_events;
mod mesh_sync;
mod metrics;
mod p2p;
mod replay;
mod signal;
mod sokol;
mod state_store;

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

use common::audit_log::{AuditLog, Rotation};
use common::canonical::CanonicalParser;
use common::NodeTelemetry;

use crate::block_policy::{BlockPolicy, HostView, PolicyHandle};
use crate::block_table::{
    family_tag, host, parse_target, show, Adoption, BlockTable, ClaimKind, Envelope, LiftError,
    Quorum, TtlPolicy, Watermark,
};
use crate::cluster_state::BirdEyeView;
use crate::p2p::{
    maintain_peer_connection, now_ms, NodeCrypto, P2PNetwork, PeerRegistry, TrustStore,
};
use ipnet::IpNet;

/// Audit trail writer. Records are queued (bounded, so a flood cannot exhaust memory) and
/// written by one thread. A record is fsynced at most `SYNC_INTERVAL` after the last successful
/// sync (or after `SYNC_BATCH` records), whatever the pace of events.
///
/// ADR-5: enforcement never waits for the audit. When the log cannot be written the node keeps
/// blocking, counts what it could not record, reports itself DEGRADED (metrics, heartbeat) and
/// reopens the log, which drops a torn tail, until it can write again.
enum AuditMsg {
    Record(String),
    /// Acked with whether everything queued before it is written and fsynced.
    Flush(std::sync::mpsc::SyncSender<bool>),
}

/// What the audit writer last managed; read by metrics and the heartbeat.
#[derive(Default)]
pub struct AuditHealth {
    write_errors: std::sync::atomic::AtomicU64,
    sync_errors: std::sync::atomic::AtomicU64,
    /// Records that could not be written (log unavailable), besides queue overflow.
    lost: std::sync::atomic::AtomicU64,
    last_sync_ok_ms: std::sync::atomic::AtomicU64,
    failing: std::sync::atomic::AtomicBool,
}

/// A point-in-time view of [`AuditHealth`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditStatus {
    pub healthy: bool,
    pub write_errors: u64,
    pub sync_errors: u64,
    pub lost: u64,
    pub last_sync_age_ms: u64,
}

pub struct SentinelDb {
    tx: std::sync::mpsc::SyncSender<AuditMsg>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
    overflow_total: std::sync::atomic::AtomicU64,
    health: Arc<AuditHealth>,
}

struct AuditWriter {
    log: Option<AuditLog>,
    path: std::path::PathBuf,
    rotation: Option<Rotation>,
    health: Arc<AuditHealth>,
    last_sync: std::time::Instant,
    /// Records lost since the log was last writable; noted in the log once it is again.
    lost_pending: u64,
}

impl AuditWriter {
    fn fail(&self, what: &str, e: &dyn std::fmt::Display) {
        use std::sync::atomic::Ordering;
        if !self.health.failing.swap(true, Ordering::Relaxed) {
            log::error!(
                "[Audit] {} failed: {}; node is DEGRADED until the log recovers",
                what,
                e
            );
        }
    }

    /// Reopens the log after a failure (dropping the old handle first releases its lock).
    fn ensure_open(&mut self) -> bool {
        if self.log.is_some() {
            return true;
        }
        match AuditLog::open_with(&self.path, self.rotation) {
            Ok(log) => {
                self.log = Some(log);
                if self.lost_pending > 0 {
                    let note = format!("AUDIT_LOST|Records:{}", self.lost_pending);
                    if self.write(note).is_ok() {
                        self.lost_pending = 0;
                    }
                }
                self.log.is_some()
            }
            Err(e) => {
                self.fail("reopen", &e);
                false
            }
        }
    }

    fn write(&mut self, payload: String) -> Result<(), ()> {
        use std::sync::atomic::Ordering;
        let Some(log) = self.log.as_mut() else {
            return Err(());
        };
        match log.append(payload.as_bytes()) {
            Ok(_) => Ok(()),
            Err(common::audit_log::AuditError::PayloadTooLarge(n)) => {
                log::error!("[Audit] Record of {} bytes dropped: too large", n);
                Ok(())
            }
            Err(e) => {
                self.health.write_errors.fetch_add(1, Ordering::Relaxed);
                self.fail("write", &e);
                self.log = None;
                Err(())
            }
        }
    }

    fn record(&mut self, payload: String) {
        use std::sync::atomic::Ordering;
        if !self.ensure_open() || self.write(payload).is_err() {
            self.lost_pending += 1;
            self.health.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn sync(&mut self) -> bool {
        use std::sync::atomic::Ordering;
        self.last_sync = std::time::Instant::now();
        if !self.ensure_open() {
            return false;
        }
        let result = self.log.as_mut().map(|l| l.sync());
        match result {
            Some(Ok(())) => {
                self.health
                    .last_sync_ok_ms
                    .store(now_ms(), Ordering::Relaxed);
                if self.lost_pending == 0 && self.health.failing.swap(false, Ordering::Relaxed) {
                    log::warn!("[Audit] Log writable again; node no longer DEGRADED");
                }
                true
            }
            Some(Err(e)) => {
                self.health.sync_errors.fetch_add(1, Ordering::Relaxed);
                self.fail("fsync", &e);
                self.log = None;
                false
            }
            None => false,
        }
    }
}

impl SentinelDb {
    const QUEUE_CAPACITY: usize = 10_000;
    const SYNC_INTERVAL: Duration = Duration::from_millis(100);
    const SYNC_BATCH: usize = 64;

    pub fn init(path: &str, rotation: Option<Rotation>) -> anyhow::Result<Self> {
        let log = AuditLog::open_with(std::path::Path::new(path), rotation)
            .map_err(|e| anyhow::anyhow!("{} ({})", e, path))?;
        log::info!("Audit log {} opened: {} records verified", path, log.len());

        let (tx, rx) = std::sync::mpsc::sync_channel::<AuditMsg>(Self::QUEUE_CAPACITY);
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let dropped_writer = dropped.clone();
        let health = Arc::new(AuditHealth::default());
        health
            .last_sync_ok_ms
            .store(now_ms(), std::sync::atomic::Ordering::Relaxed);
        let mut writer = AuditWriter {
            log: Some(log),
            path: std::path::PathBuf::from(path),
            rotation,
            health: health.clone(),
            last_sync: std::time::Instant::now(),
            lost_pending: 0,
        };

        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            use std::sync::mpsc::RecvTimeoutError;
            loop {
                let wait = Self::SYNC_INTERVAL.saturating_sub(writer.last_sync.elapsed());
                match rx.recv_timeout(wait) {
                    Ok(AuditMsg::Flush(ack)) => {
                        let ok = writer.sync();
                        let _ = ack.send(ok);
                    }
                    Ok(AuditMsg::Record(payload)) => {
                        let lost = dropped_writer.swap(0, Ordering::Relaxed);
                        if lost > 0 {
                            writer.record(format!("AUDIT_QUEUE_OVERFLOW|Dropped:{}", lost));
                        }
                        writer.record(payload);
                        let unsynced = writer.log.as_ref().map_or(0, |l| l.unsynced());
                        if unsynced >= Self::SYNC_BATCH
                            || writer.last_sync.elapsed() >= Self::SYNC_INTERVAL
                        {
                            writer.sync();
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        writer.sync();
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            writer.sync();
            log::info!("SentinelDb persistence thread terminated.");
        });

        Ok(Self {
            tx,
            dropped,
            overflow_total: std::sync::atomic::AtomicU64::new(0),
            health,
        })
    }

    pub fn overflow_total(&self) -> u64 {
        self.overflow_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn status(&self) -> AuditStatus {
        use std::sync::atomic::Ordering;
        let h = &self.health;
        AuditStatus {
            healthy: !h.failing.load(Ordering::Relaxed),
            write_errors: h.write_errors.load(Ordering::Relaxed),
            sync_errors: h.sync_errors.load(Ordering::Relaxed),
            lost: h.lost.load(Ordering::Relaxed),
            last_sync_age_ms: now_ms().saturating_sub(h.last_sync_ok_ms.load(Ordering::Relaxed)),
        }
    }

    /// Waits up to `wait` in total until everything queued so far is written and fsynced (used
    /// on shutdown). Returns whether that was confirmed.
    pub fn flush(&self, wait: Duration) -> bool {
        let deadline = std::time::Instant::now() + wait;
        let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel(1);
        let mut msg = AuditMsg::Flush(ack_tx);
        loop {
            match self.tx.try_send(msg) {
                Ok(()) => break,
                Err(std::sync::mpsc::TrySendError::Full(back)) => {
                    if std::time::Instant::now() >= deadline {
                        log::error!("[Audit] Flush could not be queued within {:?}", wait);
                        return false;
                    }
                    msg = back;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return false,
            }
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match ack_rx.recv_timeout(left) {
            Ok(true) => true,
            Ok(false) => {
                log::error!("[Audit] Flush failed: the log could not be written or synced");
                false
            }
            Err(_) => {
                log::error!("[Audit] Flush did not complete within {:?}", wait);
                false
            }
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
    version = env!("SOKOL_VERSION"),
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

    /// This node's own block decisions and operator lifts, restored on start
    /// (default: <db-path>.blocks.json). Peers' blocks come back through the mesh.
    #[arg(long)]
    state_file: Option<std::path::PathBuf>,

    /// While a distributed storm is engaged: `strict` drops packets whose headers do not parse
    /// and IPv4 fragments (restored when it ends); `observe` only logs it.
    #[arg(long, value_enum, default_value = "strict")]
    storm_mode: defense::StormMode,
    /// A peer's claims enforced here at once (ADR-7); further ones wait for a free slot.
    /// A peer can be given its own limits in the peers file: "envelope": {"max_active": ..,
    /// "max_ttl_secs": .., "min_prefix_v4": .., "min_prefix_v6": ..}.
    #[arg(long, default_value = "16384")]
    peer_max_active: usize,

    /// Longest a peer's claim is enforced here, in seconds (default: --block-ttl-max).
    #[arg(long)]
    peer_max_ttl: Option<u64>,

    /// Distinct nodes that must claim a wide prefix before a peer's claim on it is enforced
    /// here (this node's own claim counts); 1 disables it.
    #[arg(long, default_value = "2")]
    quorum: usize,

    /// IPv4 prefixes shorter than this are "wide" for --quorum.
    #[arg(long, default_value = "24")]
    quorum_prefix_v4: u8,

    /// IPv6 prefixes shorter than this are "wide" for --quorum.
    #[arg(long, default_value = "64")]
    quorum_prefix_v6: u8,

    #[arg(long, default_value = "1")]
    node_id: u64,

    /// Mesh listener. The default avoids 8080, which the CrowdSec Local API and many local
    /// services use.
    #[arg(long, default_value = "[::]:7946")]
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

    /// Replay this node's detector decisions from an audit log with this build's code, report
    /// what is reproduced, mismatched or lacks context, then exit (ADR-0016). Exit status:
    /// 0 all replayable decisions reproduced, 1 a mismatch, 2 nothing could be replayed.
    #[arg(long, value_name = "AUDIT_LOG")]
    replay: Option<std::path::PathBuf>,

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

    /// BGP community `asn:value` marking this node's Flowspec rules (default 64512:<node-id>).
    /// Only rules with it are withdrawn; give every node sharing a gobgpd its own.
    #[arg(long, value_name = "ASN:VALUE")]
    flowspec_community: Option<String>,

    /// Drops per second at which this node reports itself under attack to the mesh.
    #[arg(long, default_value = "1000")]
    attack_drops_per_sec: u64,

    /// Received packets per second above which the node logs (once per crossing) that its
    /// traffic rate is high. A fixed rate threshold, not an anomaly model; it blocks nothing.
    #[arg(long, default_value = "500")]
    rx_rate_alert_pps: f64,

    /// How long an attack report (ATTACK:, e.g. from FastNetMon) keeps this node "under attack"
    /// if the detector never clears it.
    #[arg(long, default_value = "600")]
    attack_report_ttl_secs: u64,

    /// Shortest IPv4 prefix a block may have (wider ones are refused).
    #[arg(long, default_value = "16")]
    min_block_prefix_v4: u8,

    /// Shortest IPv6 prefix a block may have.
    #[arg(long, default_value = "48")]
    min_block_prefix_v6: u8,

    /// Share of live nodes under attack above which the cluster is in a distributed storm.
    #[arg(long, default_value = "0.5")]
    storm_threshold: f64,
}

/// How often each node reports its load to itself and its mesh peers.
const TELEMETRY_INTERVAL: Duration = Duration::from_secs(5);
/// A peer gets at most one snapshot (answer to SyncRequest) per this long.
const SYNC_COOLDOWN: Duration = Duration::from_secs(5);
/// How often the host's addresses and default gateways are re-read for the never-block policy.
const PROTECTED_REFRESH: Duration = Duration::from_secs(2);

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
    policy.set_min_prefix(args.min_block_prefix_v4, args.min_block_prefix_v6);
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

/// What peers may impose, from the command line; per-peer overrides come from the peers file.
#[derive(Clone, Copy)]
struct PeerLimits {
    default: Envelope,
    quorum: Quorum,
}

impl PeerLimits {
    fn from_args(args: &Args) -> Self {
        Self {
            default: Envelope {
                max_active: args.peer_max_active,
                max_ttl: Duration::from_secs(args.peer_max_ttl.unwrap_or(args.block_ttl_max)),
                min_prefix_v4: 0,
                min_prefix_v6: 0,
            },
            quorum: Quorum {
                k: args.quorum.max(1),
                wide_v4: args.quorum_prefix_v4,
                wide_v6: args.quorum_prefix_v6,
            },
        }
    }

    fn per_peer(&self, trust: &TrustStore) -> std::collections::HashMap<u64, Envelope> {
        trust
            .envelopes()
            .iter()
            .map(|(id, spec)| {
                (
                    *id,
                    Envelope {
                        max_active: spec.max_active.unwrap_or(self.default.max_active),
                        max_ttl: spec
                            .max_ttl_secs
                            .map_or(self.default.max_ttl, Duration::from_secs),
                        min_prefix_v4: spec.min_prefix_v4.unwrap_or(self.default.min_prefix_v4),
                        min_prefix_v6: spec.min_prefix_v6.unwrap_or(self.default.min_prefix_v6),
                    },
                )
            })
            .collect()
    }
}

struct ControlCtx {
    state: Arc<StateStore>,
    peer_limits: PeerLimits,
    blocks: SharedBlockTable,
    policy: PolicyHandle,
    sntl_db: Arc<SentinelDb>,
    registry: PeerRegistry,
    peers_file: Option<std::path::PathBuf>,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
}

/// Tells the mesh that this node takes back its own claims.
async fn broadcast_retraction(ctx: &ControlCtx, ids: Vec<block_table::ClaimId>) {
    if ids.is_empty() {
        return;
    }
    let cmd = MeshCommand::Retract {
        issuer: ctx.node_id,
        claims: ids,
    };
    let _ = ctx.registry.broadcast(&cmd, ctx.node_id, &ctx.crypto).await;
}

async fn execute_control(cmd: control::ControlCommand, ctx: &ControlCtx) -> String {
    use control::ControlCommand;
    let (blocks, policy, sntl_db) = (&ctx.blocks, &ctx.policy.current(), &ctx.sntl_db);
    match cmd {
        ControlCommand::Ban(ip) => {
            let shown = show(&ip);
            if let Err(why) = policy.check_net(ip) {
                return format!("ERR {} is protected ({})", shown, why);
            }
            let at = block_table::local_ms();
            let added = match blocks
                .lock()
                .await
                .add_local(ip, ClaimKind::Operator, "operator", at)
            {
                Ok(added) => added,
                Err(why) => return format!("ERR {} not banned: {}", shown, why),
            };
            sntl_db.append(format!(
                "OPERATOR_BAN_{}|IP:{}|At:{}",
                ip_tag(ip),
                shown,
                at
            ));
            match added.applied {
                Ok(()) => {
                    log::warn!("[Control] Operator ban for {}", shown);
                    format!("OK banned {}", shown)
                }
                Err(e) => format!(
                    "ERR kernel map update failed: {:?}; the ban is kept and retried every second",
                    e
                ),
            }
        }
        ControlCommand::Unban(ip) => {
            let shown = show(&ip);
            let at = block_table::local_ms();
            let (result, still_blocked) = {
                let mut table = blocks.lock().await;
                let result = table.lift(ip, at);
                (result, table.is_blocked(ip))
            };
            match result {
                Ok(lifted) => {
                    log::warn!("[Control] Operator unban for {}", shown);
                    sntl_db.append(format!(
                        "OPERATOR_UNBAN_{}|IP:{}|Claims:{}|At:{}",
                        ip_tag(ip),
                        shown,
                        lifted.claims,
                        at
                    ));
                    broadcast_retraction(ctx, lifted.retracted).await;
                    if still_blocked {
                        format!(
                            "OK unbanned {} (kernel removal pending, retried every second)",
                            shown
                        )
                    } else {
                        format!("OK unbanned {}", shown)
                    }
                }
                Err(LiftError::Static) => format!(
                    "ERR {} is blocked by --block; change the configuration to lift it",
                    shown
                ),
                Err(LiftError::NotBlocked) => format!("ERR {} was not blocked", shown),
            }
        }
        ControlCommand::FlushDynamic => {
            let at = block_table::local_ms();
            let (released, lifted) = blocks.lock().await.flush_detector(at);
            broadcast_retraction(ctx, lifted.retracted).await;
            log::warn!(
                "[Control] Operator flushed {} dynamic blocks",
                released.len()
            );
            sntl_db.append(format!(
                "OPERATOR_FLUSH|Released:{}|At:{}",
                released.len(),
                at
            ));
            format!("OK released {} dynamic blocks", released.len())
        }
        ControlCommand::FlushAll => {
            let at = block_table::local_ms();
            let (released, lifted) = blocks.lock().await.flush_all(at);
            broadcast_retraction(ctx, lifted.retracted).await;
            log::warn!(
                "[Control] Operator flushed {} blocks (operator and dynamic)",
                released.len()
            );
            sntl_db.append(format!(
                "OPERATOR_FLUSH_ALL|Released:{}|At:{}",
                released.len(),
                at
            ));
            format!("OK released {} blocks", released.len())
        }
        ControlCommand::AcceptStateLoss => {
            if ctx.state.accept_loss() {
                log::warn!("[Control] Operator accepted running without the unrestored state");
                sntl_db.append("STATE_LOSS_ACCEPTED".to_string());
                "OK state loss accepted".to_string()
            } else {
                "ERR no failed state restore to accept".to_string()
            }
        }
        ControlCommand::ListBans => {
            let bans = blocks
                .lock()
                .await
                .operator_targets(block_table::local_ms());
            let shown: Vec<String> = bans.iter().take(LIST_BANS_MAX).map(show).collect();
            // "OK <total> <target>..."; at most LIST_BANS_MAX targets on the line.
            format!("OK {} {}", bans.len(), shown.join(" "))
                .trim_end()
                .to_string()
        }
        ControlCommand::ReloadPeers => match &ctx.peers_file {
            None => "ERR no --peers-file configured".to_string(),
            Some(path) => match TrustStore::load(path).and_then(|trust| {
                ctx.registry.check_candidate(&trust)?;
                Ok(trust)
            }) {
                Ok(trust) => {
                    let per_peer = ctx.peer_limits.per_peer(&trust);
                    let legacy = trust.legacy_peers().to_vec();
                    {
                        let mut table = ctx.blocks.lock().await;
                        table.configure_peers(
                            ctx.peer_limits.default,
                            per_peer,
                            ctx.peer_limits.quorum,
                            block_table::local_ms(),
                        );
                        // A revoked node's claims stop counting here at once.
                        table.set_pinned(trust.node_ids(), block_table::local_ms());
                    }
                    let pinned = ctx.registry.reload(trust);
                    log::warn!(
                        "[Control] Reloaded {}: {} pinned peers",
                        path.display(),
                        pinned
                    );
                    sntl_db.append(format!(
                        "PEERS_RELOADED|Pinned:{}|Legacy:{:?}",
                        pinned, legacy
                    ));
                    if legacy.is_empty() {
                        format!("OK {} pinned peers", pinned)
                    } else {
                        format!(
                            "OK {} pinned peers; not trusted until their ML-DSA key is listed \
                             (legacy key only): {:?}",
                            pinned, legacy
                        )
                    }
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

/// Sends this node's shared mesh state to one peer (catch-up on connect, anti-entropy).
async fn send_snapshot(
    addr: std::net::SocketAddr,
    blocks: &SharedBlockTable,
    registry: &PeerRegistry,
    node_id: u64,
    crypto: &Arc<NodeCrypto>,
) {
    let (claims, retracted) = blocks.lock().await.snapshot(block_table::local_ms());
    let total = claims.len();
    for cmd in mesh_sync::pack_snapshot(node_id, claims, retracted) {
        if let Err(e) = registry.send_to(addr, &cmd, node_id, crypto).await {
            log::warn!("[Mesh] Block sync to {} failed: {:#}", addr, e);
            return;
        }
    }
    log::info!("[Mesh] Sent {} shared blocks to {}", total, addr);
}

/// Writes the durable part of the table atomically (temp file + rename, mode 0600).
use state_store::{Restore, StateStore};

/// Hands the table's durable part to the state writer if it changed; never waits for the disk.
async fn submit_state(store: &StateStore, blocks: &SharedBlockTable) -> Option<u64> {
    let state = {
        let mut table = blocks.lock().await;
        table
            .dirty()
            .then(|| table.take_persisted(block_table::local_ms()))
    }?;
    Some(store.submit(state, now_ms()))
}

/// Submits the current state and waits (at most `wait`) until it, or anything newer, is on disk.
async fn persist_now(
    store: &StateStore,
    blocks: &SharedBlockTable,
    wait: Duration,
) -> Result<(), String> {
    let generation = match submit_state(store, blocks).await {
        Some(g) => g,
        None => store.submitted(),
    };
    if generation == 0 {
        return Ok(());
    }
    store.wait_durable(generation, wait).await
}

struct IpcCtx {
    blocks: SharedBlockTable,
    db: Arc<SentinelDb>,
    registry: PeerRegistry,
    node_id: u64,
    crypto: Arc<NodeCrypto>,
    policy: PolicyHandle,
    reports: Arc<std::sync::Mutex<attack_reports::AttackReports>>,
}

/// One IPC command; returns the reply a client in ACK mode gets (F09): `OK applied`,
/// `OK refused <why>` (final, do not retry), `OK pending` (recorded, kernel write retried by the
/// node), `OK recorded`, or `ERR <why>` (malformed, do not retry).
async fn handle_ipc_line(content: &str, c: &IpcCtx) -> String {
    let outcome = |e: Enforcement| match e {
        Enforcement::Enforced => "OK applied".to_string(),
        Enforcement::Refused => "OK refused protected".to_string(),
        Enforcement::Pending => "OK pending".to_string(),
        Enforcement::Duplicate => "OK duplicate".to_string(),
    };
    if content.starts_with('{') {
        if let Err(e) = CanonicalParser::validate_strict_json_object(content) {
            log::error!("[CANONICAL FAULT] Rejected malformed IPC payload: {:?}", e);
            return "ERR malformed JSON".to_string();
        }
    }
    if let Some(raw_ip_str) = content.strip_prefix("DROP_IMMEDIATE:") {
        match parse_target(raw_ip_str.trim()) {
            Some(ip) => {
                log::warn!("[XDP_ACTION] Trap triggered ban for IP: {}", show(&ip));
                outcome(
                    enforce_block_local(
                        ip,
                        "Unix IPC DROP_IMMEDIATE trigger",
                        &c.blocks,
                        &c.db,
                        &c.registry,
                        c.node_id,
                        &c.crypto,
                        &c.policy.current(),
                        None,
                    )
                    .await,
                )
            }
            None => {
                log::error!(
                    "[UNIX IPC FAULT] Failed to parse IP from 'DROP_IMMEDIATE:{}'",
                    raw_ip_str
                );
                "ERR not an IP address or CIDR prefix".to_string()
            }
        }
    } else if let Some(payload) = content.strip_prefix("ATTACK:") {
        match attack_reports::parse(payload) {
            Ok(report) => {
                c.reports
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .apply(&report, std::time::Instant::now());
                let (tag, verb) = if report.active {
                    ("ATTACK_REPORTED", "under attack")
                } else {
                    ("ATTACK_CLEARED", "attack cleared")
                };
                log::warn!(
                    "[Attack] {} reports {} {} ({} pps, {})",
                    report.source,
                    report.victim,
                    verb,
                    report.pps,
                    report.direction
                );
                c.db.append(format!(
                    "{}|Source:{}|Victim:{}|Direction:{}|PPS:{}",
                    tag, report.source, report.victim, report.direction, report.pps
                ));
                "OK recorded".to_string()
            }
            Err(e) => {
                log::error!("[UNIX IPC FAULT] Bad ATTACK line: {}", e);
                format!("ERR {}", e)
            }
        }
    } else if let Some((event_id, payload)) = signal::split_verb(content) {
        let event_id = match event_id.map(signal::event_id).transpose() {
            Ok(id) => id,
            Err(e) => return format!("ERR {}", e),
        };
        match signal::parse(payload) {
            Ok(sig) => match signal::target(&sig, &c.policy.current()) {
                Ok(ip) => {
                    c.db.append(format!(
                        "SIGNAL|Source:{}|Src:{}|Dst:{}|Target:{}|Reason:{}",
                        sig.source,
                        show(&sig.src),
                        sig.dst.map(|d| show(&d)).unwrap_or_else(|| "-".into()),
                        show(&ip),
                        sig.reason
                    ));
                    let reason = format!("{}: {}", sig.source, sig.reason);
                    let event = event_id.map(|id| (sig.source.as_str(), id));
                    outcome(
                        enforce_block_local(
                            ip,
                            &reason,
                            &c.blocks,
                            &c.db,
                            &c.registry,
                            c.node_id,
                            &c.crypto,
                            &c.policy.current(),
                            event,
                        )
                        .await,
                    )
                }
                Err(why) => {
                    log::warn!("[Signal] {} signal not enforced: {}", sig.source, why);
                    c.db.append(format!(
                        "SIGNAL_REFUSED|Source:{}|Src:{}|Why:{}",
                        sig.source,
                        show(&sig.src),
                        why
                    ));
                    format!("OK refused {}", why)
                }
            },
            Err(e) => {
                log::error!("[UNIX IPC FAULT] Bad SIGNAL line: {}", e);
                format!("ERR {}", e)
            }
        }
    } else if let Some(log_content) = content.strip_prefix("DB_LOG:") {
        c.db.append(log_content.trim().to_string());
        let telemetry_msg = format!("DB_LOG:NODE={}|{}\n", c.node_id, log_content.trim());
        push_telemetry(&telemetry_msg).await;
        "OK recorded".to_string()
    } else {
        "ERR unknown command".to_string()
    }
}

async fn push_telemetry(msg: &str) {
    let telemetry_socket = "/run/sokol_telemetry.sock";
    if let Ok(mut stream) = tokio::net::UnixStream::connect(telemetry_socket).await {
        let _ = stream.write_all(msg.as_bytes()).await;
        let _ = stream.flush().await;
    }
}

type SharedBlockTable = Arc<tokio::sync::Mutex<BlockTable>>;

/// Open connections per local socket (F11): a local producer cannot make the node spawn tasks
/// without bound, and idle connections are closed.
const IPC_MAX_CONNS: usize = 64;
const IPC_IDLE: Duration = Duration::from_secs(300);
/// Lines a detector connection may send per second (and as a burst), and all of them together.
/// A new block costs a signature and a broadcast (~0.2 ms); past the budget the reader waits,
/// so a flooding adapter is slowed by its socket, and every line is still handled (ADR-0013).
const IPC_LINES_PER_SEC: f64 = 1_000.0;
const IPC_LINE_BURST: f64 = 5_000.0;
const IPC_TOTAL_PER_SEC: f64 = 2_000.0;
const IPC_TOTAL_BURST: f64 = 20_000.0;
/// Operator commands per second (and burst) per control connection.
const CONTROL_LINES_PER_SEC: f64 = 50.0;
const CONTROL_LINE_BURST: f64 = 500.0;
const CONTROL_MAX_CONNS: usize = 16;
/// Targets listed per LIST_BANS reply.
const LIST_BANS_MAX: usize = 4096;
const CONTROL_IDLE: Duration = Duration::from_secs(60);

fn ip_tag(net: IpNet) -> &'static str {
    family_tag(&net)
}

fn ttl_label(ttl: Option<Duration>) -> String {
    match ttl {
        Some(d) => format!("{}s", d.as_secs()),
        None => "permanent".to_string(),
    }
}

/// What became of a local block request; each outcome has its own audit record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Enforcement {
    Enforced,
    Refused,
    /// Recorded, but the kernel map refused it for now; retried every second.
    Pending,
    /// The same detector event was already acted on (a replay): nothing changed.
    Duplicate,
}

impl Enforcement {
    /// The `Action:` a trap hit records.
    fn trap_action(self) -> &'static str {
        match self {
            Enforcement::Enforced => "EnforcedDrop",
            Enforcement::Refused => "Refused",
            Enforcement::Pending => "Pending",
            Enforcement::Duplicate => "Duplicate",
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn enforce_block_local(
    target: IpNet,
    reason: &str,
    blocks: &SharedBlockTable,
    sntl_db: &Arc<SentinelDb>,
    registry: &PeerRegistry,
    node_id: u64,
    node_crypto: &Arc<NodeCrypto>,
    policy: &BlockPolicy,
    event: Option<(&str, &str)>,
) -> Enforcement {
    let ip = block_table::canonical(target);
    let shown = show(&ip);
    if let Err(why) = policy.check_net(ip) {
        log::error!(
            "[Local Security] Refusing to block {} ({}) | Requested for: {}",
            shown,
            why,
            reason
        );
        sntl_db.append(format!(
            "BLOCK_REFUSED|IP:{}|Protected:{}|Reason:{}",
            shown, why, reason
        ));
        return Enforcement::Refused;
    }
    let now = block_table::local_ms();
    // Replay context (ADR-0016): the exact decision time and the event id go into every
    // decision record; the audit record's own timestamp is when it was written.
    let context = format!(
        "At:{}|Event:{}",
        now,
        event
            .map(|(source, id)| format!("{}/{}", source, id))
            .unwrap_or_else(|| "-".into())
    );
    let added = {
        let mut table = blocks.lock().await;
        // Checked and recorded under the same lock as the strike, so no state save sees one
        // without the other.
        if let Some((source, id)) = event {
            if !table.first_sighting(source, id, now) {
                log::info!(
                    "[Local Security] {} event {} for {} already handled",
                    source,
                    id,
                    shown
                );
                drop(table);
                sntl_db.append(format!("SIGNAL_DUPLICATE|IP:{}|{}", shown, context));
                return Enforcement::Duplicate;
            }
        }
        table.add_local(ip, ClaimKind::Detector, reason, now)
    };
    let added = match added {
        Ok(added) => added,
        Err(why) => {
            log::error!("[Local Security] Not blocking {}: {}", shown, why);
            sntl_db.append(format!(
                "BLOCK_REFUSED|IP:{}|Why:{}|Reason:{}|{}",
                shown, why, reason, context
            ));
            return Enforcement::Refused;
        }
    };
    let ttl = added.ttl;
    let claim = if added.new { "new" } else { "merged" };
    // A new claim is shared either way: peers can enforce it even if this node's map is full.
    // A repeat merged into the running claim is not signed and sent again (peers have it).
    if added.new {
        let broadcast_cmd = MeshCommand::Claim { claim: added.claim };
        let _ = registry
            .broadcast(&broadcast_cmd, node_id, node_crypto)
            .await;
    }
    match added.applied {
        Ok(()) => {
            log::warn!(
                "[Local Security] Dynamic block enforced in XDP: {} for {} | Reason: {}",
                shown,
                ttl_label(ttl),
                reason
            );
            sntl_db.append(format!(
                "DYNAMIC_BLOCK_{}|IP:{}|TTL:{}|Reason:{}|Enforced|Claim:{}|{}",
                ip_tag(ip),
                shown,
                ttl_label(ttl),
                reason,
                claim,
                context
            ));

            let telemetry_msg = format!(
                "DROP_IMMEDIATE:{}\nDB_LOG:NODE={}|TIER=Tier1BotTarpit|IP={}|VEC={}\n",
                shown, node_id, shown, reason
            );
            push_telemetry(&telemetry_msg).await;

            Enforcement::Enforced
        }
        Err(e) => {
            log::error!(
                "[Local Security] Failed to insert {} into eBPF: {:?}; retried every second",
                shown,
                e
            );
            sntl_db.append(format!(
                "BLOCK_PENDING|IP:{}|TTL:{}|Error:{:?}|Reason:{}|Claim:{}|{}",
                shown,
                ttl_label(ttl),
                e,
                reason,
                claim,
                context
            ));
            Enforcement::Pending
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    log::info!("Sokol-Core {}", env!("SOKOL_VERSION"));

    if let Some(path) = &args.replay {
        std::process::exit(replay::print_report(path, env!("SOKOL_BUILD_ID")));
    }

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

    // The static part (built-in ranges, seeds, --never-block) plus the host's own addresses and
    // gateways, which are re-read while the node runs (the protected set follows the host).
    let base_policy = build_block_policy(&args)?;
    let (host_view, host_read) = match HostView::discover() {
        Ok(view) => (view, true),
        Err(e) => {
            log::error!(
                "[BlockPolicy] Cannot read this host's addresses ({}); they are not protected \
                 until a read succeeds; node is DEGRADED",
                e
            );
            (HostView::default(), false)
        }
    };
    let block_policy = PolicyHandle::new(base_policy.with_host(&host_view));
    let host_read_ok = Arc::new(std::sync::atomic::AtomicBool::new(host_read));
    let attack_reports = Arc::new(std::sync::Mutex::new(attack_reports::AttackReports::new(
        Duration::from_secs(args.attack_report_ttl_secs),
    )));
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

    let rotation = (args.audit_max_bytes > 0).then_some(Rotation {
        max_bytes: args.audit_max_bytes,
        keep: args.audit_keep,
    });
    let sntl_db = Arc::new(SentinelDb::init(&args.db_path, rotation)?);
    // Opens this run in the audit log with what its decisions depend on (ADR-0016).
    sntl_db.append(
        replay::StartContext {
            build: env!("SOKOL_BUILD_ID").to_string(),
            node: args.node_id,
            ttl_base_secs: args.block_ttl,
            ttl_max_secs: args.block_ttl_max.max(args.block_ttl),
        }
        .record(),
    );

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
    let defense = {
        let config_map = bpf
            .take_map("CONFIG")
            .ok_or_else(|| anyhow::anyhow!("CONFIG map missing"))?;
        let config = Array::<MapData, u32>::try_from(config_map)?;
        let defense = Arc::new(defense::Defense::new(config, config_flags, args.storm_mode));
        defense.set(false)?;
        defense
    };

    let prog_mut = bpf
        .program_mut("sentinel_vfr_filter")
        .ok_or_else(|| anyhow::anyhow!("Critical: Program sentinel_vfr_filter not found in ELF"))?;
    let program: &mut Xdp = prog_mut.try_into()?;
    // `auto` means: driver (native) mode where the driver takes it, otherwise generic. A driver
    // can support XDP and still refuse it on a given device (virtio_net whose host enforces
    // checksum/GRO offloads, e.g. Apple Virtualization): without the fallback the node would not
    // start at all there.
    let attach = |program: &mut Xdp, mode: XdpMode| {
        program.attach(&args.interface, mode.flags()).map_err(|e| {
            anyhow::anyhow!(
                "XDP attach to {} in {:?} mode failed: {}",
                args.interface,
                mode,
                e
            )
        })
    };
    let (_link, xdp_mode) = match args.xdp_mode {
        XdpMode::Auto => match attach(program, XdpMode::Native) {
            Ok(link) => (link, XdpMode::Native),
            Err(e) => {
                log::warn!(
                    "{:#}; falling back to generic mode (slower: packets reach XDP after the \
                     kernel has built its buffers). The kernel log names the driver's reason.",
                    e
                );
                (attach(program, XdpMode::Generic)?, XdpMode::Generic)
            }
        },
        mode => (attach(program, mode)?, mode),
    };
    log::info!(
        "XDP program successfully locked and attached to interface: {} (mode: {:?})",
        args.interface,
        xdp_mode
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
    let block_hits = PerCpuArray::<MapData, u64>::try_from(
        bpf.take_map("BLOCK_HITS")
            .ok_or_else(|| anyhow::anyhow!("BLOCK_HITS missing"))?,
    )?;
    // N03: the per-CPU numbers multiply with this machine's CPU count.
    let possible_cpus = aya::util::nr_cpus()?;
    let online_cpus = aya::util::online_cpus()
        .map(|c| c.len())
        .unwrap_or(possible_cpus);
    log::info!(
        "[Resources] {} possible / {} online CPUs: {}",
        possible_cpus,
        online_cpus,
        common::resource_estimate(possible_cpus, online_cpus)
            .iter()
            .map(|(what, n)| format!("{} {}", what, n))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let blocks: SharedBlockTable = Arc::new(tokio::sync::Mutex::new(BlockTable::new(
        blocklist_v4_trie,
        blocklist_v6_trie,
        block_hits,
        aya::util::nr_cpus()?,
        ttl_policy,
        args.node_id,
    )));
    let peer_limits = PeerLimits::from_args(&args);
    {
        let mut table = blocks.lock().await;
        table.configure_peers(
            peer_limits.default,
            peer_limits.per_peer(&trust_store),
            peer_limits.quorum,
            block_table::local_ms(),
        );
        table.set_pinned(trust_store.node_ids(), block_table::local_ms());
    }
    let state_file = args
        .state_file
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}.blocks.json", args.db_path)));
    let state_store = Arc::new(StateStore::new(state_file.clone()));

    let stats_map_data = bpf
        .take_map("STATS")
        .ok_or_else(|| anyhow::anyhow!("STATS map missing"))?;
    let stats_map = PerCpuArray::<MapData, BpfPacketStats>::try_from(stats_map_data)?;

    if let Some(events_map_data) = bpf.take_map("EVENTS") {
        match RingBuf::try_from(events_map_data) {
            Ok(ring_buf) => match AsyncFd::new(ring_buf) {
                Ok(mut async_fd) => {
                    let db_events = sntl_db.clone();
                    let node_id_ev = args.node_id;
                    tokio::spawn(async move {
                        log::info!(
                            "[eBPF RingBuf] Active consumer loop attached for kernel drop events."
                        );
                        loop {
                            match async_fd.readable_mut().await {
                                Ok(mut guard) => {
                                    let rb = guard.get_inner_mut();

                                    while let Some(item) = rb.next() {
                                        if let Some(log_msg) = kernel_events::audit_line(&item) {
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
            },
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
        if let Some(ip) = parse_target(clean_str) {
            if let Err(why) = block_policy.current().check_net(ip) {
                anyhow::bail!("--block {} refused ({})", show(&ip), why);
            }
            blocks
                .lock()
                .await
                .add_local(ip, ClaimKind::Static, "--block", block_table::local_ms())
                .map_err(|why| anyhow::anyhow!("--block {}: {}", show(&ip), why))?
                .applied?;
            sntl_db.append(format!(
                "STATIC_BLOCK_{}|IP:{}|Action:XDP_DROP",
                ip_tag(ip),
                show(&ip)
            ));
            log::info!(
                "[STATIC BLOCK] Enforced permanent block for CLI IP: {}",
                show(&ip)
            );
        } else {
            log::error!(
                "[STATIC BLOCK] Invalid CLI --block IP argument: '{}'",
                ip_str
            );
        }
    }

    // R27-04: a state file that cannot be restored is not a first start. Its bytes are kept, and
    // the node stays DEGRADED until the operator accepts the loss (ACCEPT_STATE_LOSS).
    let restore = match state_store.read() {
        Ok(None) => Restore::Fresh,
        Ok(Some(state)) => {
            let (restored, refused) = blocks.lock().await.restore(
                state,
                |net| block_policy.current().check_net(net).is_ok(),
                block_table::local_ms(),
            );
            log::warn!(
                "[State] Restored {} of this node's blocks from {} ({} refused)",
                restored,
                state_file.display(),
                refused
            );
            sntl_db.append(format!(
                "STATE_RESTORED|Blocks:{}|Refused:{}",
                restored, refused
            ));
            Restore::Restored { restored, refused }
        }
        Err(failed) => {
            if let Restore::Failed { why, kept } = &failed {
                log::error!(
                    "[State] Restore failed: {}; bytes kept at {}. Running without this node's \
                     earlier decisions and lifts; node is DEGRADED until ACCEPT_STATE_LOSS",
                    why,
                    kept.as_ref()
                        .map(|k| k.display().to_string())
                        .unwrap_or_else(|| "(not kept)".into())
                );
                sntl_db.append(format!("STATE_RESTORE_FAILED|Why:{}", why));
            }
            failed
        }
    };
    state_store.set_restore(restore);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx_ctrlc = shutdown_tx.clone();

    ctrlc::set_handler(move || {
        log::warn!("SIGINT/SIGTERM received. Teardown initiated...");
        let _ = shutdown_tx_ctrlc.send(true);
    })?;

    let peer_registry = PeerRegistry::new(trust_store);
    let (mesh_cmd_tx, mut mesh_cmd_rx) = mpsc::channel::<MeshCommand>(1000);

    let p2p_bind_addr: std::net::SocketAddr = args
        .p2p_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --p2p-bind address '{}': {}", args.p2p_bind, e))?;

    let p2p_network = P2PNetwork::new(
        p2p_bind_addr,
        args.node_id,
        node_crypto.clone(),
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
            let node_id = args.node_id;

            log::info!("[P2P] Maintaining connection to seed peer: {}", seed_addr);
            tokio::spawn(maintain_peer_connection(
                seed_addr,
                node_id,
                crypto_clone,
                reg_clone,
                tx_clone,
            ));
        }
    }

    // Nodes report every TELEMETRY_INTERVAL; one missed report is tolerated, three are not.
    let bird_eye = BirdEyeView::new(args.storm_threshold, TELEMETRY_INTERVAL * 3);
    let (telemetry_tx, telemetry_rx) = mpsc::channel::<NodeTelemetry>(1000);
    let telemetry_tx_mesh = telemetry_tx.clone();
    let cluster_summary = Arc::new(std::sync::RwLock::new(mesh_sync::ClusterSummary::default()));

    let blocks_mesh = blocks.clone();

    // Catch-up for peers that (re)connect: send them our running dynamic blocks.
    let (peer_up_tx, mut peer_up_rx) = mpsc::unbounded_channel::<std::net::SocketAddr>();
    peer_registry.on_peer_up(peer_up_tx);
    {
        let (blocks, registry, crypto) =
            (blocks.clone(), peer_registry.clone(), node_crypto.clone());
        let node_id = args.node_id;
        tokio::spawn(async move {
            while let Some(addr) = peer_up_rx.recv().await {
                send_snapshot(addr, &blocks, &registry, node_id, &crypto).await;
            }
        });
    }
    let sntl_db_mesh = sntl_db.clone();
    let node_id_mesh = args.node_id;
    let policy_mesh = block_policy.clone();
    let defense_mesh = defense.clone();
    let (registry_mesh, crypto_mesh) = (peer_registry.clone(), node_crypto.clone());
    let sync_throttled = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sync_throttled_mesh = sync_throttled.clone();

    tokio::spawn(async move {
        // When each peer last got a snapshot (bounded by the pinned peers: a SyncRequest names
        // its authenticated sender).
        let mut snapshots = mesh_sync::Cooldown::new(SYNC_COOLDOWN);
        while let Some(cmd) = mesh_cmd_rx.recv().await {
            match cmd {
                MeshCommand::Claim { claim } => {
                    let shown = claim.target.clone();
                    let reason = claim.reason.clone();
                    let issuer = claim.issuer;
                    let expires = claim.expires_ms;
                    let refusal = claim
                        .net()
                        .and_then(|n| policy_mesh.current().check_net(n).err());
                    let (now, wall) = (block_table::local_ms(), now_ms());
                    let result = blocks_mesh
                        .lock()
                        .await
                        .adopt(claim, refusal.is_none(), now);
                    match (result, refusal) {
                        (Adoption::Enforced, _) => {
                            let left =
                                expires.map(|e| Duration::from_millis(e.saturating_sub(wall)));
                            log::warn!(
                                "[Mesh] Synchronized block for {} from node {} ({}): {}",
                                shown,
                                issuer,
                                ttl_label(left),
                                reason
                            );
                            let tag = parse_target(&shown).map(ip_tag).unwrap_or("V4");
                            sntl_db_mesh.append(format!(
                                "MESH_BLOCK_{}|IP:{}|TTL:{}|Reason:{}",
                                tag,
                                shown,
                                ttl_label(left),
                                reason
                            ));
                            let telemetry_msg = format!(
                                "DB_LOG:NODE={}|TIER=MeshBlock|IP={}|VEC={}\n",
                                node_id_mesh, shown, reason
                            );
                            push_telemetry(&telemetry_msg).await;
                        }
                        (Adoption::Held(held @ ("quorum" | "quota" | "envelope")), _) => {
                            log::warn!(
                                "[Mesh] Holding block for {} from node {} ({}): {}",
                                shown,
                                issuer,
                                held,
                                reason
                            );
                            sntl_db_mesh.append(format!(
                                "MESH_BLOCK_HELD|IP:{}|Issuer:{}|Why:{}|Reason:{}",
                                shown, issuer, held, reason
                            ));
                        }
                        (Adoption::Held(_), Some(why)) => {
                            log::error!(
                                "[Mesh] Refusing mesh block for protected {} ({}): {}",
                                shown,
                                why,
                                reason
                            );
                            sntl_db_mesh.append(format!(
                                "MESH_BLOCK_REFUSED|IP:{}|Protected:{}|Reason:{}",
                                shown, why, reason
                            ));
                        }
                        (Adoption::Refused(why), _) => {
                            log::warn!(
                                "[Mesh] Ignoring claim for {} from node {}: {}",
                                shown,
                                issuer,
                                why
                            )
                        }
                        _ => {}
                    }
                }
                MeshCommand::Retract { issuer, claims } => {
                    let lifted =
                        blocks_mesh
                            .lock()
                            .await
                            .retract(issuer, &claims, block_table::local_ms());
                    for net in lifted {
                        log::info!(
                            "[Mesh] Unblocked {}: node {} took back its block",
                            show(&net),
                            issuer
                        );
                        sntl_db_mesh.append(format!(
                            "MESH_UNBLOCK|IP:{}|Issuer:{}",
                            show(&net),
                            issuer
                        ));
                    }
                }
                MeshCommand::BlockSync {
                    issuer,
                    claims,
                    retracted,
                } => {
                    let (now, wall) = (block_table::local_ms(), now_ms());
                    let mut adopted = 0;
                    for claim in claims {
                        let refusal = claim
                            .net()
                            .and_then(|n| policy_mesh.current().check_net(n).err());
                        let (shown, secs) = (
                            claim.target.clone(),
                            claim.expires_ms.map(|e| e.saturating_sub(wall) / 1000),
                        );
                        let tag = parse_target(&shown).map(ip_tag).unwrap_or("V4");
                        if blocks_mesh
                            .lock()
                            .await
                            .adopt(claim, refusal.is_none(), now)
                            == Adoption::Enforced
                        {
                            adopted += 1;
                            sntl_db_mesh.append(format!(
                                "MESH_BLOCK_{}|IP:{}|TTL:{}|Reason:sync from node {}",
                                tag,
                                shown,
                                secs.map_or("permanent".into(), |s| format!("{}s", s)),
                                issuer
                            ));
                        }
                    }
                    let lifted = blocks_mesh.lock().await.retract(issuer, &retracted, now);
                    for net in &lifted {
                        sntl_db_mesh.append(format!(
                            "MESH_UNBLOCK|IP:{}|Issuer:{}",
                            show(net),
                            issuer
                        ));
                    }
                    if adopted > 0 || !lifted.is_empty() {
                        log::warn!(
                            "[Mesh] Sync from node {}: adopted {} blocks missed while disconnected, {} taken back",
                            issuer,
                            adopted,
                            lifted.len()
                        );
                    }
                }
                MeshCommand::Digest { issuer, digest } => {
                    // Our view of the sender's own claims differs: ask the sender for them.
                    let ours = blocks_mesh
                        .lock()
                        .await
                        .digest_of(issuer, block_table::local_ms());
                    if ours != digest {
                        if let Some(addr) = registry_mesh.addr_of(issuer).await {
                            log::info!(
                                "[Mesh] Node {}'s claims differ from our view; asking it",
                                issuer
                            );
                            let cmd = MeshCommand::SyncRequest {
                                issuer: node_id_mesh,
                            };
                            let _ = registry_mesh
                                .send_to(addr, &cmd, node_id_mesh, &crypto_mesh)
                                .await;
                        }
                    }
                }
                MeshCommand::SyncRequest { issuer } => {
                    // A snapshot is the most expensive answer (the whole table, signed frames):
                    // at most one per peer per SYNC_COOLDOWN. A request dropped here is repeated
                    // by the peer's next digest mismatch.
                    if !snapshots.allow(issuer, std::time::Instant::now()) {
                        sync_throttled_mesh.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                    if let Some(addr) = registry_mesh.addr_of(issuer).await {
                        send_snapshot(
                            addr,
                            &blocks_mesh,
                            &registry_mesh,
                            node_id_mesh,
                            &crypto_mesh,
                        )
                        .await;
                    }
                }
                MeshCommand::LocalDetection { ip, reason } => {
                    // The telemetry processor's own detections: enforced here and shared like
                    // any other local decision.
                    if let Some(net) = parse_target(&ip) {
                        enforce_block_local(
                            net,
                            &reason,
                            &blocks_mesh,
                            &sntl_db_mesh,
                            &registry_mesh,
                            node_id_mesh,
                            &crypto_mesh,
                            &policy_mesh.current(),
                            None,
                        )
                        .await;
                    }
                }
                c @ (MeshCommand::EngageDefense | MeshCommand::DisengageDefense) => {
                    let engaged = matches!(c, MeshCommand::EngageDefense);
                    match defense_mesh.set(engaged) {
                        Ok(flags) if defense_mesh.mode() == defense::StormMode::Strict => {
                            let label = if engaged { "Strict" } else { "Normal" };
                            log::warn!(
                                "[Defense] Distributed storm {}: XDP mode {} (flags {:#x})",
                                if engaged { "engaged" } else { "over" },
                                label,
                                flags
                            );
                            sntl_db_mesh
                                .append(format!("DEFENSE_MODE|{}|Flags:{:#x}", label, flags));
                        }
                        Ok(_) => log::warn!(
                            "[Defense] Distributed storm {} (--storm-mode observe: XDP unchanged)",
                            if engaged { "engaged" } else { "over" }
                        ),
                        Err(e) => log::error!("[Defense] Cannot update the XDP config: {:?}", e),
                    }
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

    let upstream_router_addr: std::net::SocketAddr = args.upstream_router.parse().map_err(|e| {
        anyhow::anyhow!(
            "invalid upstream router address '{}': {}",
            args.upstream_router,
            e
        )
    })?;
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
                                let outcome = enforce_block_local(
                                    host(ip),
                                    &reason,
                                    &blocks_trap,
                                    &db_trap,
                                    &registry_trap,
                                    node_id_trap,
                                    &crypto_trap,
                                    &policy_trap.current(),
                                    None,
                                )
                                .await;
                                db_trap.append(format!(
                                    "TRAP_HIT|Port:{}|IP:{}|Action:{}",
                                    port,
                                    ip,
                                    outcome.trap_action()
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
    let control_slots = Arc::new(tokio::sync::Semaphore::new(CONTROL_MAX_CONNS));
    let ctl_ctx = Arc::new(ControlCtx {
        state: state_store.clone(),
        peer_limits,
        blocks: blocks.clone(),
        policy: block_policy.clone(),
        sntl_db: sntl_db.clone(),
        registry: peer_registry.clone(),
        peers_file: args.peers_file.clone(),
        node_id: args.node_id,
        crypto: node_crypto.clone(),
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
            let Ok(permit) = control_slots.clone().try_acquire_owned() else {
                log::warn!(
                    "[Control] {} connections open; refusing another",
                    CONTROL_MAX_CONNS
                );
                continue;
            };
            let ctx = ctl_ctx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let (read_half, mut write_half) = stream.into_split();
                let mut reader = BufReader::new(read_half);
                let mut line = String::new();
                let mut budget = p2p::Bucket::new(CONTROL_LINES_PER_SEC, CONTROL_LINE_BURST);
                loop {
                    line.clear();
                    let mut limited = (&mut reader).take(control::MAX_LINE);
                    match tokio::time::timeout(CONTROL_IDLE, limited.read_line(&mut line)).await {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(_)) => {}
                    }
                    let wait = budget.take(1.0, std::time::Instant::now());
                    if !wait.is_zero() {
                        tokio::time::sleep(wait).await;
                    }
                    let reply = match control::parse(&line) {
                        Ok(cmd) => {
                            use control::ControlCommand as C;
                            let mutating = matches!(
                                cmd,
                                C::Ban(_) | C::Unban(_) | C::FlushDynamic | C::FlushAll
                            );
                            let mut reply = execute_control(cmd, &ctx).await;
                            // R26-04: an operator decision is on disk before it is answered OK.
                            if mutating && reply.starts_with("OK") {
                                if let Err(e) =
                                    persist_now(&ctx.state, &ctx.blocks, state_store::DURABLE_WAIT)
                                        .await
                                {
                                    reply = format!("{}; WARNING: {}", reply, e);
                                }
                            }
                            reply
                        }
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
    let node_id_unix = args.node_id;
    let policy_unix = block_policy.clone();
    let ipc_total = Arc::new(std::sync::Mutex::new(p2p::Bucket::new(
        IPC_TOTAL_PER_SEC,
        IPC_TOTAL_BURST,
    )));
    let ipc_delayed = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ipc_delayed_metrics = ipc_delayed.clone();
    let reports_unix = attack_reports.clone();

    let socket_path_log = socket_path.to_string();
    tokio::spawn(async move {
        log::info!(
            "[UNIX SOCKET] Listening for trap events on {}",
            socket_path_log
        );
        let ipc_slots = Arc::new(tokio::sync::Semaphore::new(IPC_MAX_CONNS));
        loop {
            match unix_listener.accept().await {
                Ok((stream, _)) => {
                    let Ok(permit) = ipc_slots.clone().try_acquire_owned() else {
                        log::warn!(
                            "[UNIX IPC] {} connections open; refusing another (uid {:?})",
                            IPC_MAX_CONNS,
                            stream.peer_cred().map(|c| c.uid()).ok()
                        );
                        continue;
                    };
                    let blocks_stream = blocks_unix.clone();
                    let db = db_unix.clone();
                    let registry = registry_unix.clone();

                    let crypto_stream = crypto_unix.clone();
                    let policy_stream = policy_unix.clone();
                    let reports_stream = reports_unix.clone();
                    let peer_uid = stream.peer_cred().map(|c| c.uid()).ok();

                    let ipc = IpcCtx {
                        blocks: blocks_stream,
                        db,
                        registry,
                        node_id: node_id_unix,
                        crypto: crypto_stream,
                        policy: policy_stream,
                        reports: reports_stream,
                    };
                    let (total, delayed) = (ipc_total.clone(), ipc_delayed.clone());
                    tokio::spawn(async move {
                        let _permit = permit;
                        let (read_half, mut writer) = stream.into_split();
                        let mut reader = BufReader::new(read_half);
                        let mut line = String::new();
                        let mut ack = false;
                        let mut own = p2p::Bucket::new(IPC_LINES_PER_SEC, IPC_LINE_BURST);

                        loop {
                            line.clear();
                            let mut limited = (&mut reader).take(MAX_IPC_LINE);
                            let Ok(read) =
                                tokio::time::timeout(IPC_IDLE, limited.read_line(&mut line)).await
                            else {
                                log::info!(
                                    "[UNIX IPC] Closing idle connection from uid {:?}",
                                    peer_uid
                                );
                                break;
                            };
                            match read {
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
                                    if content == "ACK" {
                                        // The client wants a reply per command (F09).
                                        ack = true;
                                        if writer.write_all(b"OK ack\n").await.is_err() {
                                            break;
                                        }
                                        continue;
                                    }
                                    let now = std::time::Instant::now();
                                    let wait = own.take(1.0, now).max(
                                        total
                                            .lock()
                                            .unwrap_or_else(|p| p.into_inner())
                                            .take(1.0, now),
                                    );
                                    if !wait.is_zero() {
                                        delayed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        tokio::time::sleep(wait).await;
                                    }
                                    let reply = handle_ipc_line(content, &ipc).await;
                                    if ack
                                        && writer
                                            .write_all(format!("{}\n", reply).as_bytes())
                                            .await
                                            .is_err()
                                    {
                                        break;
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

    let sokol_engine = SokolEngine::new(args.rx_rate_alert_pps);
    let mut rate_alert = sokol::RateAlert::default();
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

    log::info!("Sokol-Core running.");

    // The protected set follows the host: addresses and default gateways are re-read every
    // PROTECTED_REFRESH; a change replaces the policy and re-checks every claim, so a target that
    // became protected is released now, not only refused in the future.
    {
        let (policy, blocks, db, read_ok) = (
            block_policy.clone(),
            blocks.clone(),
            sntl_db.clone(),
            host_read_ok.clone(),
        );
        let mut last = host_view.clone();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering;
            let mut interval = tokio::time::interval(PROTECTED_REFRESH);
            loop {
                interval.tick().await;
                let view = match tokio::task::spawn_blocking(HostView::discover).await {
                    Ok(Ok(view)) => view,
                    Ok(Err(e)) => {
                        if read_ok.swap(false, Ordering::Relaxed) {
                            log::error!(
                                "[BlockPolicy] Cannot re-read this host's addresses ({}); keeping \
                                 the last known ones; node is DEGRADED",
                                e
                            );
                        }
                        continue;
                    }
                    Err(_) => continue,
                };
                if !read_ok.swap(true, Ordering::Relaxed) {
                    log::warn!("[BlockPolicy] This host's addresses are readable again");
                }
                if view == last {
                    continue;
                }
                let (added, removed) = view.diff(&last);
                policy.replace(base_policy.with_host(&view));
                log::warn!(
                    "[BlockPolicy] Protected host addresses changed: +{:?} -{:?}",
                    added,
                    removed
                );
                db.append(format!(
                    "PROTECTED_CHANGED|Added:{:?}|Removed:{:?}",
                    added, removed
                ));
                let current = policy.current();
                let released = blocks.lock().await.recheck(
                    |net| current.check_net(net).is_ok(),
                    block_table::local_ms(),
                );
                for net in released {
                    log::warn!(
                        "[BlockPolicy] Block of {} released: it is protected now",
                        show(&net)
                    );
                    db.append(format!("BLOCK_RELEASED_PROTECTED|IP:{}", show(&net)));
                }
                last = view;
            }
        });
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut tick_max_secs = 0.0f64;
    let mut outcome_stats = metrics::OutcomeStats::default();
    let mut shutdown_rx_loop = shutdown_rx.clone();
    let node_id_hb = args.node_id;
    let p2p_bind_hb = args.p2p_bind.clone();
    let control_socket_hb = args.control_socket.clone();
    let mut watermark = Watermark::default();
    let (registry_tick, crypto_tick) = (peer_registry.clone(), node_crypto.clone());
    let node_id_tick = args.node_id;
    let mut last_digest = std::time::Instant::now();
    let mut telemetry_window_start = std::time::Instant::now();
    let mut window_rx = 0u64;
    let mut window_dropped = 0u64;
    let flowspec_announced = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (flowspec_tx, flowspec_rx) = watch::channel(std::collections::HashSet::<IpNet>::new());
    let flowspec_worker = match args.flowspec_gobgp.clone() {
        Some(bin) => {
            let community = match &args.flowspec_community {
                Some(raw) => {
                    let parsed = raw
                        .split_once(':')
                        .and_then(|(a, v)| Some((a.parse::<u16>().ok()?, v.parse::<u16>().ok()?)));
                    parsed.ok_or_else(|| {
                        anyhow::anyhow!(
                            "--flowspec-community {} is not <asn>:<value> (16-bit each)",
                            raw
                        )
                    })?
                }
                None => (64512, (args.node_id & 0xFFFF) as u16),
            };
            let cli = flowspec::GobgpCli {
                bin,
                args: args.flowspec_gobgp_arg.clone(),
                community,
            };
            log::info!(
                "[Flowspec] Mirroring blocks upstream with community {}:{}",
                community.0,
                community.1
            );
            Some(tokio::spawn(flowspec::run_worker(
                cli,
                flowspec_rx,
                shutdown_rx.clone(),
                sntl_db.clone(),
                flowspec_announced.clone(),
            )))
        }
        None => None,
    };
    let mut last_tick = std::time::Instant::now();
    let mut clock_watch = clock_watch::ClockWatch::default();

    loop {
        tokio::select! {
            _ = shutdown_rx_loop.changed() => {
                if *shutdown_rx_loop.borrow() {
                    log::info!("Initiating main loop shutdown sequence...");
                    break;
                }
            }

            _ = ticker.tick() => {
                let tick_started = std::time::Instant::now();
                if let Some(step) = clock_watch.observe(now_ms(), tick_started) {
                    log::warn!(
                        "[Clock] Wall clock stepped {:+.1} s against the monotonic clock; blocks in force keep their length (ADR-0017), peers' envelopes and claims are now judged by the new time",
                        step as f64 / 1000.0
                    );
                    sntl_db.append(format!("CLOCK_STEP|By:{}ms|At:{}", step, now_ms()));
                }

                let (released, (outcomes, outcomes_dropped)) = {
                    let mut table = blocks.lock().await;
                    // ADR-0017: held blocks keep their length in real time across wall-clock steps;
                    // the offset only converts what enters or leaves the table from now on.
                    table.set_clock_offset(block_table::wall_offset_ms());
                    let released = table.tick(block_table::local_ms());
                    (released, table.take_outcomes())
                };
                for ip in released {
                    log::info!("[BlockTable] Block for {} expired; traffic allowed again", show(&ip));
                    sntl_db.append(format!("BLOCK_EXPIRED_{}|IP:{}", ip_tag(ip), show(&ip)));
                }
                // The node's memory of consequences: what every removed block actually did.
                for o in outcomes {
                    let seconds = o.removed_ms.saturating_sub(o.applied_ms) / 1000;
                    let hits = o.hits.map_or_else(|| "unknown".to_string(), |h| h.to_string());
                    log::info!(
                        "[BlockTable] Outcome of the block of {}: {} packets dropped in {} s",
                        show(&o.net),
                        hits,
                        seconds
                    );
                    // Cause last: it is free text (with any '|' replaced, the field separator).
                    sntl_db.append(format!(
                        "BLOCK_OUTCOME|IP:{}|Dropped:{}|Seconds:{}|Cause:{}",
                        show(&o.net),
                        hits,
                        seconds,
                        o.cause.replace('|', "/")
                    ));
                    match o.hits {
                        Some(0) => outcome_stats.idle += 1,
                        Some(h) => {
                            outcome_stats.effective += 1;
                            outcome_stats.hits += h;
                        }
                        None => outcome_stats.unknown += 1,
                    }
                }
                outcome_stats.dropped += outcomes_dropped;

                // ADR-4: this node's decisions and lifts survive a restart (<= 1 tick for detector
                // decisions; operator decisions are written before they are answered).
                // Never waits for the disk (R27-03): a slow write must not hold up expiry.
                let _ = submit_state(&state_store, &blocks).await;

                // ADR-3 anti-entropy: a peer whose digest differs answers with its state.
                if last_digest.elapsed() >= mesh_sync::DIGEST_INTERVAL {
                    last_digest = std::time::Instant::now();
                    let digest = blocks.lock().await.digest(block_table::local_ms());
                    let cmd = MeshCommand::Digest { issuer: node_id_tick, digest };
                    let _ = registry_tick.broadcast(&cmd, node_id_tick, &crypto_tick).await;
                }

                let mode = if sntl_db.status().healthy
                    && state_store.healthy(now_ms())
                    && host_read_ok.load(std::sync::atomic::Ordering::Relaxed)
                {
                    "NORMAL"
                } else {
                    "DEGRADED"
                };
                let hb_msg = format!("HEARTBEAT:ID={}|NAME=Sokol-Node-{}|EP={}|MODE={}|CTL={}\n", node_id_hb, node_id_hb, p2p_bind_hb, mode, control_socket_hb);
                push_telemetry(&hb_msg).await;


                let mut total_rx_packets = 0u64;
                let mut total_rx_bytes = 0u64;
                let mut total_dropped = 0u64;
                let mut snapshot = metrics::Snapshot {
                    events_malformed: kernel_events::MALFORMED
                        .load(std::sync::atomic::Ordering::Relaxed),
                    ..Default::default()
                };

                if let Ok(per_cpu_stats) = stats_map.get(&0u32, 0) {
                    for cpu_stat in per_cpu_stats.iter() {
                        total_rx_packets += cpu_stat.0.rx_packets;
                        total_rx_bytes += cpu_stat.0.rx_bytes;
                        total_dropped += cpu_stat.0.dropped_packets;
                        snapshot.events_suppressed += cpu_stat.0.events_suppressed;
                        snapshot.events_lost += cpu_stat.0.events_lost;
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
                {
                    let table = blocks.lock().await;
                    snapshot.blocks_pending = table.pending();
                    snapshot.blocks_pending_oldest_secs =
                        table.oldest_pending(block_table::local_ms()).as_secs_f64();
                    (snapshot.event_ids_remembered, snapshot.event_ids_evicted) =
                        table.event_memory();
                    (snapshot.strikes_remembered, snapshot.strikes_evicted) =
                        table.strike_memory();
                    snapshot.claims_waiting = table.waiting_claims(block_table::local_ms());
                }
                for message in watermark.update((v4_active, v6_active), common::BLOCKLIST_CAPACITY as usize) {
                    log::warn!("[BlockTable] {}", message);
                    sntl_db.append(format!("BLOCKLIST_WATERMARK|{}", message));
                }
                snapshot.p2p_peers = peer_registry.peer_count().await;
                snapshot.audit_queue_overflow = sntl_db.overflow_total();
                // R26-08: a CONFIG write that failed at a latch transition is retried here.
                if defense.pending() {
                    if let Err(e) = defense.reconcile() {
                        log::error!("[Defense] XDP config still not updated: {:?}", e);
                    }
                }
                snapshot.defense_strict = defense.strict();
                let audit = sntl_db.status();
                snapshot.audit_healthy = audit.healthy;
                snapshot.state_healthy = state_store.healthy(now_ms());
                snapshot.state_pending_secs = state_store.pending_for(now_ms()).as_secs_f64();
                snapshot.state_restore_ok = state_store.restore_status().ok();
                {
                    use std::sync::atomic::Ordering;
                    let stats = &peer_registry.stats;
                    snapshot.mesh_handshakes_refused = stats.handshakes_refused.load(Ordering::Relaxed);
                    snapshot.mesh_handshake_timeouts = stats.handshake_timeouts.load(Ordering::Relaxed);
                    snapshot.mesh_frames_delayed = stats.frames_delayed.load(Ordering::Relaxed);
                    snapshot.mesh_sync_requests_throttled =
                        sync_throttled.load(Ordering::Relaxed);
                    snapshot.mesh_dropped_urgent = stats.dropped_urgent.load(Ordering::Relaxed);
                    for (out, counter) in snapshot.mesh_rejected.iter_mut().zip(&stats.rejected) {
                        *out = counter.load(Ordering::Relaxed);
                    }
                    snapshot.clock_steps = clock_watch.steps;
                    snapshot.clock_last_step_ms = clock_watch.last_step_ms;
                    snapshot.mesh_dropped_bulk = stats.dropped_bulk.load(Ordering::Relaxed);
                    snapshot.ipc_lines_delayed = ipc_delayed_metrics.load(Ordering::Relaxed);
                }
                // Time the tick took up to here (expiry, state hand-off, digest, heartbeat, stats).
                let tick_secs = tick_started.elapsed().as_secs_f64();
                tick_max_secs = tick_max_secs.max(tick_secs);
                snapshot.tick_secs = tick_secs;
                snapshot.xdp_native = matches!(xdp_mode, XdpMode::Native);
                snapshot.outcomes = outcome_stats;
                snapshot.tick_max_secs = tick_max_secs;
                snapshot.protected_refresh_ok =
                    host_read_ok.load(std::sync::atomic::Ordering::Relaxed);
                snapshot.audit_write_errors = audit.write_errors + audit.sync_errors;
                snapshot.audit_lost = audit.lost;
                snapshot.audit_sync_age_ms = audit.last_sync_age_ms;

                let reported_attacks = attack_reports
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .active(std::time::Instant::now());
                if telemetry_window_start.elapsed() >= TELEMETRY_INTERVAL {
                    let secs = telemetry_window_start.elapsed().as_secs_f64().max(1.0);
                    let rx_pps = (total_rx_packets.saturating_sub(window_rx) as f64 / secs) as u64;
                    let drops_per_sec = (total_dropped.saturating_sub(window_dropped) as f64 / secs) as u64;
                    let report = MeshCommand::Telemetry {
                        node_id: node_id_hb,
                        rx_pps,
                        drops_per_sec,
                        under_attack: drops_per_sec >= args.attack_drops_per_sec || reported_attacks > 0,
                        blocks_active: (v4_active + v6_active) as u64,
                    };
                    if let Some(record) = report.telemetry_record() {
                        let _ = telemetry_tx.try_send(record);
                    }
                    if let Err(e) = peer_registry.broadcast(&report, node_id_hb, &node_crypto).await {
                        log::warn!("[Mesh] Telemetry broadcast failed: {:#}", e);
                    }
                    telemetry_window_start = std::time::Instant::now();
                    window_rx = total_rx_packets;
                    window_dropped = total_dropped;
                }
                snapshot.external_attacks = reported_attacks;
                let cluster = *cluster_summary.read().unwrap_or_else(|p| p.into_inner());
                snapshot.cluster_status = cluster.status_code;
                snapshot.cluster_nodes = cluster.nodes;
                snapshot.cluster_attacked = cluster.attacked;
                snapshot.cluster_storm_engaged = cluster.storm_engaged;

                if flowspec_worker.is_some() {
                    let _ = flowspec_tx.send(blocks.lock().await.active_ips());
                    snapshot.flowspec_announced =
                        flowspec_announced.load(std::sync::atomic::Ordering::Relaxed);
                }
                *metrics_snapshot.write().unwrap_or_else(|p| p.into_inner()) = snapshot;

                let delta_packets = total_rx_packets.saturating_sub(prev_packets);
                let delta_bytes = total_rx_bytes.saturating_sub(prev_bytes);
                let delta_dropped = total_dropped.saturating_sub(prev_dropped);

                // Measured, not assumed: a delayed tick must not inflate the rates.
                let dt = last_tick.elapsed().as_secs_f64().max(0.001);
                last_tick = std::time::Instant::now();
                let rate_high = sokol_engine.rate_above(
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

                // A rate threshold (N04): reported when crossed, not on every tick above it.
                match rate_alert.update(!first_tick && rate_high) {
                    Some(true) => {
                        log::warn!(
                            "[Traffic] RX rate {:.0} pkts/s is above --rx-rate-alert-pps {:.0}",
                            flow_rate.0, args.rx_rate_alert_pps
                        );
                        let telemetry = format!(
                            "DB_LOG:NODE={}|TIER=Tier3RateAnomaly|IP=0.0.0.0|VEC=RX rate {:.0} pkts/s above {:.0}\n",
                            node_id_hb, flow_rate.0, args.rx_rate_alert_pps
                        );
                        push_telemetry(&telemetry).await;
                    }
                    Some(false) => log::info!(
                        "[Traffic] RX rate {:.0} pkts/s is back below {:.0}",
                        flow_rate.0, args.rx_rate_alert_pps
                    ),
                    None => {}
                }
                if !first_tick && delta_dropped > 0 {
                    log::warn!(
                        "[Traffic] {} packets dropped in the last {:.1} s ({} total) | RX {:.0} pkts/s, {} bytes",
                        delta_dropped, dt, total_dropped, flow_rate.0, delta_bytes
                    );
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
    if let Some(worker) = flowspec_worker {
        // The worker withdraws this node's rules on shutdown, within its own budget.
        if tokio::time::timeout(flowspec::SHUTDOWN_BUDGET + Duration::from_secs(2), worker)
            .await
            .is_err()
        {
            log::error!("[Flowspec] Worker did not finish withdrawing in time");
        }
    }
    // The last decisions since the previous tick (R26-04).
    if let Err(e) = persist_now(&state_store, &blocks, Duration::from_secs(5)).await {
        log::error!(
            "[State] Shutdown without a confirmed final state write: {}",
            e
        );
    }
    sntl_db.append("NODE_SHUTDOWN".to_string());
    if !sntl_db.flush(Duration::from_secs(2)) {
        log::error!("[Audit] Shutdown without a confirmed final fsync");
    }
    let _ = std::fs::remove_file(socket_path);
    let _ = std::fs::remove_file(&args.control_socket);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("sokol-db-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("audit.log").to_string_lossy().into_owned()
    }

    /// F07: with an event every 30 ms the old writer's 100 ms receive timeout never fired and
    /// nothing was fsynced until 64 records had piled up (about 2 s here).
    #[test]
    fn a_steady_stream_is_fsynced_within_the_interval() {
        let db = SentinelDb::init(&temp_log("steady"), None).unwrap();
        for i in 0..20 {
            db.append(format!("EVENT|{}", i));
            std::thread::sleep(Duration::from_millis(30));
        }
        let status = db.status();
        assert!(status.healthy);
        assert!(
            status.last_sync_age_ms < 250,
            "last fsync {} ms ago under a 30 ms event stream",
            status.last_sync_age_ms
        );
        assert!(db.flush(Duration::from_secs(2)));
    }

    #[test]
    fn a_second_node_cannot_open_the_same_audit_log() {
        let path = temp_log("twice");
        let _first = SentinelDb::init(&path, None).unwrap();
        let second = SentinelDb::init(&path, None);
        assert!(
            second.is_err(),
            "two writers would interleave sequence numbers"
        );
    }
}
