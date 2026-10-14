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
use axum::{
    extract::{Json, Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive},
        Html, IntoResponse, Response, Sse,
    },
    routing::{get, post},
    Router,
};
use chrono::Utc;
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet, convert::Infallible, path::Path as StdPath, sync::Arc, time::Duration,
};
use sysinfo::{Networks, System};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener, UnixStream},
    sync::RwLock,
};

#[derive(Clone, Serialize, Deserialize)]
struct ClientNode {
    id: u32,
    name: String,
    endpoint: String,
    control_socket: String,
    health_status: String,
    last_seen: String,
    xdp_loaded: bool,
    defense_mode: String,
    packets_dropped: u64,
    blacklist: HashSet<String>,
    #[serde(default)]
    ban_readback: BanReadback,
    /// uid of the process that first announced this node; its heartbeats (and control socket)
    /// must keep coming from it.
    #[serde(skip)]
    uid: u32,
    /// When its last heartbeat arrived; the view marks the node STALE after NODE_STALE_AFTER.
    #[serde(skip)]
    seen_at: Option<std::time::Instant>,
}

#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ReadbackStatus {
    #[default]
    Unknown,
    Fresh,
    Stale,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct BanReadback {
    status: ReadbackStatus,
    observed_at: Option<String>,
    age_ms: Option<u64>,
    total: Option<usize>,
    error: Option<String>,
    #[serde(skip)]
    observed_when: Option<std::time::Instant>,
    #[serde(skip)]
    attempt: Option<Arc<()>>,
}

impl BanReadback {
    fn view(&self, now: std::time::Instant) -> Self {
        let mut view = self.clone();
        if let Some(when) = self.observed_when {
            let age = now.saturating_duration_since(when);
            view.age_ms = Some(age.as_millis().min(u64::MAX as u128) as u64);
            if age > BANS_STALE_AFTER {
                view.status = ReadbackStatus::Stale;
            }
        }
        view
    }
}

#[derive(Debug)]
enum ControlOutcome {
    Confirmed(String),
    Rejected(String),
    NotSent(String),
    Unknown(String),
}

impl ControlOutcome {
    fn into_result(self) -> Result<String, String> {
        match self {
            Self::Confirmed(reply) => Ok(reply),
            Self::Rejected(error) | Self::NotSent(error) | Self::Unknown(error) => Err(error),
        }
    }
}

/// ADR-0005: `OK …; WARNING: not yet durable` is not plain `OK`. The node acknowledged the
/// command but cannot yet say it is on disk; that warning stays in the answer.
fn command_json(outcome: ControlOutcome) -> Json<serde_json::Value> {
    let (status, success, error, warning) = match outcome {
        ControlOutcome::Confirmed(reply) => (
            "CONFIRMED",
            true,
            None,
            reply.split_once("WARNING:").map(|(_, w)| {
                w.trim()
                    .chars()
                    .take(CONTROL_ERROR_CHARS)
                    .collect::<String>()
            }),
        ),
        ControlOutcome::Rejected(e) => ("REJECTED", false, Some(e), None),
        ControlOutcome::NotSent(e) => ("NOT_SENT", false, Some(e), None),
        ControlOutcome::Unknown(e) => ("UNKNOWN", false, Some(e), None),
    };
    Json(serde_json::json!({"success":success, "outcome":status, "error":error, "warning":warning}))
}

#[derive(Clone, Serialize, Deserialize)]
struct SecurityAlert {
    id: u64,
    timestamp: String,
    node_id: u32,
    source_ip: String,
    attack_vector: String,
    mitigation: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct TrapMetrics {
    tier1_bot_tarpit: u64,
    tier1_5_slow_drip: u64,
    tier2_payload_capture: u64,
    tier3_interactive_jail: u64,
    total_bytes_captured: u64,
    active_banned_ips: usize,
    total_dropped: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct SystemMetrics {
    p2p_active_peers: u32,
    dag_tips: u32,
    db_latency_ms: f32,
    db_size_mb: f32,
    traps: TrapMetrics,
}

#[derive(Clone)]
struct AppState {
    nodes: Arc<RwLock<Vec<ClientNode>>>,
    alerts: Arc<RwLock<Vec<SecurityAlert>>>,
    metrics: Arc<RwLock<SystemMetrics>>,
    token: Arc<String>,
    /// uids allowed to send telemetry and to serve node control sockets.
    node_uids: Arc<HashSet<u32>>,
}

const SESSION_COOKIE: &str = "sokol_operator";
const TELEMETRY_MAX_CONNS: usize = 32;
/// Heartbeats come every second; a node silent this long is shown as STALE.
const NODE_STALE_AFTER: Duration = Duration::from_secs(15);
/// A node silent this long is dropped from the view.
const NODE_FORGET_AFTER: Duration = Duration::from_secs(3600);
/// How often the dashboard re-reads each node's bans from the node itself.
const BANS_REFRESH: Duration = Duration::from_secs(5);
const BANS_STALE_AFTER: Duration = Duration::from_secs(15);
// LIST_BANS emits at most 4096 IPv4/IPv6 targets; 256 KiB includes the count and framing.
const CONTROL_REPLY_BYTES: u64 = 256 * 1024;
const MAX_LISTED_BANS: usize = 4096;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(3);
const CONTROL_ERROR_CHARS: usize = 512;
const TELEMETRY_MAX_LINE: u64 = 8192;
const TELEMETRY_IDLE: Duration = Duration::from_secs(10);

/// uids allowed to send telemetry and serve node control sockets: `SOKOL_NODE_UIDS`
/// (comma-separated), by default root and the operator's own uid.
fn node_uids_from_env() -> HashSet<u32> {
    match std::env::var("SOKOL_NODE_UIDS") {
        Ok(list) => list
            .split(',')
            .filter_map(|u| u.trim().parse().ok())
            .collect(),
        Err(_) => [0, unsafe { libc::getuid() }].into_iter().collect(),
    }
}

/// Mode 0660, and group `SOKOL_TELEMETRY_GROUP` if set (so a node running as another user in
/// that group can write). Without the group only the operator's own uid (and root) can connect.
fn restrict_telemetry_socket(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(group) = std::env::var("SOKOL_TELEMETRY_GROUP") {
        let name = std::ffi::CString::new(group.clone()).map_err(|e| e.to_string())?;
        let gr = unsafe { libc::getgrnam(name.as_ptr()) };
        if gr.is_null() {
            return Err(format!("group {} does not exist", group));
        }
        let gid = unsafe { (*gr).gr_gid };
        let cpath = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
        if unsafe { libc::chown(cpath.as_ptr(), u32::MAX, gid) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| e.to_string())
}

/// Reads newline-framed telemetry until EOF, idle timeout or an over-long line: a heartbeat split
/// across reads is not lost, and a silent or flooding writer cannot hold a slot forever.
async fn read_telemetry(state: &AppState, uid: u32, stream: UnixStream) {
    use tokio::io::AsyncBufReadExt;
    let mut reader = tokio::io::BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        let mut limited = (&mut reader).take(TELEMETRY_MAX_LINE);
        match tokio::time::timeout(TELEMETRY_IDLE, limited.read_line(&mut line)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) if !line.ends_with('\n') && line.len() as u64 >= TELEMETRY_MAX_LINE => break,
            Ok(Ok(_)) => process_trident_telemetry(state, uid, &line).await,
        }
    }
}

/// Every API route needs this token, even on loopback: without it any web page the operator
/// visits could POST to the unauthenticated endpoints (a body-less POST needs no CORS preflight).
fn operator_token() -> Result<String, String> {
    match std::env::var("SOKOL_OPERATOR_TOKEN") {
        Ok(token) if token.len() >= 16 => Ok(token),
        Ok(_) => Err("SOKOL_OPERATOR_TOKEN must be at least 16 characters".into()),
        Err(_) => {
            let token: String = (0..32)
                .map(|_| format!("{:x}", rand::random::<u8>() & 0xF))
                .collect();
            log::warn!(
                "[*] SOKOL_OPERATOR_TOKEN not set; generated one-time token: {}",
                token
            );
            Ok(token)
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn presented_token(headers: &HeaderMap) -> Option<String> {
    if let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(bearer.trim().to_string());
    }
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| {
            kv.trim()
                .strip_prefix(&format!("{}=", SESSION_COOKIE))
                .map(str::to_string)
        })
}

async fn require_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    match presented_token(req.headers()) {
        Some(t) if constant_time_eq(t.as_bytes(), state.token.as_bytes()) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false, "error": "unauthorized" })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct LoginReq {
    token: String,
}

async fn api_login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Response {
    if !constant_time_eq(req.token.as_bytes(), state.token.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "success": false })),
        )
            .into_response();
    }
    let cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/",
        SESSION_COOKIE, state.token
    );
    (
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "success": true })),
    )
        .into_response()
}

/// The node control protocol is line-based, so anything but a plain address could smuggle
/// extra commands (e.g. "1.2.3.4\nXDP_UNLOAD").
fn parse_block_target(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    raw.parse::<ipnet::IpNet>().ok().map(|net| net.to_string())
}

#[derive(Deserialize)]
struct BlacklistReq {
    ip: String,
    action: String,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("[*] Запуск SOKOL-CORE Operations & Control Center...");

    let token = match operator_token() {
        Ok(token) => token,
        Err(e) => {
            log::error!("[!] {}", e);
            std::process::exit(1);
        }
    };

    let state = AppState {
        nodes: Arc::new(RwLock::new(Vec::new())),
        alerts: Arc::new(RwLock::new(Vec::new())),
        metrics: Arc::new(RwLock::new(SystemMetrics::default())),
        token: Arc::new(token),
        node_uids: Arc::new(node_uids_from_env()),
    };

    let state_clone = state.clone();
    tokio::spawn(async move {
        // The node writes to this fixed path (push_telemetry in the orchestrator).
        let socket_path = "/run/sokol_telemetry.sock".to_string();
        if StdPath::new(&socket_path).exists() {
            let _ = std::fs::remove_file(&socket_path);
        }
        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                log::error!(
                    "[!] Cannot create the telemetry socket {}: {}",
                    socket_path,
                    e
                );
                return;
            }
        };
        if let Err(e) = restrict_telemetry_socket(&socket_path) {
            log::error!("[!] Telemetry socket {}: {}", socket_path, e);
            return;
        }
        log::info!(
            "[*] Telemetry socket {} accepts uids {:?}",
            socket_path,
            state_clone.node_uids
        );
        let slots = Arc::new(tokio::sync::Semaphore::new(TELEMETRY_MAX_CONNS));
        while let Ok((stream, _)) = listener.accept().await {
            let Ok(uid) = stream.peer_cred().map(|c| c.uid()) else {
                continue;
            };
            if !state_clone.node_uids.contains(&uid) {
                log::warn!("[!] Telemetry from uid {} refused (not a node uid)", uid);
                continue;
            }
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                log::warn!(
                    "[!] {} telemetry connections open; refusing another",
                    TELEMETRY_MAX_CONNS
                );
                continue;
            };
            let state_inner = state_clone.clone();
            tokio::spawn(async move {
                let _permit = permit;
                read_telemetry(&state_inner, uid, stream).await;
            });
        }
    });

    tokio::spawn(refresh_all(state.clone()));
    let app = build_router(state);

    let bind_addr =
        std::env::var("SOKOL_OPERATOR_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let listener = TcpListener::bind(&bind_addr).await?;
    log::info!("[*] Command Center operational at http://{}", bind_addr);
    axum::serve(listener, app).await
}

fn build_router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/data", get(api_get_all_data))
        .route("/api/nodes/:id/blacklist", post(api_update_blacklist))
        .route("/api/nodes/:id/flush", post(api_flush_blacklist))
        .route("/metrics/stream", get(metrics_stream))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));

    Router::new()
        .route("/", get(dashboard_handler))
        .route("/api/login", post(api_login))
        .merge(protected)
        .with_state(state)
}

/// Applies telemetry sent by a process running as `uid` (already checked against the allowed
/// uids). A node stays bound to the uid that first announced it: a heartbeat for the same node id
/// from another uid is ignored, so it cannot redirect the operator's commands (CTL=).
async fn process_trident_telemetry(state: &AppState, uid: u32, raw_msg: &str) {
    let mut metrics = state.metrics.write().await;
    let mut alerts = state.alerts.write().await;
    let mut nodes = state.nodes.write().await;

    for line in raw_msg.lines() {
        if let Some(data) = line.strip_prefix("HEARTBEAT:") {
            let Some(id) = extract_value(data, "ID=").and_then(|id| id.parse::<u32>().ok()) else {
                log::warn!("Ignoring heartbeat without a valid node ID");
                continue;
            };
            if !nodes.iter().any(|n| n.id == id) {
                nodes.push(ClientNode {
                    id,
                    name: extract_value(data, "NAME=").unwrap_or(format!("Node-{}", id)),
                    endpoint: extract_value(data, "EP=").unwrap_or("Unknown".into()),
                    control_socket: extract_value(data, "CTL=")
                        .unwrap_or_else(|| format!("/run/sokol_node_{}.sock", id)),
                    health_status: "HEALTHY".into(),
                    last_seen: Utc::now().format("%H:%M:%S").to_string(),
                    xdp_loaded: true,
                    defense_mode: extract_value(data, "MODE=").unwrap_or("NORMAL".into()),
                    packets_dropped: 0,
                    blacklist: HashSet::new(),
                    ban_readback: BanReadback::default(),
                    uid,
                    seen_at: Some(std::time::Instant::now()),
                });
                metrics.p2p_active_peers = nodes.len() as u32;
            } else if let Some(node) = nodes.iter_mut().find(|n| n.id == id) {
                if node.uid != uid {
                    log::warn!(
                        "[!] Heartbeat for node {} from uid {} ignored: the node belongs to uid {}",
                        id,
                        uid,
                        node.uid
                    );
                    continue;
                }
                node.last_seen = Utc::now().format("%H:%M:%S").to_string();
                node.seen_at = Some(std::time::Instant::now());
                if let Some(ctl) = extract_value(data, "CTL=") {
                    if node.control_socket != ctl {
                        node.control_socket = ctl;
                        node.blacklist.clear();
                        node.ban_readback = BanReadback::default();
                    }
                }
            }
        } else if let Some(data) = line.strip_prefix("DB_LOG:") {
            // VEC is the final, opaque field: client diagnostics may contain pipes and
            // key-shaped text. They must not supply telemetry header fields or choose a tier.
            let (header, vector) = data.split_once("|VEC=").unwrap_or_else(|| {
                data.strip_prefix("VEC=")
                    .map_or((data, "Unknown Anomaly"), |vector| ("", vector))
            });
            let Some(node_id) =
                extract_value(header, "NODE=").and_then(|id| id.parse::<u32>().ok())
            else {
                log::warn!("Ignoring telemetry log without a valid node ID");
                continue;
            };
            match extract_value(header, "TIER=").as_deref() {
                Some("Tier1BotTarpit") => metrics.traps.tier1_bot_tarpit += 1,
                Some("Tier1_5SlowDrip") => metrics.traps.tier1_5_slow_drip += 1,
                Some("Tier2PayloadCapture") => metrics.traps.tier2_payload_capture += 1,
                Some("Tier3InteractiveJail") => metrics.traps.tier3_interactive_jail += 1,
                _ => {}
            }

            let new_id = alerts.len() as u64 + 1;
            alerts.insert(
                0,
                SecurityAlert {
                    id: new_id,
                    timestamp: Utc::now().format("%H:%M:%S").to_string(),
                    node_id,
                    source_ip: extract_value(header, "IP=").unwrap_or_else(|| "Unknown".into()),
                    attack_vector: vector.to_string(),
                    mitigation: "TRIDENT_TRAP_ENGAGED".into(),
                },
            );
            if alerts.len() > 50 {
                alerts.pop();
            }
        } else if let Some(ip) = line.strip_prefix("DROP_IMMEDIATE:") {
            metrics.traps.active_banned_ips += 1;
            metrics.traps.total_dropped += 1;
            log::warn!("[XDP BAN SYNC] IP permanently blocked: {}", ip.trim());
        }
    }
}

fn extract_value(s: &str, key: &str) -> Option<String> {
    s.split('|')
        .find_map(|p| p.strip_prefix(key))
        .map(str::to_string)
}

async fn dashboard_handler() -> Html<&'static str> {
    Html(HTML_DASHBOARD)
}

/// The nodes as the operator should see them: health from the heartbeat's age, not a flag set
/// once and never cleared.
fn observed_nodes(nodes: &[ClientNode]) -> Vec<ClientNode> {
    nodes
        .iter()
        .map(|n| {
            let mut n = n.clone();
            n.ban_readback = n.ban_readback.view(std::time::Instant::now());
            if n.seen_at.is_none_or(|t| t.elapsed() > NODE_STALE_AFTER) {
                n.health_status = "STALE".into();
                n.xdp_loaded = false;
            }
            n
        })
        .collect()
}

async fn api_get_all_data(State(state): State<AppState>) -> Json<serde_json::Value> {
    // One lock at a time, each released before the next: holding `alerts` while waiting for
    // `metrics` deadlocked against telemetry, which takes `metrics` then `alerts` (review
    // 2026-10-05, prompted by an external analysis of await points under locks).
    let nodes = observed_nodes(&state.nodes.read().await);
    let alerts = state.alerts.read().await.clone();
    let metrics = state.metrics.read().await.clone();

    Json(serde_json::json!({
        "nodes": nodes,
        "alerts": alerts,
        "metrics": metrics,
        "timestamp": Utc::now().to_rfc3339()
    }))
}

async fn api_update_blacklist(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(req): Json<BlacklistReq>,
) -> Json<serde_json::Value> {
    let Some(target) = parse_block_target(&req.ip) else {
        return command_json(ControlOutcome::NotSent(format!(
            "'{}' is not an IP address or CIDR",
            req.ip.trim()
        )));
    };
    let adding = match req.action.as_str() {
        "add" => true,
        "remove" => false,
        other => {
            return command_json(ControlOutcome::NotSent(format!(
                "unknown action '{}'",
                other
            )))
        }
    };
    let Some((ctl, uid)) = route(&state, id).await else {
        return command_json(ControlOutcome::NotSent(format!("unknown node {}", id)));
    };
    let cmd = if adding {
        format!("BAN_IP:{}\n", target)
    } else {
        format!("UNBAN_IP:{}\n", target)
    };
    let outcome = control_exchange(&ctl, Some(uid), &state.node_uids, &cmd).await;
    refresh_bans(&state, id).await;
    command_json(outcome)
}

async fn api_flush_blacklist(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> Json<serde_json::Value> {
    let Some((ctl, uid)) = route(&state, id).await else {
        return command_json(ControlOutcome::NotSent(format!("unknown node {}", id)));
    };
    // One command on the node: operator bans and dynamic blocks, whatever this dashboard knew.
    let outcome = control_exchange(&ctl, Some(uid), &state.node_uids, "FLUSH_ALL\n").await;
    refresh_bans(&state, id).await;
    command_json(outcome)
}

/// The node's control socket and uid, read without holding the lock during socket I/O.
async fn route(state: &AppState, id: u32) -> Option<(String, u32)> {
    state
        .nodes
        .read()
        .await
        .iter()
        .find(|n| n.id == id)
        .map(|n| (n.control_socket.clone(), n.uid))
}

/// Re-reads a node's operator bans from the node (LIST_BANS): the node, not this dashboard, is
/// the source of truth, so a dashboard restart or another operator's change shows up here.
fn parse_bans(reply: &str) -> Result<(usize, HashSet<String>), String> {
    let mut fields = reply.split_whitespace();
    let total = fields
        .next()
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or_else(|| "invalid LIST_BANS count".to_string())?;
    let mut bans = HashSet::new();
    for field in fields {
        let target =
            parse_block_target(field).ok_or_else(|| "invalid LIST_BANS target".to_string())?;
        if bans.len() >= MAX_LISTED_BANS {
            return Err(format!(
                "LIST_BANS lists more than {MAX_LISTED_BANS} targets"
            ));
        }
        if !bans.insert(target) {
            return Err("duplicate LIST_BANS target".into());
        }
    }
    if bans.len() != total.min(MAX_LISTED_BANS) {
        return Err("LIST_BANS count does not describe its targets".into());
    }
    Ok((total, bans))
}

async fn refresh_bans(state: &AppState, id: u32) {
    let ticket = Arc::new(());
    let (ctl, uid) = {
        let mut nodes = state.nodes.write().await;
        let Some(node) = nodes.iter_mut().find(|n| n.id == id) else {
            return;
        };
        node.ban_readback.attempt = Some(ticket.clone());
        (node.control_socket.clone(), node.uid)
    };
    let result = query_node(&ctl, Some(uid), &state.node_uids, "LIST_BANS\n")
        .await
        .and_then(|reply| parse_bans(&reply));
    let mut nodes = state.nodes.write().await;
    let Some(node) = nodes.iter_mut().find(|n| n.id == id) else {
        return;
    };
    // Only the latest attempt on this route may publish a result, even if a node was
    // forgotten/re-announced while the socket I/O was in flight.
    if !node
        .ban_readback
        .attempt
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, &ticket))
    {
        return;
    }
    match result {
        Ok((total, bans)) => {
            node.blacklist = bans;
            node.ban_readback.status = ReadbackStatus::Fresh;
            node.ban_readback.observed_at = Some(Utc::now().to_rfc3339());
            node.ban_readback.observed_when = Some(std::time::Instant::now());
            node.ban_readback.total = Some(total);
            node.ban_readback.error = None;
        }
        Err(error) => {
            node.ban_readback.status = if node.ban_readback.observed_when.is_some() {
                ReadbackStatus::Stale
            } else {
                ReadbackStatus::Unknown
            };
            node.ban_readback.error = Some(error.chars().take(CONTROL_ERROR_CHARS).collect());
        }
    }
}

/// Keeps every node's ban list in line with the node, and forgets nodes gone for long.
async fn refresh_all(state: AppState) {
    loop {
        state
            .nodes
            .write()
            .await
            .retain(|n| n.seen_at.is_some_and(|t| t.elapsed() < NODE_FORGET_AFTER));
        let ids: Vec<u32> = state.nodes.read().await.iter().map(|n| n.id).collect();
        for id in ids {
            refresh_bans(&state, id).await;
        }
        tokio::time::sleep(BANS_REFRESH).await;
    }
}

/// Queries the authenticated control socket. Readback failures preserve the last observation.
async fn query_node(
    socket_path: &str,
    node_uid: Option<u32>,
    allowed: &HashSet<u32>,
    cmd: &str,
) -> Result<String, String> {
    control_exchange(socket_path, node_uid, allowed, cmd)
        .await
        .into_result()
}

async fn control_exchange(
    socket_path: &str,
    node_uid: Option<u32>,
    allowed: &HashSet<u32>,
    cmd: &str,
) -> ControlOutcome {
    use tokio::io::AsyncBufReadExt;
    if !StdPath::new(socket_path).exists() {
        return ControlOutcome::NotSent(format!(
            "node control socket {} is not available",
            socket_path
        ));
    }
    let mut attempted_write = false;
    let exchange = async {
        let mut socket = UnixStream::connect(socket_path)
            .await
            .map_err(|e| e.to_string())?;
        let served_by = socket.peer_cred().map_err(|e| e.to_string())?.uid();
        let trusted = node_uid.map_or_else(|| allowed.contains(&served_by), |uid| served_by == uid);
        if !trusted {
            return Err(format!(
                "control socket {} is served by uid {}, not by the node's uid",
                socket_path, served_by
            ));
        }
        // A partial write can reach the peer: after this point loss of the reply is unknown.
        attempted_write = true;
        socket
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut reply = String::new();
        tokio::io::BufReader::new(&mut socket)
            .take(CONTROL_REPLY_BYTES)
            .read_line(&mut reply)
            .await
            .map_err(|e| e.to_string())?;
        if !reply.ends_with('\n') {
            return Err("node reply is oversized or incomplete".into());
        }
        Ok::<String, String>(reply.trim().to_string())
    };
    let result = match tokio::time::timeout(CONTROL_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_) => Err("node did not answer within 3 s".into()),
    };
    match result {
        Err(error) if attempted_write => ControlOutcome::Unknown(error),
        Err(error) => ControlOutcome::NotSent(error),
        Ok(reply) => {
            if reply == "OK" {
                return ControlOutcome::Confirmed(String::new());
            }
            if let Some(rest) = reply.strip_prefix("OK ") {
                return ControlOutcome::Confirmed(rest.trim().to_string());
            }
            if reply == "ERR" {
                return ControlOutcome::Rejected("node refused the command".into());
            }
            if let Some(rest) = reply.strip_prefix("ERR ") {
                return ControlOutcome::Rejected(rest.chars().take(CONTROL_ERROR_CHARS).collect());
            }
            ControlOutcome::Unknown("node returned an unrecognised reply".into())
        }
    }
}

async fn metrics_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let sys = System::new_all();
    let networks = Networks::new_with_refreshed_list();

    struct MetricsCtx {
        rx: u64,
        tx: u64,
        drops: u64,
    }
    let initial_ctx = MetricsCtx {
        rx: 0,
        tx: 0,
        drops: state.metrics.read().await.traps.total_dropped,
    };

    let stream = stream::unfold(
        (sys, networks, initial_ctx, state),
        move |(mut sys, mut networks, mut ctx, state)| async move {
            tokio::time::sleep(Duration::from_secs(1)).await;

            sys.refresh_cpu_all();
            networks.refresh(true);

            let mut current_rx: u64 = 0;
            let mut current_tx: u64 = 0;

            for (_, data) in &networks {
                current_rx += data.packets_received();
                current_tx += data.packets_transmitted();
            }

            let pps_rx = if ctx.rx > 0 {
                current_rx.saturating_sub(ctx.rx)
            } else {
                0
            };
            let pps_tx = if ctx.tx > 0 {
                current_tx.saturating_sub(ctx.tx)
            } else {
                0
            };

            let current_drops = state.metrics.read().await.traps.total_dropped;
            let drops_sec = if ctx.drops > 0 {
                current_drops.saturating_sub(ctx.drops)
            } else {
                0
            };

            ctx.rx = current_rx;
            ctx.tx = current_tx;
            ctx.drops = current_drops;

            let cpu_usage = sys.global_cpu_usage();
            let payload = format!(
                r#"{{"cpu": {:.1}, "pps_rx": {}, "pps_tx": {}, "drops_sec": {}}}"#,
                cpu_usage, pps_rx, pps_tx, drops_sec
            );
            Some((
                Ok(Event::default().data(payload)),
                (sys, networks, ctx, state),
            ))
        },
    );

    Sse::new(stream).keep_alive(KeepAlive::new())
}

const HTML_DASHBOARD: &str = r###"
<!DOCTYPE html>
<html lang="uk" class="dark">
<head>
    <meta charset="UTF-8">
    <title>SOKOL-CORE // Operations Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #18181b; }
        ::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 3px; }
    </style>
</head>
<body class="bg-zinc-950 text-zinc-300 font-mono antialiased min-h-screen p-4 text-sm">
    <div class="max-w-screen-2xl mx-auto space-y-4">
        <form id="login-form" class="hidden rounded-lg border border-amber-800 p-3 flex gap-2" onsubmit="loginSubmit(event)">
            <label for="operator-token">Operator token</label>
            <input id="operator-token" type="password" autocomplete="off" required class="bg-zinc-900 border border-zinc-700 rounded px-2" />
            <button type="submit" class="text-amber-300">Connect</button>
            <span id="login-error" class="text-red-400"></span>
        </form>
        <div id="command-status" role="status" class="hidden rounded-lg border p-3"></div>
        <div id="data-status" role="status" class="text-xs text-amber-400">Waiting for node observations…</div>
        <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex items-center justify-between">
                <div>
                    <h1 class="font-bold text-amber-500">SOKOL-CORE</h1>
                    <p class="text-[10px] text-zinc-500">XDP enforcement + trust mesh</p>
                </div>
                <div class="text-right">
                    <div class="text-[10px]">SYS CPU</div>
                    <div id="m-cpu" class="text-xl font-bold text-emerald-400">0.0%</div>
                </div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex items-center justify-between">
                <div>
                    <div class="text-[10px] text-zinc-500">TRAP TIER-1 (TARPIT)</div>
                    <div id="trap-t1" class="text-xl font-bold text-cyan-400">0</div>
                </div>
                <div class="text-right text-[10px] text-zinc-500">Scanners</div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex items-center justify-between">
                <div>
                    <div class="text-[10px] text-zinc-500">TRAP TIER-1.5 (SLOW DRIP)</div>
                    <div id="trap-t15" class="text-xl font-bold text-amber-400">0</div>
                </div>
                <div class="text-right text-[10px] text-zinc-500">Floods</div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex items-center justify-between">
                <div>
                    <div class="text-[10px] text-zinc-500">TRAP TIER-2 (PAYLOAD CAPTURE)</div>
                    <div id="trap-t2" class="text-xl font-bold text-purple-400">0</div>
                </div>
                <div class="text-right text-[10px] text-zinc-500">Shellcode-like</div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex items-center justify-between">
                <div>
                    <div class="text-[10px] text-zinc-500">TRAP TIER-3 (JAIL)</div>
                    <div id="trap-t3" class="text-xl font-bold text-red-500">0</div>
                </div>
                <div class="text-right text-[10px] text-zinc-500">Interactive</div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex items-center justify-between">
                <div>
                    <div class="text-[10px] text-zinc-500">P2P MESH SWARM</div>
                    <div class="font-bold text-zinc-100"><span id="m-peers" class="text-cyan-400">0</span> Active Nodes | DAG Tips: <span id="m-dag" class="text-cyan-500">0</span></div>
                </div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex items-center justify-between">
                <div>
                    <div class="text-[10px] text-zinc-500">AUDIT LOG STORAGE</div>
                    <div class="font-bold text-zinc-100">Latency: <span id="m-dblat" class="text-amber-400">0 ms</span> | Banned IPs: <span id="trap-banned" class="text-red-400">0</span></div>
                </div>
            </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div class="lg:col-span-2 space-y-4">
                <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="font-bold text-zinc-100">Global Network Traffic (Real-time PPS)</h3>
                        <div class="flex gap-4 text-xs">
                            <div>RX: <span id="m-pps-rx" class="text-emerald-400 font-bold">0</span> pps</div>
                            <div>DROPS: <span id="m-drops" class="text-red-400 font-bold">0</span> /sec</div>
                        </div>
                    </div>
                    <div class="h-48 w-full"><canvas id="trafficChart"></canvas></div>
                </div>

                <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl">
                    <h3 class="font-bold text-zinc-100 mb-3">Trident Security & Trap Telemetry Log</h3>
                    <div class="overflow-x-auto h-48">
                        <table class="w-full text-xs text-left">
                            <thead class="bg-zinc-950 sticky top-0">
                                <tr>
                                    <th class="p-2 text-zinc-500">Time</th>
                                    <th class="p-2">Node</th>
                                    <th class="p-2">Attacker IP</th>
                                    <th class="p-2">Vector / Telemetry Payload</th>
                                    <th class="p-2">Action</th>
                                </tr>
                            </thead>
                            <tbody id="alerts-table" class="divide-y divide-zinc-800">
                                <tr><td colspan="5" class="p-4 text-center text-zinc-600">Очікування телеметрії...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex flex-col h-full">
                <h3 class="font-bold text-zinc-100 mb-3 flex justify-between items-center">
                    <span>Trident Defense Nodes</span>
                    <button onclick="fetchData()" class="text-xs text-zinc-500 hover:text-zinc-300">↻ Refresh</button>
                </h3>
                <div id="nodes-container" class="space-y-4 overflow-y-auto flex-1 pr-2">
                    <div class="text-center text-zinc-600 mt-10">Очікування підключення вузлів (Heartbeat)...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(ctx, {
            type: 'line',
            data: { labels: Array(20).fill(''), datasets: [
                { label: 'RX Packets', borderColor: '#34d399', backgroundColor: 'rgba(52, 211, 153, 0.1)', data: Array(20).fill(0), tension: 0.4, fill: true, pointRadius: 0 },
                { label: 'Dropped', borderColor: '#f87171', data: Array(20).fill(0), tension: 0.4, pointRadius: 0 }
            ]},
            options: { responsive: true, maintainAspectRatio: false, animation: false, scales: { x: { display: false }, y: { grid: { color: '#27272a' }, ticks: { color: '#71717a' }, beginAtZero: true}}, plugins: { legend: { display: false } }}
        });

        function esc(v) {
            return String(v).replace(/[&<>"'`]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[c]));
        }

        async function login() {
            document.getElementById('login-form').classList.remove('hidden');
            return false;
        }

        async function loginSubmit(event) {
            event.preventDefault();
            const input = document.getElementById('operator-token');
            try {
                const res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: input.value }) });
                if (!res.ok) throw new Error('Token rejected');
                input.value = '';
                document.getElementById('login-error').textContent = '';
                document.getElementById('login-form').classList.add('hidden');
                fetchData(); initSSE();
            } catch (e) { document.getElementById('login-error').textContent = e.message; }
        }

        async function authedFetch(url, opts) {
            let res = await fetch(url, opts);
            if (res.status === 401 && await login()) { res = await fetch(url, opts); initSSE(); }
            return res;
        }

        function report(data) {
            const box = document.getElementById('command-status');
            const labels = {
                CONFIRMED: 'Node confirmed the command. Check the ban readback below.',
                REJECTED: 'Node refused the command.',
                NOT_SENT: 'Command was not sent.',
                UNKNOWN: 'Outcome unknown. The command may have taken effect; read the current state before retrying.'
            };
            const outcome = data.outcome || 'UNKNOWN';
            box.className = 'rounded-lg border p-3 ' + (outcome === 'CONFIRMED' && !data.warning ? 'border-emerald-800 text-emerald-300' : 'border-amber-800 text-amber-300');
            box.textContent = (labels[outcome] || labels.UNKNOWN) + (data.error ? ' ' + data.error : '') + (data.warning ? ' WARNING: ' + data.warning : '');
        }

        async function fetchData() {
            try {
                const res = await authedFetch('/api/data');
                if (!res.ok) throw new Error('Operator API unavailable: ' + res.status);
                const data = await res.json();
                document.getElementById('data-status').textContent = 'Node observations received ' + new Date(data.timestamp).toLocaleTimeString();
                document.getElementById('data-status').className = 'text-xs text-zinc-400';
                document.getElementById('m-peers').innerText = data.metrics.p2p_active_peers;
                document.getElementById('m-dag').innerText = data.metrics.dag_tips;
                document.getElementById('m-dblat').innerText = data.metrics.db_latency_ms.toFixed(1) + ' ms';
                
                document.getElementById('trap-t1').innerText = data.metrics.traps.tier1_bot_tarpit;
                document.getElementById('trap-t15').innerText = data.metrics.traps.tier1_5_slow_drip;
                document.getElementById('trap-t2').innerText = data.metrics.traps.tier2_payload_capture;
                document.getElementById('trap-t3').innerText = data.metrics.traps.tier3_interactive_jail;
                document.getElementById('trap-banned').innerText = data.metrics.traps.active_banned_ips;

                {
                    const active = document.activeElement;
                    const focusId = active && active.id.startsWith('ip-in-') ? active.id : null;
                    const drafts = new Map(Array.from(document.querySelectorAll('input[id^="ip-in-"]')).map(input => [input.id, input.value]));
                    const nodeKey = JSON.stringify(data.nodes.map(({last_seen, ban_readback, ...node}) => ({...node, blacklist: [...node.blacklist].sort(), ban_readback: {...ban_readback, age_ms: null, observed_at: null}})));
                    if (nodeKey !== window.lastNodeKey) {
                    document.getElementById('nodes-container').innerHTML = data.nodes.map(n => `
                        <div class="bg-zinc-950 border border-zinc-800 rounded-lg p-3">
                            <div class="flex justify-between items-start mb-2">
                                <div>
                                    <div class="font-bold text-emerald-400">${esc(n.name)}</div>
                                    <div class="text-[10px] text-zinc-500">${esc(n.endpoint)}</div>
                                </div>
                                <div class="flex flex-col gap-1 text-right">
                                    <span class="text-[9px] text-zinc-400">Heartbeat: ${esc(n.health_status)}</span>
                                    <span class="text-[9px] px-1.5 py-0.5 rounded ${n.xdp_loaded ? 'bg-emerald-900/30 text-emerald-500 border border-emerald-900' : 'bg-red-900/30 text-red-500 border border-red-900'}">${n.health_status === 'STALE' ? 'XDP: UNKNOWN' : (n.xdp_loaded ? 'XDP: REPORTED ON' : 'XDP: REPORTED OFF')}</span>
                                    <span class="text-[9px] px-1.5 py-0.5 rounded ${n.defense_mode === 'MAX_SHIELD' ? 'bg-amber-900/30 text-amber-500 border border-amber-900' : 'bg-zinc-800 text-zinc-400 border border-zinc-700'}">${esc(n.defense_mode)}</span>
                                </div>
                            </div>
                            
                            <div class="mb-3 space-y-1">
                                <div class="text-[10px] text-zinc-400 flex justify-between">
                                    <span>Operator bans: ${n.ban_readback.total === null ? 'not observed' : `${n.blacklist.length} shown / ${n.ban_readback.total} reported`}</span>
                                    <button onclick="apiCall('/api/nodes/${n.id}/flush')" class="text-red-400 hover:text-red-300">Flush</button>
                                </div>
                                <div class="text-xs ${n.ban_readback.status === 'FRESH' ? 'text-emerald-400' : 'text-amber-400'}">
                                    ${esc(n.ban_readback.status)} · <span id="ban-age-${n.id}"></span>
                                    ${n.ban_readback.total > n.blacklist.length ? ' · Partial list' : ''}
                                </div>
                                ${n.ban_readback.error ? `<div class="text-xs text-amber-300">${esc(n.ban_readback.error)}</div>` : ''}
                                <div class="flex flex-wrap gap-1 ${n.ban_readback.status === 'FRESH' ? '' : 'opacity-60'}">
                                    ${Array.from(n.blacklist).sort().map(ip => `<span class="bg-zinc-900 border border-zinc-800 text-[10px] px-1.5 py-0.5 rounded flex items-center gap-1">${esc(ip)} <button data-node="${Number(n.id)}" data-ip="${esc(ip)}" class="unban text-red-500 hover:text-red-400">×</button></span>`).join('')}
                                </div>
                            </div>

                            <div class="flex gap-1 mb-2">
                                <input type="text" id="ip-in-${n.id}" placeholder="IP to ban..." class="bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs w-full outline-none focus:border-amber-500">
                                <button onclick="addIp(${n.id})" class="bg-red-950 border border-red-900 hover:bg-red-900 text-red-300 px-2 rounded text-xs">Ban</button>
                            </div>
                            
                        </div>
                    `).join('');
                    window.lastNodeKey = nodeKey;
                    for (const [id, value] of drafts) { const input = document.getElementById(id); if (input) input.value = value; }
                    if (focusId) document.getElementById(focusId)?.focus();
                    }
                    for (const n of data.nodes) {
                        const age = document.getElementById(`ban-age-${n.id}`);
                        if (age) age.textContent = n.ban_readback.age_ms === null ? 'No successful read yet' : `${Math.floor(n.ban_readback.age_ms / 1000)}s since last successful read`;
                    }
                }

                if (data.alerts.length > 0) {
                    document.getElementById('alerts-table').innerHTML = data.alerts.map(a => `
                        <tr class="hover:bg-zinc-900 transition border-b border-zinc-900/50">
                            <td class="p-2 whitespace-nowrap">${esc(a.timestamp)}</td>
                            <td class="p-2 text-cyan-400">#${esc(a.node_id)}</td>
                            <td class="p-2 font-bold text-red-400">${esc(a.source_ip)}</td>
                            <td class="p-2 text-amber-500 truncate max-w-xs" title="${esc(a.attack_vector)}">${esc(a.attack_vector)}</td>
                            <td class="p-2 text-emerald-400">${esc(a.mitigation)}</td>
                        </tr>
                    `).join('');
                }
            } catch (e) {
                document.getElementById('data-status').textContent = 'Operator API unavailable — displayed observations may be stale. ' + e.message;
                document.getElementById('data-status').className = 'text-xs text-amber-400';
            }
        }

        let evtSource = null;
        function initSSE() {
            if (evtSource) evtSource.close();
            evtSource = new EventSource("/metrics/stream");
            evtSource.onmessage = function(e) {
                const data = JSON.parse(e.data);
                document.getElementById('m-cpu').innerText = data.cpu.toFixed(1) + '%';
                document.getElementById('m-pps-rx').innerText = data.pps_rx.toLocaleString();
                document.getElementById('m-drops').innerText = data.drops_sec;

                trafficChart.data.datasets[0].data.shift();
                trafficChart.data.datasets[0].data.push(data.pps_rx);
                trafficChart.data.datasets[1].data.shift();
                trafficChart.data.datasets[1].data.push(data.drops_sec);
                trafficChart.update();
            }
        }

        async function apiCall(endpoint) {
            try {
                const res = await authedFetch(endpoint, { method: 'POST' });
                report(await res.json());
            } catch (e) { report({ outcome: 'UNKNOWN', error: 'Operator connection lost: ' + e.message }); }
            fetchData();
        }

        document.addEventListener('click', e => {
            const btn = e.target.closest('button.unban');
            if (btn) modifyBlacklist(Number(btn.dataset.node), btn.dataset.ip, 'remove');
        });

        async function modifyBlacklist(id, ip, action) {
            try {
                const res = await authedFetch(`/api/nodes/${id}/blacklist`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, action })
                });
                report(await res.json());
            } catch (e) { report({ outcome: 'UNKNOWN', error: 'Operator connection lost: ' + e.message }); }
            fetchData();
        }

        async function addIp(id) {
            const input = document.getElementById(`ip-in-${id}`);
            if (input.value) { await modifyBlacklist(id, input.value, 'add'); input.value = ''; }
        }

        fetchData(); setInterval(fetchData, 3000); initSSE();
    </script>
</body>
</html>
"###;
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    const TOKEN: &str = "test-token-0123456789";

    fn state() -> AppState {
        AppState {
            nodes: Arc::new(RwLock::new(Vec::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(SystemMetrics::default())),
            token: Arc::new(TOKEN.to_string()),
            node_uids: Arc::new([me()].into_iter().collect()),
        }
    }

    fn me() -> u32 {
        unsafe { libc::getuid() }
    }

    async fn call(
        app: Router,
        req: axum::http::Request<Body>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let res = app.oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn get(uri: &str) -> axum::http::request::Builder {
        axum::http::Request::builder().uri(uri)
    }

    fn post_json(uri: &str, body: serde_json::Value) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {}", TOKEN))
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn api_requires_the_token() {
        let app = build_router(state());
        let (status, _, _) = call(app.clone(), get("/api/data").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _, _) = call(
            app.clone(),
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/nodes/1/flush")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "body-less POST (CSRF shape) must be rejected"
        );

        let (status, _, _) = call(
            app.clone(),
            get("/api/data")
                .header(header::AUTHORIZATION, "Bearer wrong-token-000000")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _, _) = call(
            app.clone(),
            get("/api/data")
                .header(header::AUTHORIZATION, format!("Bearer {}", TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, _) = call(app.clone(), get("/").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK, "dashboard page itself is public");
    }

    #[tokio::test]
    async fn login_sets_a_strict_cookie_that_authorizes() {
        let app = build_router(state());
        let login = |token: &str| {
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "token": token }).to_string(),
                ))
                .unwrap()
        };
        let (status, _, _) = call(app.clone(), login("nope")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, headers, _) = call(app.clone(), login(TOKEN)).await;
        assert_eq!(status, StatusCode::OK);
        let cookie = headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));

        let pair = cookie.split(';').next().unwrap().to_string();
        let (status, _, _) = call(
            app,
            get("/api/data")
                .header(header::COOKIE, pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn control_actions_validate_input_and_report_real_outcome() {
        let st = state();
        process_trident_telemetry(&st, me(), "HEARTBEAT:ID=7|NAME=n7|EP=x|MODE=NORMAL\n").await;
        let app = build_router(st.clone());

        let (_, _, body) = call(
            app.clone(),
            post_json(
                "/api/nodes/7/blacklist",
                serde_json::json!({ "ip": "1.2.3.4\nXDP_UNLOAD", "action": "add" }),
            ),
        )
        .await;
        assert_eq!(body["success"], false, "newline injection must be rejected");

        let (_, _, body) = call(
            app.clone(),
            post_json(
                "/api/nodes/7/blacklist",
                serde_json::json!({ "ip": "203.0.113.5", "action": "add" }),
            ),
        )
        .await;
        assert_eq!(
            body["success"], false,
            "no node control socket exists, so this cannot succeed"
        );
        assert!(
            st.nodes.read().await[0].blacklist.is_empty(),
            "state must not change on failure"
        );

        let _ = app;
    }

    /// Review 2026-10-05: telemetry takes `metrics` then `alerts`; the data API took `alerts`
    /// then `metrics`, so each could wait for the other forever (dashboard frozen). While the
    /// API waits for `metrics`, it must hold no other lock telemetry needs.
    #[tokio::test]
    async fn the_data_api_holds_no_lock_while_it_waits_for_another() {
        let st = state();
        let telemetry_holds_metrics = st.metrics.write().await;
        let api = tokio::spawn(api_get_all_data(State(st.clone())));
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert!(!api.is_finished(), "the API must be waiting for metrics");
        assert!(
            st.alerts.try_write().is_ok(),
            "telemetry's next lock (alerts) is held by the waiting API: deadlock"
        );
        drop(telemetry_holds_metrics);
        let Json(body) = tokio::time::timeout(std::time::Duration::from_secs(2), api)
            .await
            .unwrap()
            .unwrap();
        assert!(body.get("metrics").is_some());
    }

    /// Review 2026-10-05 F2: the page offers only what a node carries out. Every API path the
    /// dashboard calls is served, and the removed controls (XDP toggle, shield mode, mesh
    /// broadcast to a socket nothing served) are gone from both the page and the router.
    #[tokio::test]
    async fn the_dashboard_calls_only_served_routes() {
        let mut paths = Vec::new();
        let mut rest = HTML_DASHBOARD;
        while let Some(at) = rest.find("/api/") {
            let tail = rest.get(at..).unwrap_or_default();
            let end = tail.find(['\'', '`', '"']).unwrap_or(tail.len());
            paths.push(
                tail.get(..end)
                    .unwrap_or_default()
                    .replace("${n.id}", "7")
                    .replace("${id}", "7"),
            );
            rest = tail.get(5..).unwrap_or_default();
        }
        assert!(paths.len() >= 4, "{:?}", paths);
        let st = state();
        process_trident_telemetry(&st, me(), "HEARTBEAT:ID=7|NAME=n7|EP=x|MODE=NORMAL\n").await;
        let app = build_router(st);
        for path in paths.iter().map(String::as_str).chain([
            "/api/nodes/7/toggle-xdp",
            "/api/nodes/7/shield",
            "/api/mesh/broadcast",
        ]) {
            let removed = path.ends_with("toggle-xdp")
                || path.ends_with("shield")
                || path.ends_with("broadcast");
            let method = if path == "/api/data" { "GET" } else { "POST" };
            let (status, _, _) = call(
                app.clone(),
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::AUTHORIZATION, format!("Bearer {}", TOKEN))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
            assert_eq!(
                status == StatusCode::NOT_FOUND,
                removed,
                "{} {} -> {}",
                method,
                path,
                status
            );
        }
        for gone in [
            "toggle-xdp",
            "/shield",
            "/api/mesh/broadcast",
            "FLUSH_ALL_BANS",
            "SYNC_DAG",
        ] {
            assert!(
                !HTML_DASHBOARD.contains(gone),
                "the page still offers {}",
                gone
            );
        }
    }

    /// A fake node that answers like the orchestrator's control socket.
    /// A node control socket that keeps its operator bans, like the orchestrator's.
    async fn fake_node(path: std::path::PathBuf, log: Arc<RwLock<Vec<String>>>) {
        use tokio::io::AsyncBufReadExt;
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let bans: Arc<RwLock<HashSet<String>>> = Arc::default();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let log = log.clone();
                let bans = bans.clone();
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut lines = tokio::io::BufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        log.write().await.push(line.clone());
                        let mut bans = bans.write().await;
                        let reply = if line.starts_with("BAN_IP:10.") {
                            "ERR 10.0.0.1 is protected (loopback)".to_string()
                        } else if let Some(ip) = line.strip_prefix("BAN_IP:") {
                            bans.insert(ip.to_string());
                            "OK banned".to_string()
                        } else if let Some(ip) = line.strip_prefix("UNBAN_IP:") {
                            bans.remove(ip);
                            "OK unbanned".to_string()
                        } else if line == "FLUSH_ALL" {
                            bans.clear();
                            "OK released".to_string()
                        } else if line == "LIST_BANS" {
                            let mut list: Vec<&String> = bans.iter().collect();
                            list.sort();
                            let list: Vec<&str> = list.iter().map(|s| s.as_str()).collect();
                            format!("OK {} {}", list.len(), list.join(" "))
                        } else {
                            "OK done".to_string()
                        };
                        let _ = w.write_all(format!("{}\n", reply).as_bytes()).await;
                    }
                });
            }
        });
    }

    /// F11: a node is bound to the uid that announced it; another uid cannot re-point its
    /// control socket, and a control socket served by another uid is not used.
    #[tokio::test]
    async fn a_node_is_bound_to_the_uid_that_announced_it() {
        let dir = std::env::temp_dir().join(format!("sokol-op-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("ctl.sock");
        let seen = Arc::new(RwLock::new(Vec::new()));
        fake_node(sock.clone(), seen.clone()).await;
        let st = state();
        let hb = |ctl: &str| format!("HEARTBEAT:ID=5|NAME=n5|EP=x|MODE=NORMAL|CTL={}\n", ctl);
        process_trident_telemetry(&st, me(), &hb(&sock.display().to_string())).await;
        process_trident_telemetry(&st, me() + 1, &hb("/tmp/attacker.sock")).await;
        assert_eq!(
            st.nodes.read().await[0].control_socket,
            sock.display().to_string(),
            "another uid re-pointed the node's control socket"
        );

        // The same node, recorded as another uid: the socket (served by us) is refused.
        st.nodes.write().await[0].uid = me() + 1;
        let app = build_router(st.clone());
        let (_, _, body) = call(
            app,
            post_json(
                "/api/nodes/5/blacklist",
                serde_json::json!({ "ip": "203.0.113.8", "action": "add" }),
            ),
        )
        .await;
        assert_eq!(body["success"], false, "{}", body);
        assert!(body["error"].as_str().unwrap().contains("served by uid"));
        assert!(
            seen.read().await.is_empty(),
            "the command reached the socket"
        );
    }

    /// F08: the node, not the dashboard, holds the bans: a restarted dashboard shows them again,
    /// and a flush is one command on the node whatever the dashboard knew.
    #[tokio::test]
    async fn the_ban_list_is_read_from_the_node() {
        let dir = std::env::temp_dir().join(format!("sokol-op-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("ctl.sock");
        let seen = Arc::new(RwLock::new(Vec::new()));
        fake_node(sock.clone(), seen.clone()).await;
        let hb = format!(
            "HEARTBEAT:ID=4|NAME=n4|EP=x|MODE=NORMAL|CTL={}\n",
            sock.display()
        );

        let first = state();
        process_trident_telemetry(&first, me(), &hb).await;
        let (_, _, body) = call(
            build_router(first.clone()),
            post_json(
                "/api/nodes/4/blacklist",
                serde_json::json!({ "ip": "203.0.113.9", "action": "add" }),
            ),
        )
        .await;
        assert_eq!(body["success"], true, "{}", body);

        // A new dashboard process knows nothing, until it reads the node.
        let restarted = state();
        process_trident_telemetry(&restarted, me(), &hb).await;
        assert!(restarted.nodes.read().await[0].blacklist.is_empty());
        refresh_bans(&restarted, 4).await;
        assert!(
            restarted.nodes.read().await[0]
                .blacklist
                .contains("203.0.113.9"),
            "a restarted dashboard lost the node's ban"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_live_heartbeat_cannot_make_failed_ban_readback_fresh() {
        let dir = std::env::temp_dir().join(format!("sokol-op-readback-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("ctl.sock");
        fake_node(sock.clone(), Arc::default()).await;
        let st = state();
        let hb = format!("HEARTBEAT:ID=4|CTL={}\n", sock.display());
        process_trident_telemetry(&st, me(), &hb).await;
        refresh_bans(&st, 4).await;
        let Json(before) = api_get_all_data(State(st.clone())).await;
        assert_eq!(before["nodes"][0]["ban_readback"]["status"], "FRESH");
        std::fs::remove_file(&sock).unwrap();
        process_trident_telemetry(&st, me(), &hb).await;
        refresh_bans(&st, 4).await;
        let Json(after) = api_get_all_data(State(st)).await;
        assert_eq!(after["nodes"][0]["health_status"], "HEALTHY");
        assert_eq!(after["nodes"][0]["ban_readback"]["status"], "STALE");
        assert_eq!(
            after["nodes"][0]["ban_readback"]["observed_at"],
            before["nodes"][0]["ban_readback"]["observed_at"]
        );
        assert!(after["nodes"][0]["ban_readback"]["error"].is_string());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_command_applied_without_a_reply_has_an_unknown_outcome() {
        use tokio::io::AsyncBufReadExt;
        let dir = std::env::temp_dir().join(format!("sokol-op-unknown-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("ctl.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let applied = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let effect = applied.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("the control request never reached the fixture")
                .unwrap();
            let mut reader = tokio::io::BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "BAN_IP:203.0.113.9\n");
            effect.store(true, std::sync::atomic::Ordering::SeqCst);
            // The node applied the command, then lost its reply.
        });
        let st = state();
        process_trident_telemetry(
            &st,
            me(),
            &format!("HEARTBEAT:ID=4|CTL={}\n", sock.display()),
        )
        .await;
        let (_, _, body) = call(
            build_router(st),
            post_json(
                "/api/nodes/4/blacklist",
                serde_json::json!({"ip":"203.0.113.9", "action":"add"}),
            ),
        )
        .await;
        server.await.unwrap();
        assert!(applied.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            body["outcome"], "UNKNOWN",
            "lost reply cannot prove rejection: {body}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sokol-op-{label}-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn reply_once(path: &std::path::Path, reply: String) -> tokio::task::JoinHandle<()> {
        use tokio::io::AsyncBufReadExt;
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("the control request never reached the fixture")
                .unwrap();
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            tokio::io::BufReader::new(r)
                .read_line(&mut line)
                .await
                .unwrap();
            let _ = w.write_all(reply.as_bytes()).await;
        })
    }

    #[test]
    fn ban_readback_age_is_independent_of_heartbeat_and_wall_time() {
        let now = std::time::Instant::now();
        let readback = BanReadback {
            status: ReadbackStatus::Fresh,
            observed_when: Some(now),
            ..Default::default()
        };
        assert_eq!(readback.view(now).age_ms, Some(0));
        assert_eq!(
            readback.view(now + BANS_STALE_AFTER).status,
            ReadbackStatus::Fresh
        );
        let stale = readback.view(now + BANS_STALE_AFTER + Duration::from_millis(1));
        assert_eq!(stale.status, ReadbackStatus::Stale);
        assert_eq!(stale.age_ms, Some(15_001));
        assert_eq!(
            BanReadback::default().view(now).status,
            ReadbackStatus::Unknown
        );
    }

    #[test]
    fn a_list_reply_reports_its_total_and_refuses_malformed_targets() {
        for bad in [
            "",
            "x",
            "0 203.0.113.9",
            "1",
            "1 nope",
            "2 203.0.113.9",
            "2 203.0.113.9 203.0.113.9",
        ] {
            assert!(parse_bans(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_bans("0").unwrap(), (0, HashSet::new()));
        assert_eq!(parse_bans("2 203.0.113.9 2001:db8::/64").unwrap().0, 2);
        let targets: Vec<_> = (0..MAX_LISTED_BANS)
            .map(|i| format!("10.{}.{}.1", i / 256, i % 256))
            .collect();
        let reply = format!("{} {}", MAX_LISTED_BANS + 1, targets.join(" "));
        let (total, listed) = parse_bans(&reply).unwrap();
        assert_eq!(total, MAX_LISTED_BANS + 1);
        assert_eq!(listed.len(), MAX_LISTED_BANS);
        assert!(parse_bans(&(reply + " 203.0.113.9")).is_err());
    }

    /// Review of #31: a reply over the listing cap and a reply with a repeated target are
    /// different faults; the operator reading the error must not look for a duplicate that
    /// is not there.
    #[test]
    fn an_over_long_list_and_a_duplicate_are_told_apart() {
        let targets: Vec<_> = (0..=MAX_LISTED_BANS)
            .map(|i| format!("10.{}.{}.1", i / 256, i % 256))
            .collect();
        let long = format!("{} {}", MAX_LISTED_BANS + 1, targets.join(" "));
        assert_eq!(
            parse_bans(&long).unwrap_err(),
            format!("LIST_BANS lists more than {MAX_LISTED_BANS} targets")
        );
        assert_eq!(
            parse_bans("2 203.0.113.9 203.0.113.9").unwrap_err(),
            "duplicate LIST_BANS target"
        );
    }

    #[tokio::test]
    async fn unread_and_invalid_lists_stay_unknown_then_recover() {
        let dir = scratch("invalid-readback");
        let sock = dir.join("ctl.sock");
        let st = state();
        process_trident_telemetry(
            &st,
            me(),
            &format!("HEARTBEAT:ID=4|CTL={}\n", sock.display()),
        )
        .await;
        for (reply, expected) in [
            ("OK 1 nope\n", "UNKNOWN"),
            ("OK 1 203.0.113.9\n", "FRESH"),
            ("OK 0 203.0.113.9\n", "STALE"),
            ("OK 0\n", "FRESH"),
        ] {
            let server = reply_once(&sock, reply.into()).await;
            refresh_bans(&st, 4).await;
            server.await.unwrap();
            let Json(body) = api_get_all_data(State(st.clone())).await;
            assert_eq!(body["nodes"][0]["ban_readback"]["status"], expected);
            if expected == "STALE" {
                assert_eq!(
                    body["nodes"][0]["blacklist"],
                    serde_json::json!(["203.0.113.9"])
                );
            }
        }
        let Json(body) = api_get_all_data(State(st)).await;
        assert_eq!(body["nodes"][0]["blacklist"], serde_json::json!([]));
        assert!(body["nodes"][0]["ban_readback"]["error"].is_null());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn late_readback_cannot_overwrite_a_new_attempt_or_route() {
        use tokio::io::AsyncBufReadExt;
        for change_route in [false, true] {
            let dir = scratch("late-readback");
            let sock = dir.join("old.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let st = state();
            let hb = |sock: &std::path::Path| format!("HEARTBEAT:ID=4|CTL={}\n", sock.display());
            process_trident_telemetry(&st, me(), &hb(&sock)).await;
            let first_state = st.clone();
            let first = tokio::spawn(async move { refresh_bans(&first_state, 4).await });
            let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("the control request never reached the fixture")
                .unwrap();
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            tokio::io::BufReader::new(r)
                .read_line(&mut line)
                .await
                .unwrap();
            let new_sock = if change_route {
                dir.join("new.sock")
            } else {
                sock.clone()
            };
            let server = if change_route {
                process_trident_telemetry(&st, me(), &hb(&new_sock)).await;
                reply_once(&new_sock, "OK 1 203.0.113.2\n".into()).await
            } else {
                tokio::spawn(async move {
                    let (stream, _) =
                        tokio::time::timeout(Duration::from_secs(2), listener.accept())
                            .await
                            .expect("the control request never reached the fixture")
                            .unwrap();
                    let (r, mut w) = stream.into_split();
                    tokio::io::BufReader::new(r)
                        .read_line(&mut String::new())
                        .await
                        .unwrap();
                    w.write_all(b"OK 1 203.0.113.2\n").await.unwrap();
                })
            };
            refresh_bans(&st, 4).await;
            server.await.unwrap();
            w.write_all(b"OK 1 203.0.113.1\n").await.unwrap();
            first.await.unwrap();
            let Json(body) = api_get_all_data(State(st)).await;
            assert_eq!(
                body["nodes"][0]["blacklist"],
                serde_json::json!(["203.0.113.2"])
            );
            assert_eq!(body["nodes"][0]["ban_readback"]["status"], "FRESH");
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn control_outcomes_require_an_exact_bounded_complete_reply() {
        let (_, _, invalid) = call(
            build_router(state()),
            post_json(
                "/api/nodes/4/blacklist",
                serde_json::json!({"ip":"not-an-ip", "action":"add"}),
            ),
        )
        .await;
        assert_eq!(
            invalid["outcome"], "NOT_SENT",
            "invalid input never reaches the node"
        );
        let (_, _, invalid) = call(
            build_router(state()),
            post_json(
                "/api/nodes/4/blacklist",
                serde_json::json!({"ip":"203.0.113.9", "action":"other"}),
            ),
        )
        .await;
        assert_eq!(invalid["outcome"], "NOT_SENT");
        let dir = scratch("replies");
        let sock = dir.join("ctl.sock");
        for (reply, expected) in [
            ("OK banned\n".to_string(), "CONFIRMED"),
            ("OK\n".into(), "CONFIRMED"),
            ("ERR protected\n".into(), "REJECTED"),
            ("ERR\n".into(), "REJECTED"),
            ("OKAY\n".into(), "UNKNOWN"),
            (
                "OK".to_string() + &" ".repeat(262_144 - 3) + "\n",
                "CONFIRMED",
            ),
            (
                "OK".to_string() + &" ".repeat(262_144 - 2) + "\n",
                "UNKNOWN",
            ),
            ("OK banned".into(), "UNKNOWN"),
            ("\n".into(), "UNKNOWN"),
            ("x".repeat(CONTROL_REPLY_BYTES as usize) + "\n", "UNKNOWN"),
        ] {
            let server = reply_once(&sock, reply).await;
            let Json(body) = command_json(
                control_exchange(
                    sock.to_str().unwrap(),
                    Some(me()),
                    &[me()].into_iter().collect(),
                    "BAN_IP:203.0.113.9\n",
                )
                .await,
            );
            server.await.unwrap();
            assert_eq!(body["outcome"], expected, "{body}");
            assert_eq!(body["success"], expected == "CONFIRMED");
        }
        std::fs::remove_file(&sock).unwrap();
        let Json(body) = command_json(
            control_exchange(sock.to_str().unwrap(), None, &HashSet::new(), "LIST_BANS\n").await,
        );
        assert_eq!(body["outcome"], "NOT_SENT");
        let server = reply_once(&sock, "OK unexpected\n".into()).await;
        let Json(body) = command_json(
            control_exchange(
                sock.to_str().unwrap(),
                Some(me().wrapping_add(1)),
                &HashSet::new(),
                "LIST_BANS\n",
            )
            .await,
        );
        server.await.unwrap();
        assert_eq!(
            body["outcome"], "NOT_SENT",
            "untrusted uid must not receive the command"
        );
        std::fs::remove_file(&sock).unwrap();
        std::fs::write(&sock, "not a socket").unwrap();
        let Json(body) = command_json(
            control_exchange(
                sock.to_str().unwrap(),
                Some(me()),
                &HashSet::new(),
                "LIST_BANS\n",
            )
            .await,
        );
        assert_eq!(
            body["outcome"], "NOT_SENT",
            "a connect error precedes any write"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_written_command_timeout_is_unknown_and_has_a_fixed_deadline() {
        use tokio::io::AsyncBufReadExt;
        // Keep paused time from auto-advancing while the OS completes socket I/O.
        let clock_guard = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        let dir = scratch("timeout");
        let sock = dir.join("ctl.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (written_tx, written_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("the control request never reached the fixture")
                .unwrap();
            let mut reader = tokio::io::BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            written_tx.send(()).unwrap();
            let _ = release_rx.await;
        });
        let path = sock.clone();
        let mut request = tokio::spawn(async move {
            control_exchange(
                path.to_str().unwrap(),
                Some(me()),
                &HashSet::new(),
                "FLUSH_ALL\n",
            )
            .await
        });
        tokio::select! {
            written = written_rx => written.expect("fixture lost the control request"),
            premature = &mut request => panic!("command ended before the fixture read it: {premature:?}"),
        }
        tokio::time::advance(CONTROL_TIMEOUT - Duration::from_millis(1)).await;
        assert!(!request.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        let Json(body) = command_json(request.await.unwrap());
        assert_eq!(body["outcome"], "UNKNOWN");
        assert_eq!(body["error"], "node did not answer within 3 s");
        clock_guard.abort();
        release_tx.send(()).unwrap();
        server.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_silent_node_is_shown_stale() {
        let st = state();
        process_trident_telemetry(&st, me(), "HEARTBEAT:ID=8|NAME=n8|EP=x|MODE=NORMAL\n").await;
        assert_eq!(
            observed_nodes(&st.nodes.read().await)[0].health_status,
            "HEALTHY"
        );
        st.nodes.write().await[0].seen_at =
            std::time::Instant::now().checked_sub(NODE_STALE_AFTER + Duration::from_secs(1));
        let view = observed_nodes(&st.nodes.read().await);
        assert_eq!(view[0].health_status, "STALE");
        assert!(!view[0].xdp_loaded);
    }

    #[tokio::test]
    async fn a_vector_cannot_choose_the_operator_tier_or_supply_header_fields() {
        let st = state();
        process_trident_telemetry(&st, me(),
            "DB_LOG:NODE=7|TIER=Tier2PayloadCapture|VEC=client TIER=Tier1BotTarpit|IP=203.0.113.9\n").await;
        let metrics = st.metrics.read().await;
        assert_eq!(
            metrics.traps.tier1_bot_tarpit, 0,
            "client text must not choose Tier1"
        );
        assert_eq!(metrics.traps.tier2_payload_capture, 1);
        drop(metrics);
        let alerts = st.alerts.read().await;
        assert_eq!(alerts[0].node_id, 7);
        assert_eq!(
            alerts[0].source_ip, "Unknown",
            "IP inside VEC is opaque text"
        );
        assert_eq!(
            alerts[0].attack_vector,
            "client TIER=Tier1BotTarpit|IP=203.0.113.9"
        );
    }

    #[tokio::test]
    async fn operator_tiers_are_exact_fields_and_unknown_tiers_remain_unknown() {
        let st = state();
        for tier in [
            "Tier1BotTarpit",
            "Tier1_5SlowDrip",
            "Tier2PayloadCapture",
            "Tier3InteractiveJail",
        ] {
            process_trident_telemetry(
                &st,
                me(),
                &format!("DB_LOG:NODE=7|TIER={tier}|IP=203.0.113.7|VEC=normal\n"),
            )
            .await;
        }
        for data in [
            "TIER=Tier1BotTarpitSuffix|VEC=unknown",
            "TIER=unknown|VEC=TIER=Tier1BotTarpit",
            "VEC=TIER=Tier1BotTarpit",
        ] {
            process_trident_telemetry(&st, me(), &format!("DB_LOG:NODE=7|{data}\n")).await;
        }
        let metrics = st.metrics.read().await;
        assert_eq!(
            (
                metrics.traps.tier1_bot_tarpit,
                metrics.traps.tier1_5_slow_drip,
                metrics.traps.tier2_payload_capture,
                metrics.traps.tier3_interactive_jail
            ),
            (1, 1, 1, 1)
        );
        let alerts = st.alerts.read().await;
        assert_eq!(alerts.len(), 7, "unknown tier still has a visible alert");
        assert_eq!(alerts.last().unwrap().source_ip, "203.0.113.7");
    }

    #[tokio::test]
    async fn malformed_telemetry_identity_does_not_invent_node_zero_or_one() {
        let st = state();
        for message in [
            "HEARTBEAT:NAME=missing",
            "HEARTBEAT:ID=wrong",
            "HEARTBEAT:ID=4294967296",
            "DB_LOG:TIER=Tier1BotTarpit|VEC=no owner",
            "DB_LOG:NODE=wrong|TIER=Tier1BotTarpit|VEC=no owner",
            "DB_LOG:VEC=client|NODE=7|TIER=Tier1BotTarpit",
        ] {
            process_trident_telemetry(&st, me(), message).await;
        }
        assert!(
            st.nodes.read().await.is_empty(),
            "missing identity is not node zero"
        );
        assert!(
            st.alerts.read().await.is_empty(),
            "missing identity is not node one"
        );
        assert_eq!(st.metrics.read().await.traps.tier1_bot_tarpit, 0);
        process_trident_telemetry(
            &st,
            me(),
            "HEARTBEAT:ID=0|NAME=real-zero\nDB_LOG:NODE=0|TIER=Tier1BotTarpit|VEC=real\n",
        )
        .await;
        assert_eq!(
            st.nodes.read().await[0].id,
            0,
            "an explicit zero is a real identity"
        );
        assert_eq!(st.alerts.read().await[0].node_id, 0);
    }

    #[tokio::test]
    async fn opaque_vectors_survive_the_socket_and_operator_data_api() {
        let st = state();
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let consumer = tokio::spawn({
            let st = st.clone();
            async move { read_telemetry(&st, me(), reader).await }
        });
        writer.write_all(b"DB_LOG:NODE=7|TIER=Tier3InteractiveJail|IP=203.0.113.7|VEC=payload|TIER=Tier1BotTarpit|NODE=99\n").await.unwrap();
        drop(writer);
        consumer.await.unwrap();
        let (status, _, body) = call(
            build_router(st),
            get("/api/data")
                .header(header::AUTHORIZATION, format!("Bearer {}", TOKEN))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["metrics"]["traps"]["tier1_bot_tarpit"], 0);
        assert_eq!(body["metrics"]["traps"]["tier3_interactive_jail"], 1);
        assert_eq!(body["alerts"][0]["node_id"], 7);
        assert_eq!(body["alerts"][0]["source_ip"], "203.0.113.7");
        assert_eq!(
            body["alerts"][0]["attack_vector"],
            "payload|TIER=Tier1BotTarpit|NODE=99"
        );
    }

    /// F11: telemetry is framed by lines, so a heartbeat split across writes is not lost.
    #[tokio::test]
    async fn telemetry_split_across_writes_is_read_whole() {
        let st = state();
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let task = tokio::spawn({
            let st = st.clone();
            async move { read_telemetry(&st, me(), reader).await }
        });
        writer.write_all(b"HEARTBEAT:ID=9|NAME=n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        writer.write_all(b"9|EP=x|MODE=NORMAL\n").await.unwrap();
        drop(writer);
        task.await.unwrap();
        let nodes = st.nodes.read().await;
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "n9");
    }

    #[tokio::test]
    async fn commands_reach_the_node_socket_and_its_reply_decides_the_outcome() {
        let dir = std::env::temp_dir().join(format!("sokol-op-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("ctl.sock");
        let seen = Arc::new(RwLock::new(Vec::new()));
        fake_node(sock.clone(), seen.clone()).await;

        let st = state();
        process_trident_telemetry(
            &st,
            me(),
            &format!(
                "HEARTBEAT:ID=3|NAME=n3|EP=x|MODE=NORMAL|CTL={}\n",
                sock.display()
            ),
        )
        .await;
        let app = build_router(st.clone());
        let ban = |ip: &str| {
            post_json(
                "/api/nodes/3/blacklist",
                serde_json::json!({ "ip": ip, "action": "add" }),
            )
        };

        let (_, _, body) = call(app.clone(), ban("203.0.113.7")).await;
        assert_eq!(body["success"], true, "{}", body);
        assert!(st.nodes.read().await[0].blacklist.contains("203.0.113.7"));

        let (_, _, body) = call(app.clone(), ban("10.0.0.1")).await;
        assert_eq!(body["success"], false);
        assert_eq!(body["error"], "10.0.0.1 is protected (loopback)");
        assert!(!st.nodes.read().await[0].blacklist.contains("10.0.0.1"));

        let flush = axum::http::Request::builder()
            .method("POST")
            .uri("/api/nodes/3/flush")
            .header(header::AUTHORIZATION, format!("Bearer {}", TOKEN))
            .body(Body::empty())
            .unwrap();
        let (_, _, body) = call(app, flush).await;
        assert_eq!(body["success"], true);
        assert!(st.nodes.read().await[0].blacklist.is_empty());
        assert_eq!(
            *seen.read().await,
            vec![
                "BAN_IP:203.0.113.7",
                "LIST_BANS",
                "BAN_IP:10.0.0.1",
                "LIST_BANS",
                "FLUSH_ALL",
                "LIST_BANS"
            ]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn block_targets_are_addresses_only() {
        assert_eq!(
            parse_block_target(" 10.0.0.1 ").as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(
            parse_block_target("2001:db8::/32").as_deref(),
            Some("2001:db8::/32")
        );
        assert_eq!(parse_block_target("10.0.0.1\nFLUSH_BANS"), None);
        assert_eq!(parse_block_target("example.com"), None);
    }

    /// ADR-0005: the operator's answer tells `OK` from `OK …; WARNING: not yet durable`
    /// ("невідоме не видається за успіх"). The node applied the ban but cannot yet say it is
    /// on disk; the operator API must not present that as the same plain success.
    #[tokio::test]
    async fn a_not_yet_durable_confirmation_keeps_its_warning() {
        let dir = scratch("durable");
        let sock = dir.join("ctl.sock");
        let st = state();
        process_trident_telemetry(
            &st,
            me(),
            &format!("HEARTBEAT:ID=5|CTL={}\n", sock.display()),
        )
        .await;
        let node = reply_once(
            &sock,
            "OK banned 203.0.113.9; WARNING: not yet durable (state write pending)\n".into(),
        )
        .await;
        let (_, _, body) = call(
            build_router(st),
            post_json(
                "/api/nodes/5/blacklist",
                serde_json::json!({"ip":"203.0.113.9", "action":"add"}),
            ),
        )
        .await;
        node.await.unwrap();
        assert_eq!(body["outcome"], "CONFIRMED", "{body}");
        assert!(
            body.to_string().contains("not yet durable"),
            "the node's durability warning was dropped from the operator answer: {body}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
