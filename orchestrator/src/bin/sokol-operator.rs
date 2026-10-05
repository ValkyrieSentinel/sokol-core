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
    /// uid of the process that first announced this node; its heartbeats (and control socket)
    /// must keep coming from it.
    #[serde(skip)]
    uid: u32,
    /// When its last heartbeat arrived; the view marks the node STALE after NODE_STALE_AFTER.
    #[serde(skip)]
    seen_at: Option<std::time::Instant>,
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

fn result_json(res: Result<(), String>) -> Json<serde_json::Value> {
    match res {
        Ok(()) => Json(serde_json::json!({ "success": true })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })),
    }
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
            let id = extract_value(data, "ID=")
                .unwrap_or("0".into())
                .parse::<u32>()
                .unwrap_or(0);
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
                    node.control_socket = ctl;
                }
            }
        } else if let Some(data) = line.strip_prefix("DB_LOG:") {
            let node_id = extract_value(data, "NODE=")
                .unwrap_or("1".into())
                .parse::<u32>()
                .unwrap_or(1);

            if data.contains("TIER=Tier1BotTarpit") {
                metrics.traps.tier1_bot_tarpit += 1;
            } else if data.contains("TIER=Tier1_5SlowDrip") {
                metrics.traps.tier1_5_slow_drip += 1;
            } else if data.contains("TIER=Tier2PayloadCapture") {
                metrics.traps.tier2_payload_capture += 1;
            } else if data.contains("TIER=Tier3InteractiveJail") {
                metrics.traps.tier3_interactive_jail += 1;
            }

            let new_id = alerts.len() as u64 + 1;
            alerts.insert(
                0,
                SecurityAlert {
                    id: new_id,
                    timestamp: Utc::now().format("%H:%M:%S").to_string(),
                    node_id,
                    source_ip: extract_value(data, "IP=").unwrap_or_else(|| "Unknown".into()),
                    attack_vector: extract_value(data, "VEC=")
                        .unwrap_or_else(|| "Unknown Anomaly".into()),
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
            if n.seen_at.is_none_or(|t| t.elapsed() > NODE_STALE_AFTER) {
                n.health_status = "STALE".into();
                n.xdp_loaded = false;
            }
            n
        })
        .collect()
}

async fn api_get_all_data(State(state): State<AppState>) -> Json<serde_json::Value> {
    let nodes = observed_nodes(&state.nodes.read().await);
    let alerts = state.alerts.read().await;
    let metrics = state.metrics.read().await;

    Json(serde_json::json!({
        "nodes": nodes,
        "alerts": *alerts,
        "metrics": *metrics,
        "timestamp": Utc::now().to_rfc3339()
    }))
}

async fn api_update_blacklist(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(req): Json<BlacklistReq>,
) -> Json<serde_json::Value> {
    let Some(target) = parse_block_target(&req.ip) else {
        return result_json(Err(format!(
            "'{}' is not an IP address or CIDR",
            req.ip.trim()
        )));
    };
    let adding = match req.action.as_str() {
        "add" => true,
        "remove" => false,
        other => return result_json(Err(format!("unknown action '{}'", other))),
    };
    let Some((ctl, uid)) = route(&state, id).await else {
        return result_json(Err(format!("unknown node {}", id)));
    };
    let cmd = if adding {
        format!("BAN_IP:{}\n", target)
    } else {
        format!("UNBAN_IP:{}\n", target)
    };
    let res = send_command_to_node(&ctl, Some(uid), &state.node_uids, &cmd).await;
    refresh_bans(&state, id).await;
    result_json(res)
}

async fn api_flush_blacklist(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> Json<serde_json::Value> {
    let Some((ctl, uid)) = route(&state, id).await else {
        return result_json(Err(format!("unknown node {}", id)));
    };
    // One command on the node: operator bans and dynamic blocks, whatever this dashboard knew.
    let res = send_command_to_node(&ctl, Some(uid), &state.node_uids, "FLUSH_ALL\n").await;
    refresh_bans(&state, id).await;
    result_json(res)
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
async fn refresh_bans(state: &AppState, id: u32) {
    let Some((ctl, uid)) = route(state, id).await else {
        return;
    };
    match query_node(&ctl, Some(uid), &state.node_uids, "LIST_BANS\n").await {
        Ok(reply) => {
            let bans: HashSet<String> =
                reply.split_whitespace().skip(1).map(String::from).collect();
            if let Some(node) = state.nodes.write().await.iter_mut().find(|n| n.id == id) {
                node.blacklist = bans;
            }
        }
        Err(e) => log::warn!("[!] Cannot read bans of node {}: {}", id, e),
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

/// Sends one command to the node's control socket (announced as CTL= in its heartbeat) and
/// returns its reply. The node answers "OK ..." or "ERR ..."; anything else is a failure.
/// The control socket must be served by `node_uid` (the uid the node announced itself from) or,
/// for sockets not tied to a node, by one of `allowed`: a socket path learned from telemetry is
/// not trusted on its own.
async fn send_command_to_node(
    socket_path: &str,
    node_uid: Option<u32>,
    allowed: &HashSet<u32>,
    cmd: &str,
) -> Result<(), String> {
    query_node(socket_path, node_uid, allowed, cmd)
        .await
        .map(|_| ())
}

/// Like [`send_command_to_node`], returning the text after "OK".
async fn query_node(
    socket_path: &str,
    node_uid: Option<u32>,
    allowed: &HashSet<u32>,
    cmd: &str,
) -> Result<String, String> {
    use tokio::io::AsyncBufReadExt;
    if !StdPath::new(socket_path).exists() {
        log::warn!("[!] Socket missing for command routing: {}", socket_path);
        return Err(format!(
            "node control socket {} is not available",
            socket_path
        ));
    }
    let exchange = async {
        let mut socket = UnixStream::connect(socket_path)
            .await
            .map_err(|e| e.to_string())?;
        let served_by = socket.peer_cred().map_err(|e| e.to_string())?.uid();
        let trusted = match node_uid {
            Some(uid) => served_by == uid,
            None => allowed.contains(&served_by),
        };
        if !trusted {
            return Err(format!(
                "control socket {} is served by uid {}, not by the node's uid",
                socket_path, served_by
            ));
        }
        socket
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut reply = String::new();
        tokio::io::BufReader::new(&mut socket)
            .read_line(&mut reply)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<String, String>(reply.trim().to_string())
    };
    let reply = tokio::time::timeout(Duration::from_secs(3), exchange)
        .await
        .map_err(|_| "node did not answer within 3 s".to_string())??;
    match reply.strip_prefix("OK") {
        Some(rest) => Ok(rest.trim().to_string()),
        None => Err(reply.strip_prefix("ERR ").unwrap_or(&reply).to_string()),
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
            const token = prompt('Operator token (SOKOL_OPERATOR_TOKEN or the one printed at startup):');
            if (!token) return false;
            const res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
            return res.ok;
        }

        async function authedFetch(url, opts) {
            let res = await fetch(url, opts);
            if (res.status === 401 && await login()) { res = await fetch(url, opts); initSSE(); }
            return res;
        }

        function report(data) {
            if (data && data.success === false) alert('Command failed: ' + (data.error || 'unknown error'));
        }

        async function fetchData() {
            try {
                const res = await authedFetch('/api/data');
                const data = await res.json();
                
                document.getElementById('m-peers').innerText = data.metrics.p2p_active_peers;
                document.getElementById('m-dag').innerText = data.metrics.dag_tips;
                document.getElementById('m-dblat').innerText = data.metrics.db_latency_ms.toFixed(1) + ' ms';
                
                document.getElementById('trap-t1').innerText = data.metrics.traps.tier1_bot_tarpit;
                document.getElementById('trap-t15').innerText = data.metrics.traps.tier1_5_slow_drip;
                document.getElementById('trap-t2').innerText = data.metrics.traps.tier2_payload_capture;
                document.getElementById('trap-t3').innerText = data.metrics.traps.tier3_interactive_jail;
                document.getElementById('trap-banned').innerText = data.metrics.traps.active_banned_ips;

                if (data.nodes.length > 0) {
                    document.getElementById('nodes-container').innerHTML = data.nodes.map(n => `
                        <div class="bg-zinc-950 border border-zinc-800 rounded-lg p-3">
                            <div class="flex justify-between items-start mb-2">
                                <div>
                                    <div class="font-bold text-emerald-400">${esc(n.name)}</div>
                                    <div class="text-[10px] text-zinc-500">${esc(n.endpoint)}</div>
                                </div>
                                <div class="flex flex-col gap-1 text-right">
                                    <span class="text-[9px] px-1.5 py-0.5 rounded ${n.xdp_loaded ? 'bg-emerald-900/30 text-emerald-500 border border-emerald-900' : 'bg-red-900/30 text-red-500 border border-red-900'}">${n.xdp_loaded ? 'XDP: ON' : 'XDP: OFF'}</span>
                                    <span class="text-[9px] px-1.5 py-0.5 rounded ${n.defense_mode === 'MAX_SHIELD' ? 'bg-amber-900/30 text-amber-500 border border-amber-900' : 'bg-zinc-800 text-zinc-400 border border-zinc-700'}">${esc(n.defense_mode)}</span>
                                </div>
                            </div>
                            
                            <div class="mb-3 space-y-1">
                                <div class="text-[10px] text-zinc-400 flex justify-between">
                                    <span>Blacklist: ${n.blacklist.length} IPs</span>
                                    <button onclick="apiCall('/api/nodes/${n.id}/flush')" class="text-red-400 hover:text-red-300">Flush</button>
                                </div>
                                <div class="flex flex-wrap gap-1">
                                    ${Array.from(n.blacklist).map(ip => `<span class="bg-zinc-900 border border-zinc-800 text-[10px] px-1.5 py-0.5 rounded flex items-center gap-1">${esc(ip)} <button data-node="${Number(n.id)}" data-ip="${esc(ip)}" class="unban text-red-500 hover:text-red-400">×</button></span>`).join('')}
                                </div>
                            </div>

                            <div class="flex gap-1 mb-2">
                                <input type="text" id="ip-in-${n.id}" placeholder="IP to ban..." class="bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs w-full outline-none focus:border-amber-500">
                                <button onclick="addIp(${n.id})" class="bg-red-950 border border-red-900 hover:bg-red-900 text-red-300 px-2 rounded text-xs">Ban</button>
                            </div>
                            
                        </div>
                    `).join('');
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
            } catch (e) { console.error(e); }
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
            const res = await authedFetch(endpoint, { method: 'POST' });
            report(await res.json());
            fetchData();
        }

        document.addEventListener('click', e => {
            const btn = e.target.closest('button.unban');
            if (btn) modifyBlacklist(Number(btn.dataset.node), btn.dataset.ip, 'remove');
        });

        async function modifyBlacklist(id, ip, action) {
            const res = await authedFetch(`/api/nodes/${id}/blacklist`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, action })
            });
            report(await res.json());
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
}
