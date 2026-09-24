use axum::{
    extract::{Json, Path, State},
    response::{
        sse::{Event, KeepAlive},
        Html, Sse,
    },
    routing::{get, post},
    Router,
};
use chrono::Utc;
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    convert::Infallible,
    path::Path as StdPath,
    sync::Arc,
    time::Duration,
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
    tier1_5_revenge: u64,
    tier2_apt_sandbox: u64,
    tier3_interactive_jail: u64,
    total_bytes_vacuumed: u64,
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
}

#[derive(Deserialize)]
struct BlacklistReq {
    ip: String,
    action: String,
}

#[derive(Deserialize)]
struct MeshCommandReq {
    command: String,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("[*] Запуск SOKOL-CORE Operations & Control Center...");

    let state = AppState {
        nodes: Arc::new(RwLock::new(Vec::new())),
        alerts: Arc::new(RwLock::new(Vec::new())),
        metrics: Arc::new(RwLock::new(SystemMetrics::default())),
    };

    let state_clone = state.clone();
    tokio::spawn(async move {
        let socket_path = "/run/sokol_telemetry.sock";
        if StdPath::new(socket_path).exists() {
            let _ = std::fs::remove_file(socket_path);
        }

        if let Ok(listener) = UnixListener::bind(socket_path) {
            log::info!("[*] Global Trident Telemetry Unix Socket active on {}", socket_path);
            while let Ok((mut stream, _)) = listener.accept().await {
                let state_inner = state_clone.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    if let Ok(n) = stream.read(&mut buf).await {
                        if n > 0 {
                            let msg = String::from_utf8_lossy(&buf[..n]);
                            process_trident_telemetry(&state_inner, &msg).await;
                        }
                    }
                });
            }
        } else {
            log::error!("[!] Не вдалося створити телеметричний сокет: {}", socket_path);
        }
    });

    let app = Router::new()
        .route("/", get(dashboard_handler))
        .route("/api/data", get(api_get_all_data))
        .route("/api/nodes/:id/blacklist", post(api_update_blacklist))
        .route("/api/nodes/:id/flush", post(api_flush_blacklist))
        .route("/api/nodes/:id/toggle-xdp", post(api_toggle_xdp))
        .route("/api/nodes/:id/shield", post(api_toggle_shield))
        .route("/api/mesh/broadcast", post(api_broadcast_command))
        .route("/metrics/stream", get(metrics_stream))
        .with_state(state);

    let bind_addr = std::env::var("SOKOL_OPERATOR_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let listener = TcpListener::bind(&bind_addr).await.unwrap();
    log::info!("[*] Command Center operational at http://{}", bind_addr);
    axum::serve(listener, app).await.unwrap();
}

async fn process_trident_telemetry(state: &AppState, raw_msg: &str) {
    let mut metrics = state.metrics.write().await;
    let mut alerts = state.alerts.write().await;
    let mut nodes = state.nodes.write().await;

    for line in raw_msg.lines() {
        if let Some(data) = line.strip_prefix("HEARTBEAT:") {
            let id = extract_value(data, "ID=").unwrap_or("0".into()).parse::<u32>().unwrap_or(0);
            if !nodes.iter().any(|n| n.id == id) {
                nodes.push(ClientNode {
                    id,
                    name: extract_value(data, "NAME=").unwrap_or(format!("Node-{}", id)),
                    endpoint: extract_value(data, "EP=").unwrap_or("Unknown".into()),
                    control_socket: format!("/run/sokol_node_{}.sock", id),
                    health_status: "HEALTHY".into(),
                    last_seen: Utc::now().format("%H:%M:%S").to_string(),
                    xdp_loaded: true,
                    defense_mode: extract_value(data, "MODE=").unwrap_or("NORMAL".into()),
                    packets_dropped: 0,
                    blacklist: HashSet::new(),
                });
                metrics.p2p_active_peers = nodes.len() as u32;
            } else if let Some(node) = nodes.iter_mut().find(|n| n.id == id) {
                node.last_seen = Utc::now().format("%H:%M:%S").to_string();
            }
        } else if let Some(data) = line.strip_prefix("DB_LOG:") {
            let node_id = extract_value(data, "NODE=").unwrap_or("1".into()).parse::<u32>().unwrap_or(1);

            if data.contains("TIER=Tier1BotTarpit") {
                metrics.traps.tier1_bot_tarpit += 1;
            } else if data.contains("TIER=Tier1_5Revenge") {
                metrics.traps.tier1_5_revenge += 1;
            } else if data.contains("TIER=Tier2AptSandbox") {
                metrics.traps.tier2_apt_sandbox += 1;
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
                    attack_vector: extract_value(data, "VEC=").unwrap_or_else(|| "Unknown Anomaly".into()),
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
    s.split('|').find(|p| p.starts_with(key)).map(|p| p[key.len()..].to_string())
}

async fn dashboard_handler() -> Html<&'static str> {
    Html(HTML_DASHBOARD)
}

async fn api_get_all_data(State(state): State<AppState>) -> Json<serde_json::Value> {
    let nodes = state.nodes.read().await;
    let alerts = state.alerts.read().await;
    let metrics = state.metrics.read().await;

    Json(serde_json::json!({
        "nodes": *nodes,
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
    let mut nodes = state.nodes.write().await;
    if let Some(node) = nodes.iter_mut().find(|n| n.id == id) {
        let cmd = if req.action == "add" {
            node.blacklist.insert(req.ip.clone());
            format!("BAN_IP:{}\n", req.ip)
        } else {
            node.blacklist.remove(&req.ip);
            format!("UNBAN_IP:{}\n", req.ip)
        };
        let _ = send_command_to_node(&node.control_socket, &cmd).await;
        Json(serde_json::json!({ "success": true }))
    } else {
        Json(serde_json::json!({ "success": false }))
    }
}

async fn api_flush_blacklist(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> Json<serde_json::Value> {
    let mut nodes = state.nodes.write().await;
    if let Some(node) = nodes.iter_mut().find(|n| n.id == id) {
        node.blacklist.clear();
        let _ = send_command_to_node(&node.control_socket, "FLUSH_BANS\n").await;
        Json(serde_json::json!({ "success": true }))
    } else {
        Json(serde_json::json!({ "success": false }))
    }
}

async fn api_toggle_xdp(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> Json<serde_json::Value> {
    let mut nodes = state.nodes.write().await;
    if let Some(node) = nodes.iter_mut().find(|n| n.id == id) {
        node.xdp_loaded = !node.xdp_loaded;
        let cmd = if node.xdp_loaded {
            "XDP_LOAD\n"
        } else {
            "XDP_UNLOAD\n"
        };
        let res = send_command_to_node(&node.control_socket, cmd).await;
        Json(serde_json::json!({ "success": res.is_ok() }))
    } else {
        Json(serde_json::json!({ "success": false }))
    }
}

async fn api_toggle_shield(
    State(state): State<AppState>,
    Path(id): Path<u32>,
) -> Json<serde_json::Value> {
    let mut nodes = state.nodes.write().await;
    if let Some(node) = nodes.iter_mut().find(|n| n.id == id) {
        node.defense_mode = if node.defense_mode == "NORMAL" {
            "MAX_SHIELD".into()
        } else {
            "NORMAL".into()
        };
        let cmd = format!("SET_DEFENSE:{}\n", node.defense_mode);
        let _ = send_command_to_node(&node.control_socket, &cmd).await;
        Json(serde_json::json!({ "success": true }))
    } else {
        Json(serde_json::json!({ "success": false }))
    }
}

async fn api_broadcast_command(
    State(_state): State<AppState>,
    Json(req): Json<MeshCommandReq>,
) -> Json<serde_json::Value> {
    log::info!("[P2P MESH] Broadcasting command across active nodes: {}", req.command);
    let p2p_socket = "/run/sokol_p2p.sock";
    let status = send_command_to_node(p2p_socket, &format!("BROADCAST:{}\n", req.command)).await.is_ok();
    Json(serde_json::json!({ "success": status, "command": req.command }))
}

async fn send_command_to_node(socket_path: &str, cmd: &str) -> Result<(), Box<dyn std::error::Error>> {
    if StdPath::new(socket_path).exists() {
        let mut socket = UnixStream::connect(socket_path).await?;
        socket.write_all(cmd.as_bytes()).await?;
        socket.flush().await?;
    } else {
        log::warn!("[!] Socket missing for command routing: {}", socket_path);
    }
    Ok(())
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
                    <p class="text-[10px] text-zinc-500">Trident Engine v2.5</p>
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
                    <div class="text-[10px] text-zinc-500">TRAP TIER-1.5 (REVENGE)</div>
                    <div id="trap-t15" class="text-xl font-bold text-amber-400">0</div>
                </div>
                <div class="text-right text-[10px] text-zinc-500">Floods</div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex items-center justify-between">
                <div>
                    <div class="text-[10px] text-zinc-500">TRAP TIER-2 (APT SANDBOX)</div>
                    <div id="trap-t2" class="text-xl font-bold text-purple-400">0</div>
                </div>
                <div class="text-right text-[10px] text-zinc-500">Stagers</div>
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
                    <div class="text-[10px] text-zinc-500">SNTL_DB STORAGE (ZIG)</div>
                    <div class="font-bold text-zinc-100">Latency: <span id="m-dblat" class="text-amber-400">0 ms</span> | Banned IPs: <span id="trap-banned" class="text-red-400">0</span></div>
                </div>
            </div>
            <div class="bg-zinc-900 border border-zinc-800 p-4 rounded-xl flex flex-col justify-center">
                <div class="text-[10px] text-zinc-500 mb-1">GLOBAL MESH COMMANDS</div>
                <div class="flex gap-2">
                    <select id="p2p-cmd" class="bg-zinc-950 border border-zinc-700 rounded px-2 py-1 text-xs w-full">
                        <option value="SYNC_DAG">Force DAG Sync</option>
                        <option value="RELOAD_RULES">Reload Security Rules</option>
                        <option value="FLUSH_ALL_BANS">Flush All Swarm Bans</option>
                    </select>
                    <button onclick="broadcastCommand()" class="bg-cyan-900/50 hover:bg-cyan-800 border border-cyan-700 text-cyan-300 px-3 py-1 rounded text-xs font-bold transition">SEND</button>
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

        async function fetchData() {
            try {
                const res = await fetch('/api/data');
                const data = await res.json();
                
                document.getElementById('m-peers').innerText = data.metrics.p2p_active_peers;
                document.getElementById('m-dag').innerText = data.metrics.dag_tips;
                document.getElementById('m-dblat').innerText = data.metrics.db_latency_ms.toFixed(1) + ' ms';
                
                document.getElementById('trap-t1').innerText = data.metrics.traps.tier1_bot_tarpit;
                document.getElementById('trap-t15').innerText = data.metrics.traps.tier1_5_revenge;
                document.getElementById('trap-t2').innerText = data.metrics.traps.tier2_apt_sandbox;
                document.getElementById('trap-t3').innerText = data.metrics.traps.tier3_interactive_jail;
                document.getElementById('trap-banned').innerText = data.metrics.traps.active_banned_ips;

                if (data.nodes.length > 0) {
                    document.getElementById('nodes-container').innerHTML = data.nodes.map(n => `
                        <div class="bg-zinc-950 border border-zinc-800 rounded-lg p-3">
                            <div class="flex justify-between items-start mb-2">
                                <div>
                                    <div class="font-bold text-emerald-400">${n.name}</div>
                                    <div class="text-[10px] text-zinc-500">${n.endpoint}</div>
                                </div>
                                <div class="flex flex-col gap-1 text-right">
                                    <span class="text-[9px] px-1.5 py-0.5 rounded ${n.xdp_loaded ? 'bg-emerald-900/30 text-emerald-500 border border-emerald-900' : 'bg-red-900/30 text-red-500 border border-red-900'}">${n.xdp_loaded ? 'XDP: ON' : 'XDP: OFF'}</span>
                                    <span class="text-[9px] px-1.5 py-0.5 rounded ${n.defense_mode === 'MAX_SHIELD' ? 'bg-amber-900/30 text-amber-500 border border-amber-900' : 'bg-zinc-800 text-zinc-400 border border-zinc-700'}">${n.defense_mode}</span>
                                </div>
                            </div>
                            
                            <div class="mb-3 space-y-1">
                                <div class="text-[10px] text-zinc-400 flex justify-between">
                                    <span>Blacklist: ${n.blacklist.length} IPs</span>
                                    <button onclick="apiCall('/api/nodes/${n.id}/flush')" class="text-red-400 hover:text-red-300">Flush</button>
                                </div>
                                <div class="flex flex-wrap gap-1">
                                    ${Array.from(n.blacklist).map(ip => `<span class="bg-zinc-900 border border-zinc-800 text-[10px] px-1.5 py-0.5 rounded flex items-center gap-1">${ip} <button onclick="modifyBlacklist(${n.id}, '${ip}', 'remove')" class="text-red-500 hover:text-red-400">×</button></span>`).join('')}
                                </div>
                            </div>

                            <div class="flex gap-1 mb-2">
                                <input type="text" id="ip-in-${n.id}" placeholder="IP to ban..." class="bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs w-full outline-none focus:border-amber-500">
                                <button onclick="addIp(${n.id})" class="bg-red-950 border border-red-900 hover:bg-red-900 text-red-300 px-2 rounded text-xs">Ban</button>
                            </div>
                            
                            <div class="grid grid-cols-2 gap-1 mt-2 pt-2 border-t border-zinc-900">
                                <button onclick="apiCall('/api/nodes/${n.id}/toggle-xdp')" class="bg-zinc-900 hover:bg-zinc-800 text-zinc-300 py-1 rounded text-xs transition">Toggle XDP</button>
                                <button onclick="apiCall('/api/nodes/${n.id}/shield')" class="bg-amber-950/50 hover:bg-amber-900/50 text-amber-500 border border-amber-900/50 py-1 rounded text-xs transition">Shield Mode</button>
                            </div>
                        </div>
                    `).join('');
                }

                if (data.alerts.length > 0) {
                    document.getElementById('alerts-table').innerHTML = data.alerts.map(a => `
                        <tr class="hover:bg-zinc-900 transition border-b border-zinc-900/50">
                            <td class="p-2 whitespace-nowrap">${a.timestamp}</td>
                            <td class="p-2 text-cyan-400">#${a.node_id}</td>
                            <td class="p-2 font-bold text-red-400">${a.source_ip}</td>
                            <td class="p-2 text-amber-500 truncate max-w-xs" title="${a.attack_vector}">${a.attack_vector}</td>
                            <td class="p-2 text-emerald-400">${a.mitigation}</td>
                        </tr>
                    `).join('');
                }
            } catch (e) { console.error(e); }
        }

        function initSSE() {
            const evtSource = new EventSource("/metrics/stream");
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
            await fetch(endpoint, { method: 'POST' });
            fetchData();
        }

        async function modifyBlacklist(id, ip, action) {
            await fetch(`/api/nodes/${id}/blacklist`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, action })
            });
            fetchData();
        }

        async function addIp(id) {
            const input = document.getElementById(`ip-in-${id}`);
            if (input.value) { await modifyBlacklist(id, input.value, 'add'); input.value = ''; }
        }

        async function broadcastCommand() {
            const cmd = document.getElementById('p2p-cmd').value;
            await fetch('/api/mesh/broadcast', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: cmd })
            });
            console.log(`Command ${cmd} dispatched to P2P Daemon`);
        }

        fetchData(); setInterval(fetchData, 3000); initSSE();
    </script>
</body>
</html>
"###;