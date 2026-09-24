use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout, Duration};

fn ipc_socket_path() -> String {
    std::env::var("SOKOL_IPC_SOCKET").unwrap_or_else(|_| "/run/sokol.sock".to_string())
}

/// Ports that decoy services listen on. 8080 is left out: local services such as the CrowdSec
/// Local API use it, and a trap there would ban their clients.
const DEFAULT_TRAP_PORTS: [u16; 6] = [22, 80, 443, 3306, 6379, 8443];
/// The XDP program always passes this port as the operator's real SSH (ADMIN_SSH_PORT).
const ADMIN_SSH_PORT: u16 = 2222;
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

pub struct TrapConfig {
    pub ports: Vec<u16>,
    /// External interactive jail to proxy SSH attackers to. None = embedded mock jail.
    pub jail_addr: Option<SocketAddr>,
}

impl TrapConfig {
    /// SOKOL_TRAP_PORTS="22,80,3306" and SOKOL_JAIL_ADDR="127.0.0.1:2022".
    pub fn from_env() -> Result<Self, String> {
        Self::parse(
            std::env::var("SOKOL_TRAP_PORTS").ok().as_deref(),
            std::env::var("SOKOL_JAIL_ADDR").ok().as_deref(),
        )
    }

    fn parse(ports: Option<&str>, jail: Option<&str>) -> Result<Self, String> {
        let ports = match ports {
            None => DEFAULT_TRAP_PORTS.to_vec(),
            Some(list) => list
                .split(',')
                .map(|p| {
                    p.trim()
                        .parse::<u16>()
                        .map_err(|_| format!("invalid trap port '{}'", p.trim()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        if ports.contains(&ADMIN_SSH_PORT) {
            return Err(format!(
                "port {} is the operator SSH port and cannot be a trap",
                ADMIN_SSH_PORT
            ));
        }
        let jail_addr = match jail {
            None | Some("") => None,
            Some(raw) => {
                let addr: SocketAddr = raw
                    .parse()
                    .map_err(|_| format!("invalid SOKOL_JAIL_ADDR '{}'", raw))?;
                // Proxying into the real sshd would hand attackers a login prompt that
                // appears to come from localhost.
                if addr.port() == ADMIN_SSH_PORT {
                    return Err(format!(
                        "SOKOL_JAIL_ADDR must not point at the operator SSH port {}",
                        ADMIN_SSH_PORT
                    ));
                }
                Some(addr)
            }
        };
        Ok(Self { ports, jail_addr })
    }
}

pub struct UltimateTridentOrchestrator {
    config: Arc<TrapConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TridentTier {
    Tier1BotTarpit,
    Tier1_5Revenge,
    Tier2AptSandbox,
    Tier3InteractiveJail,
}

pub struct ConnectionFingerprint {
    pub ip: String,
    pub port: u16,
    pub payload_len: usize,
    pub entropy: f64,
    pub non_printable_ratio: f64,
    pub fingerprint_hash: u64,
    pub snippet: String,
}

impl ConnectionFingerprint {
    pub fn empty(ip: &str, port: u16) -> Self {
        Self {
            ip: ip.to_string(),
            port,
            payload_len: 0,
            entropy: 0.0,
            non_printable_ratio: 0.0,
            fingerprint_hash: 0,
            snippet: String::new(),
        }
    }
}

impl UltimateTridentOrchestrator {
    pub fn new(config: TrapConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] Sokol-Core Trident Node initializing (Single-Writer via Unix Socket)...");
        match self.config.jail_addr {
            Some(addr) => println!("[*] Tier-3 attackers are proxied to external jail {}", addr),
            None => println!("[*] Tier-3 attackers are handled by the embedded mock jail"),
        }

        let mut handles = vec![];
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        for &port in &self.config.ports {
            let config = self.config.clone();
            let permits = permits.clone();
            let addr = format!("0.0.0.0:{}", port);

            let handle = tokio::spawn(async move {
                let listener = match TcpListener::bind(&addr).await {
                    Ok(l) => {
                        println!("[*] Sokol-Core Trident Node armed on port {}", port);
                        l
                    }
                    Err(e) => {
                        eprintln!("[!] Failed to bind port {}: {}", port, e);
                        return;
                    }
                };

                while let Ok((stream, peer_addr)) = listener.accept().await {
                    // Over the limit the connection is simply closed: the trap must not let a
                    // flood exhaust this host's memory or file descriptors.
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let ip = peer_addr.ip().to_canonical().to_string();
                    let config = config.clone();

                    tokio::spawn(async move {
                        let _ = handle_trident_connection(stream, ip, port, &config).await;
                        drop(permit);
                    });
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
}

async fn handle_trident_connection(
    mut stream: TcpStream,
    ip: String,
    port: u16,
    config: &TrapConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 2048];

    let read_result = timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

    let n = match read_result {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            let _ = trigger_xdp_drop(&ip).await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    let payload = &buf[..n];
    let fingerprint = analyze_and_fingerprint(&ip, port, payload);
    let tier = classify_traffic_tier(payload, &fingerprint);

    let unique_log_record = format!(
        "TRIDENT_HIT|TIER={:?}|IP={}|PORT={}|LEN={}|ENTROPY={:.2}|NON_PRINT={:.2}|HASH={:016X}|SNIPPET={}",
        tier,
        fingerprint.ip,
        fingerprint.port,
        fingerprint.payload_len,
        fingerprint.entropy,
        fingerprint.non_printable_ratio,
        fingerprint.fingerprint_hash,
        fingerprint.snippet
    );

    let _ = send_log_to_orchestrator(&unique_log_record).await;

    match tier {
        TridentTier::Tier1BotTarpit => {
            println!(
                "[TIER-1] Bot/Scanner detected from IP: {} on port {} | Hash: {:016X}",
                ip, port, fingerprint.fingerprint_hash
            );
            run_tier1_bot_tarpit(stream, &ip).await?;
        }
        TridentTier::Tier1_5Revenge => {
            println!(
                "[TIER-1.5 REVENGE] Binary garbage flood from IP: {} on port {} | Counter-strike active!",
                ip, port
            );
            run_counter_strike_revenge(stream, &ip, fingerprint.fingerprint_hash).await?;
        }
        TridentTier::Tier2AptSandbox => {
            println!(
                "[TIER-2 APT ALERT] High-value target / Stager detected from IP: {} on port {}! Vacuuming payload...",
                ip, port
            );

            let _ = notify_ebpf_kernel_apt(&ip).await;
            run_tier2_apt_sandbox(stream, payload, &ip).await?;
        }
        TridentTier::Tier3InteractiveJail => {
            println!(
                "[TIER-3 JAIL] SSH interaction detected from IP: {} on port {}! Engaging bait and proxying to Jail...",
                ip, port
            );
            run_tier3_interactive_jail(stream, payload, &ip, config.jail_addr).await?;
        }
    }

    Ok(())
}

fn classify_traffic_tier(payload: &[u8], fp: &ConnectionFingerprint) -> TridentTier {
    if payload.is_empty() {
        return TridentTier::Tier1BotTarpit;
    }

    if payload.starts_with(b"SSH-2.0-") || fp.port == 22 {
        return TridentTier::Tier3InteractiveJail;
    }

    let has_shellcode_patterns = payload
        .windows(4)
        .any(|w| w == b"\x90\x90\x90\x90" || w == b"\x31\xc0\x50\x68" || w == b"\xeb\xfe\x90\x90");

    if has_shellcode_patterns || (fp.non_printable_ratio > 0.6 && payload.len() > 128) {
        return TridentTier::Tier2AptSandbox;
    }

    if fp.non_printable_ratio > 0.4 && payload.len() > 16 {
        return TridentTier::Tier1_5Revenge;
    }

    TridentTier::Tier1BotTarpit
}

fn analyze_and_fingerprint(ip: &str, port: u16, payload: &[u8]) -> ConnectionFingerprint {
    if payload.is_empty() {
        return ConnectionFingerprint::empty(ip, port);
    }

    let payload_len = payload.len();

    let non_printable = payload
        .iter()
        .filter(|&&b| !b.is_ascii_graphic() && !b.is_ascii_whitespace())
        .count();

    let non_printable_ratio = non_printable as f64 / payload_len as f64;
    let entropy = calculate_shannon_entropy(payload);

    let mut hasher = DefaultHasher::new();
    payload.hash(&mut hasher);
    ip.hash(&mut hasher);
    let fingerprint_hash = hasher.finish();

    let snippet = String::from_utf8_lossy(&payload[..payload_len.min(32)])
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect::<String>();

    ConnectionFingerprint {
        ip: ip.to_string(),
        port,
        payload_len,
        entropy,
        non_printable_ratio,
        fingerprint_hash,
        snippet,
    }
}

fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

async fn run_tier1_bot_tarpit(
    mut stream: TcpStream,
    ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = stream
        .write_all(
            b"HTTP/1.1 200 OK\r\n\
        Server: nginx/1.18.0\r\n\
        Content-Type: text/html\r\n\
        Transfer-Encoding: chunked\r\n\r\n",
        )
        .await;

    for i in 0..120 {
        let chunk_data = format!(
            "<div>Diagnostic block ID: {} - Synchronizing state...</div>\n",
            i
        );
        let chunk = format!("{:X}\r\n{}\r\n", chunk_data.len(), chunk_data);
        if stream.write_all(chunk.as_bytes()).await.is_err() {
            break;
        }
        let _ = stream.flush().await;
        sleep(Duration::from_millis(150)).await;
    }
    let _ = stream.write_all(b"0\r\n\r\n").await;
    let _ = trigger_xdp_drop(ip).await;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Binary floods get a slow drip of noise: the connection is held for up to 30 s at 32 bytes
/// per second. Answering with a burst (formerly 1 MiB per connection) spent this host's own
/// uplink on the attacker.
async fn run_counter_strike_revenge(
    mut stream: TcpStream,
    ip: &str,
    seed_hash: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut seed: u64 = seed_hash ^ 0xDEADBEEFCAFEBABE;
    let mut chunk = [0u8; 16];

    for _ in 0..60 {
        for byte in chunk.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = (seed & 0xFF) as u8;
        }
        if stream.write_all(&chunk).await.is_err() {
            break;
        }
        let _ = stream.flush().await;
        sleep(Duration::from_millis(500)).await;
    }

    let _ = trigger_xdp_drop(ip).await;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn run_tier2_apt_sandbox(
    mut stream: TcpStream,
    initial_payload: &[u8],
    ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stager_storage = initial_payload.to_vec();
    let mut buf = vec![0u8; 4096];

    loop {
        let read_res = timeout(Duration::from_secs(8), stream.read(&mut buf)).await;

        match read_res {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                stager_storage.extend_from_slice(&buf[..n]);

                let chunk_log = format!("STAGER_CHUNK|IP={}|BYTES={}", ip, n);
                let _ = send_log_to_orchestrator(&chunk_log).await;

                if stager_storage.len() > 2 * 1024 * 1024 {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }

    println!(
        "[TIER-2] Successfully vacuumed {} bytes of stager payload from APT operator {}.",
        stager_storage.len(),
        ip
    );

    let _ = stream
        .write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        .await;
    let _ = stream.flush().await;

    let _ = trigger_xdp_drop(ip).await;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn run_tier3_interactive_jail(
    mut attacker_stream: TcpStream,
    initial_payload: &[u8],
    ip: &str,
    jail_addr: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let jail = match jail_addr {
        Some(addr) => TcpStream::connect(addr).await.ok(),
        None => None,
    };

    match jail {
        Some(mut jail_stream) => {
            let juicy_bait_banner = b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n";
            if attacker_stream.write_all(juicy_bait_banner).await.is_ok() {
                let _ = attacker_stream.flush().await;

                if !initial_payload.is_empty() {
                    let _ = jail_stream.write_all(initial_payload).await;
                }

                if let Ok((from_attacker, from_jail)) =
                    tokio::io::copy_bidirectional(&mut attacker_stream, &mut jail_stream).await
                {
                    println!(
                        "[TIER-3 JAIL] Session ended for {}. Attacker sent {} bytes, Jail replied with {} bytes.",
                        ip, from_attacker, from_jail
                    );
                    let session_log = format!(
                        "JAIL_SESSION_END|IP={}|IN={}|OUT={}",
                        ip, from_attacker, from_jail
                    );
                    let _ = send_log_to_orchestrator(&session_log).await;
                }
            }
        }
        None => {
            let _ = run_embedded_mock_jail(&mut attacker_stream, initial_payload, ip).await;
        }
    };

    let _ = trigger_xdp_drop(ip).await;
    let _ = attacker_stream.shutdown().await;
    Ok(())
}

async fn run_embedded_mock_jail(
    stream: &mut TcpStream,
    initial_payload: &[u8],
    ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "[TIER-3 EMBEDDED TRAP] External jail offline. Engaging internal Async Mock Jail for IP: {}",
        ip
    );

    if stream
        .write_all(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        .await
        .is_err()
    {
        return Ok(());
    }
    let _ = stream.flush().await;

    let mut buf = vec![0u8; 1024];
    let mut captured_data = initial_payload.to_vec();

    loop {
        let read_res = timeout(Duration::from_secs(8), stream.read(&mut buf)).await;
        match read_res {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                captured_data.extend_from_slice(&buf[..n]);

                let snippet = String::from_utf8_lossy(&buf[..n.min(32)])
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .collect::<String>();

                let chunk_log = format!(
                    "EMBEDDED_JAIL_INPUT|IP={}|BYTES={}|SNIPPET={}",
                    ip, n, snippet
                );
                let _ = send_log_to_orchestrator(&chunk_log).await;

                if stream
                    .write_all(b"Permission denied (publickey,password).\r\nlogin: ")
                    .await
                    .is_err()
                {
                    break;
                }
                let _ = stream.flush().await;

                if captured_data.len() > 1024 * 1024 {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }

    let final_log = format!(
        "EMBEDDED_TRAP_FINALISED|IP={}|TOTAL_CAPTURED={}",
        ip,
        captured_data.len()
    );
    let _ = send_log_to_orchestrator(&final_log).await;
    println!(
        "[TIER-3 EMBEDDED TRAP] Vacuumed {} bytes of interactive input from {}.",
        captured_data.len(),
        ip
    );

    Ok(())
}

async fn send_log_to_orchestrator(
    log_msg: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = ipc_socket_path();
    let msg = format!("DB_LOG:{}\n", log_msg);

    match tokio::net::UnixStream::connect(&socket_path).await {
        Ok(mut socket) => {
            socket.write_all(msg.as_bytes()).await?;
            socket.flush().await?;
            let _ = socket.shutdown().await;
            Ok(())
        }
        Err(e) => {
            eprintln!("[WARN] Failed to write audit log to IPC: {}", e);
            Err(e.into())
        }
    }
}

async fn notify_ebpf_kernel_apt(ip: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = ipc_socket_path();
    let msg = format!("APT_HIGH_PRIORITY:{}\n", ip);

    match tokio::net::UnixStream::connect(&socket_path).await {
        Ok(mut socket) => {
            socket.write_all(msg.as_bytes()).await?;
            socket.flush().await?;
            let _ = socket.shutdown().await;
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "\x1b[1;31m[CRITICAL]\x1b[0m APT Notification failed for IP {}: {}",
                ip, e
            );
            Err(e.into())
        }
    }
}

async fn trigger_xdp_drop(ip: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = ipc_socket_path();
    let msg = format!("DROP_IMMEDIATE:{}\n", ip);
    let max_retries = 3;
    let mut retry_delay = Duration::from_millis(50);

    for attempt in 1..=max_retries {
        match tokio::net::UnixStream::connect(&socket_path).await {
            Ok(mut socket) => {
                if let Err(e) = socket.write_all(msg.as_bytes()).await {
                    eprintln!(
                        "[!] IPC Write Fail (Attempt {}/{}): {}",
                        attempt, max_retries, e
                    );
                } else if let Err(e) = socket.flush().await {
                    eprintln!(
                        "[!] IPC Flush Fail (Attempt {}/{}): {}",
                        attempt, max_retries, e
                    );
                } else {
                    let _ = socket.shutdown().await;
                    println!(
                        "[XDP_ACTION] IP {} sent to IPC orchestrator for XDP drop.",
                        ip
                    );
                    return Ok(());
                }
            }
            Err(e) => {
                eprintln!(
                    "[!] Cannot connect to Unix socket '{}' (Attempt {}/{}): {}",
                    socket_path, attempt, max_retries, e
                );
            }
        }

        if attempt < max_retries {
            sleep(retry_delay).await;
            retry_delay *= 2;
        }
    }

    let err_msg = format!(
        "CRITICAL IPC FAILURE: Failed to deliver DROP_IMMEDIATE for IP {} after {} attempts. Is sokol daemon running?",
        ip, max_retries
    );
    eprintln!("\x1b[1;31m[CRITICAL]\x1b[0m {}", err_msg);

    Err(err_msg.into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("======================================================");
    println!("    SOKOL-CORE: MULTI-PORT ULTIMATE TRIDENT ENGINE    ");
    println!("======================================================");

    let config = match TrapConfig::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("[!] {}", e);
            std::process::exit(1);
        }
    };
    UltimateTridentOrchestrator::new(config).run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_avoid_the_p2p_and_admin_ssh_ports() {
        let config = TrapConfig::parse(None, None).unwrap();
        assert!(
            !config.ports.contains(&8080),
            "8080 is left to local services such as the CrowdSec Local API"
        );
        assert!(!config.ports.contains(&ADMIN_SSH_PORT));
        assert!(
            config.jail_addr.is_none(),
            "no external jail unless configured"
        );
    }

    #[test]
    fn admin_ssh_port_can_be_neither_trap_nor_jail() {
        assert!(TrapConfig::parse(Some("22,2222"), None).is_err());
        assert!(TrapConfig::parse(None, Some("127.0.0.1:2222")).is_err());
        let config = TrapConfig::parse(Some("23, 3389"), Some("127.0.0.1:2022")).unwrap();
        assert_eq!(config.ports, vec![23, 3389]);
        assert_eq!(config.jail_addr, Some("127.0.0.1:2022".parse().unwrap()));
        assert!(TrapConfig::parse(Some("22,http"), None).is_err());
    }
}
