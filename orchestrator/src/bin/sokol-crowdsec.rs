//! CrowdSec → Sokol adapter (a CrowdSec "bouncer").
//!
//! Polls the CrowdSec Local API decision stream and turns `ban` decisions on single addresses
//! into `SIGNAL:` lines on the orchestrator's IPC socket. Sokol then drops the address in XDP on
//! this node and, through the mesh, on every other node.
//!
//! ```text
//! cscli bouncers add sokol            # prints the API key
//! SOKOL_CROWDSEC_KEY=<key> sokol-crowdsec --lapi-url http://127.0.0.1:8080 --ipc-socket /run/sokol/sokol.sock
//! ```
//!
//! By default only local decisions are forwarded (origins `crowdsec` and `cscli`). Community
//! blocklists (`CAPI`, `lists`) can hold tens of thousands of addresses; add them to `--origins`
//! only if the mesh should carry them. Range decisions are forwarded as prefixes; the node
//! refuses ones wider than its --min-block-prefix or covering protected addresses. Decisions
//! CrowdSec deletes are not lifted automatically:
//! Sokol's own TTL ends them, and an operator can lift one early with UNBAN_IP on the control
//! socket.
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(about = "Forward CrowdSec ban decisions to Sokol-Core as block signals")]
struct Args {
    /// CrowdSec Local API.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    lapi_url: String,

    /// Bouncer API key (`cscli bouncers add <name>`).
    #[arg(long, env = "SOKOL_CROWDSEC_KEY", hide_env_values = true)]
    api_key: String,

    /// Orchestrator IPC socket (its --ipc-socket).
    #[arg(long, env = "SOKOL_IPC_SOCKET", default_value = "/run/sokol.sock")]
    ipc_socket: PathBuf,

    /// Decision origins to forward, comma-separated.
    #[arg(long, default_value = "crowdsec,cscli", value_delimiter = ',')]
    origins: Vec<String>,

    /// Seconds between polls of the decision stream.
    #[arg(long, default_value = "5")]
    poll_secs: u64,

    /// Upper bound on signals per second sent to the node.
    #[arg(long, default_value = "200")]
    max_signals_per_sec: u32,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Batch {
    /// Ready-to-send `SIGNAL:` lines.
    signals: Vec<String>,
    skipped_origin: usize,
    skipped_not_ban: usize,
    skipped_scope: usize,
    deleted: usize,
}

/// Decisions from one `/v1/decisions/stream` response.
fn batch_from(body: &str, origins: &[String]) -> Result<Batch, String> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("bad JSON: {}", e))?;
    let mut batch = Batch {
        deleted: doc
            .get("deleted")
            .and_then(|d| d.as_array())
            .map_or(0, |d| d.len()),
        ..Batch::default()
    };
    let Some(new) = doc.get("new").and_then(|n| n.as_array()) else {
        return Ok(batch);
    };
    for decision in new {
        let field = |k: &str| decision.get(k).and_then(|v| v.as_str()).unwrap_or("");
        if !origins
            .iter()
            .any(|o| o.eq_ignore_ascii_case(field("origin")))
        {
            batch.skipped_origin += 1;
            continue;
        }
        if !field("type").eq_ignore_ascii_case("ban") {
            batch.skipped_not_ban += 1;
            continue;
        }
        let value = field("value");
        let target = if field("scope").eq_ignore_ascii_case("ip") {
            value.parse::<IpAddr>().ok().map(|ip| ip.to_string())
        } else if field("scope").eq_ignore_ascii_case("range") {
            value
                .parse::<ipnet::IpNet>()
                .ok()
                .map(|net| net.to_string())
        } else {
            None
        };
        let Some(ip) = target else {
            // Other scopes (country, AS) have no address to block.
            batch.skipped_scope += 1;
            continue;
        };
        let reason: String = format!(
            "{} (origin {}, crowdsec duration {})",
            field("scenario"),
            field("origin"),
            field("duration")
        )
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect();
        batch
            .signals
            .push(format!("SIGNAL:crowdsec|{}|-|{}\n", ip, reason));
    }
    Ok(batch)
}

fn stream_url(base: &str, startup: bool) -> String {
    format!(
        "{}/v1/decisions/stream?startup={}",
        base.trim_end_matches('/'),
        startup
    )
}

fn poll(args: &Args, startup: bool) -> Result<String, String> {
    ureq::get(&stream_url(&args.lapi_url, startup))
        .set("X-Api-Key", &args.api_key)
        .set("User-Agent", "sokol-crowdsec")
        .timeout(Duration::from_secs(10))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())
}

fn send(conn: &mut Option<UnixStream>, socket: &Path, line: &str) -> io::Result<()> {
    for attempt in 0..2 {
        if conn.is_none() {
            *conn = Some(UnixStream::connect(socket)?);
        }
        let stream = conn.as_mut().unwrap();
        match stream
            .write_all(line.as_bytes())
            .and_then(|()| stream.flush())
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                *conn = None;
                if attempt == 1 {
                    return Err(e);
                }
            }
        }
    }
    unreachable!()
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let mut conn: Option<UnixStream> = None;
    // The first successful poll asks for all current decisions, later ones only for changes.
    let mut startup = true;
    let pause = Duration::from_secs_f64(1.0 / f64::from(args.max_signals_per_sec.max(1)));
    log::info!(
        "[sokol-crowdsec] polling {} every {} s (origins: {}), signalling {}",
        args.lapi_url,
        args.poll_secs,
        args.origins.join(","),
        args.ipc_socket.display()
    );

    loop {
        match poll(&args, startup).and_then(|body| batch_from(&body, &args.origins)) {
            Ok(batch) => {
                startup = false;
                if batch.skipped_origin + batch.skipped_not_ban + batch.skipped_scope > 0 {
                    log::info!(
                        "[sokol-crowdsec] skipped {} other-origin, {} non-ban, {} non-address decisions",
                        batch.skipped_origin,
                        batch.skipped_not_ban,
                        batch.skipped_scope
                    );
                }
                if batch.deleted > 0 {
                    log::info!(
                        "[sokol-crowdsec] {} decisions deleted in CrowdSec; Sokol blocks end on their own TTL (lift early with UNBAN_IP)",
                        batch.deleted
                    );
                }
                for line in &batch.signals {
                    match send(&mut conn, &args.ipc_socket, line) {
                        Ok(()) => log::info!("[sokol-crowdsec] {}", line.trim()),
                        Err(e) => log::error!(
                            "[sokol-crowdsec] cannot reach {}: {}",
                            args.ipc_socket.display(),
                            e
                        ),
                    }
                    std::thread::sleep(pause);
                }
            }
            Err(e) => log::warn!("[sokol-crowdsec] LAPI poll failed: {}", e),
        }
        std::thread::sleep(Duration::from_secs(args.poll_secs));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from CrowdSec 1.4.6 after `cscli decisions add --ip 203.0.113.9 --reason "test ban"`.
    const STARTUP: &str = r#"{"deleted":null,"new":[{"duration":"3h59m59.382698294s","id":1,"origin":"cscli","scenario":"test ban","scope":"Ip","type":"ban","value":"203.0.113.9"}]}"#;

    fn local() -> Vec<String> {
        vec!["crowdsec".into(), "cscli".into()]
    }

    #[test]
    fn real_lapi_response_becomes_a_signal() {
        let batch = batch_from(STARTUP, &local()).unwrap();
        assert_eq!(
            batch.signals,
            vec!["SIGNAL:crowdsec|203.0.113.9|-|test ban (origin cscli, crowdsec duration 3h59m59.382698294s)\n"]
        );
        assert_eq!(
            batch_from(r#"{"deleted":null,"new":null}"#, &local()).unwrap(),
            Batch::default()
        );
    }

    #[test]
    fn filters_origin_type_and_scope() {
        let body = r#"{"deleted":[{"value":"198.51.100.1"}],"new":[
            {"origin":"CAPI","type":"ban","scope":"Ip","value":"198.51.100.2","scenario":"community"},
            {"origin":"crowdsec","type":"captcha","scope":"Ip","value":"198.51.100.3","scenario":"http"},
            {"origin":"crowdsec","type":"ban","scope":"Range","value":"198.51.100.0/24","scenario":"x"},
            {"origin":"crowdsec","type":"ban","scope":"Country","value":"XX","scenario":"geo"},
            {"origin":"crowdsec","type":"ban","scope":"Ip","value":"2001:db8::7","scenario":"crowdsecurity/ssh-bf"}
        ]}"#;
        let batch = batch_from(body, &local()).unwrap();
        assert_eq!(batch.skipped_origin, 1);
        assert_eq!(batch.skipped_not_ban, 1);
        assert_eq!(batch.skipped_scope, 1, "country scope has no address");
        assert_eq!(batch.deleted, 1);
        assert_eq!(batch.signals.len(), 2);
        assert!(
            batch.signals[0].starts_with("SIGNAL:crowdsec|198.51.100.0/24|-|x"),
            "ranges become prefixes"
        );
        assert!(batch.signals[1].starts_with("SIGNAL:crowdsec|2001:db8::7|-|crowdsecurity/ssh-bf"));

        let with_capi = batch_from(body, &["crowdsec".into(), "CAPI".into()]).unwrap();
        assert_eq!(
            with_capi.signals.len(),
            3,
            "community decisions only when asked for"
        );
    }

    #[test]
    fn a_scenario_cannot_inject_a_second_line() {
        let body = r#"{"new":[{"origin":"cscli","type":"ban","scope":"Ip","value":"203.0.113.9","scenario":"x\nDROP_IMMEDIATE:1.1.1.1"}]}"#;
        let batch = batch_from(body, &local()).unwrap();
        assert_eq!(batch.signals[0].matches('\n').count(), 1);
        assert!(batch_from("not json", &local()).is_err());
    }

    #[test]
    fn stream_url_marks_startup() {
        assert_eq!(
            stream_url("http://127.0.0.1:8080/", true),
            "http://127.0.0.1:8080/v1/decisions/stream?startup=true"
        );
        assert!(stream_url("http://x", false).ends_with("startup=false"));
    }
}
