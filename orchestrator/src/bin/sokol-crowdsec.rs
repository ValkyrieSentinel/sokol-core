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
//! refuses ones wider than its --min-block-prefix or covering protected addresses.
//!
//! ADR-0019:
//! - A decision's `duration` is sent as `;ttl=<seconds>`: the block lasts that long, within the
//!   node's `--block-ttl-max`, instead of the node's own escalation.
//! - A decision CrowdSec deletes is sent as `RETRACT#<id>:crowdsec|<target>`. The node lifts
//!   the block only if nothing else holds it (e.g. a Suricata alert on the same address).

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
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;

#[path = "../delivery.rs"]
mod delivery;

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
    /// Deletions sent as retractions.
    deleted: usize,
    /// Deletions of decisions this adapter never forwards (other origin, type or scope, no id).
    deleted_skipped: usize,
}

enum Skip {
    Origin,
    NotBan,
    Scope,
}

/// The address or prefix a decision is about, if this adapter forwards it.
fn decision_target(decision: &serde_json::Value, origins: &[String]) -> Result<String, Skip> {
    let field = |k: &str| decision.get(k).and_then(|v| v.as_str()).unwrap_or("");
    if !origins
        .iter()
        .any(|o| o.eq_ignore_ascii_case(field("origin")))
    {
        return Err(Skip::Origin);
    }
    if !field("type").eq_ignore_ascii_case("ban") {
        return Err(Skip::NotBan);
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
    // Other scopes (country, AS) have no address to block.
    target.ok_or(Skip::Scope)
}

/// A Go duration (`3h59m59.38s`, `90s`, `1h`) in whole seconds, rounded up; `None` if it is
/// not one or is not positive (an expired decision).
fn duration_secs(d: &str) -> Option<u64> {
    let (mut total, mut num) = (0f64, String::new());
    let mut rest = d.trim();
    if rest.is_empty() || rest.starts_with('-') {
        return None;
    }
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        num.clear();
        num.push_str(rest.get(..digits)?);
        rest = rest.get(digits..)?;
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let unit = rest.get(..unit_len)?;
        rest = rest.get(unit_len..)?;
        let scale = match unit {
            "h" => 3600.0,
            "m" => 60.0,
            "s" => 1.0,
            "ms" => 1e-3,
            "us" | "µs" => 1e-6,
            "ns" => 1e-9,
            _ => return None,
        };
        total += num.parse::<f64>().ok()? * scale;
    }
    let secs = total.ceil();
    (secs >= 1.0 && secs < u64::MAX as f64).then_some(secs as u64)
}

/// Decisions from one `/v1/decisions/stream` response.
fn batch_from(body: &str, origins: &[String]) -> Result<Batch, String> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("bad JSON: {}", e))?;
    let mut batch = Batch::default();
    // Deletions first: a decision deleted and re-added between two polls ends up blocked.
    for decision in doc
        .get("deleted")
        .and_then(|d| d.as_array())
        .into_iter()
        .flatten()
    {
        match (
            decision_target(decision, origins),
            decision.get("id").and_then(|v| v.as_u64()),
        ) {
            (Ok(target), Some(id)) => {
                batch.deleted += 1;
                batch
                    .signals
                    .push(format!("RETRACT#{}:crowdsec|{}\n", id, target));
            }
            _ => batch.deleted_skipped += 1,
        }
    }
    let Some(new) = doc.get("new").and_then(|n| n.as_array()) else {
        return Ok(batch);
    };
    for decision in new {
        let field = |k: &str| decision.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let ip = match decision_target(decision, origins) {
            Ok(ip) => ip,
            Err(Skip::Origin) => {
                batch.skipped_origin += 1;
                continue;
            }
            Err(Skip::NotBan) => {
                batch.skipped_not_ban += 1;
                continue;
            }
            Err(Skip::Scope) => {
                batch.skipped_scope += 1;
                continue;
            }
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
        // The decision id names the event: a decision replayed by `startup=true` after an
        // adapter restart, or resent after a lost ACK, adds no strike on the node.
        let mut verb = match decision.get("id").and_then(|v| v.as_u64()) {
            Some(id) => format!("SIGNAL#{}", id),
            None => "SIGNAL".to_string(),
        };
        // ADR-0019 T2: CrowdSec's duration is the block's, within the node's ceiling.
        if let Some(secs) = duration_secs(field("duration")) {
            verb.push_str(&format!(";ttl={}", secs));
        }
        batch
            .signals
            .push(format!("{}:crowdsec|{}|-|{}\n", verb, ip, reason));
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

/// Decisions kept while the node cannot be reached.
const OUTBOX_CAP: usize = 100_000;

/// Sends what is queued at `pause` per signal; a decision leaves the queue only when the node
/// has answered it. Stops at the first transport failure (retried on the next round).
fn deliver(outbox: &mut delivery::Outbox, socket: &Path, pause: Duration) {
    while outbox.pending() > 0 {
        let was_failing = outbox.failing;
        let (done, err) = outbox.flush(1);
        for (line, outcome) in done {
            match outcome {
                delivery::Outcome::Refused(why) => {
                    log::warn!("[sokol-crowdsec] {}: refused by the node: {}", line, why)
                }
                delivery::Outcome::Rejected(why) => {
                    log::error!("[sokol-crowdsec] {}: rejected by the node: {}", line, why)
                }
                ok => log::info!("[sokol-crowdsec] {} ({:?})", line, ok),
            }
        }
        if let Some(e) = err {
            if !was_failing {
                log::error!(
                    "[sokol-crowdsec] cannot deliver to {}: {}; {} decisions queued, retrying",
                    socket.display(),
                    e,
                    outbox.pending()
                );
            }
            return;
        }
        std::thread::sleep(pause);
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let mut outbox = delivery::Outbox::new(&args.ipc_socket, OUTBOX_CAP);
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
                if batch.deleted + batch.deleted_skipped > 0 {
                    log::info!(
                        "[sokol-crowdsec] {} deleted decisions parsed as retractions, {} not forwarded ones skipped",
                        batch.deleted,
                        batch.deleted_skipped
                    );
                }
                // Queued, not yet delivered: the outbox keeps them until the node answers, so a
                // batch fetched while the node is down is not lost.
                let lost = outbox.lost;
                for line in &batch.signals {
                    if let Err(error) = outbox.push(line) {
                        log::warn!(
                            "[sokol-crowdsec] decision rejected before queueing: {}",
                            error
                        );
                    }
                }
                if outbox.lost > lost {
                    log::error!(
                        "[sokol-crowdsec] outbox full: {} oldest decisions dropped",
                        outbox.lost - lost
                    );
                }
            }
            Err(e) => log::warn!("[sokol-crowdsec] LAPI poll failed: {}", e),
        }
        deliver(&mut outbox, &args.ipc_socket, pause);
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
            vec!["SIGNAL#1;ttl=14400:crowdsec|203.0.113.9|-|test ban (origin cscli, crowdsec duration 3h59m59.382698294s)\n"]
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
        assert_eq!(
            batch.deleted, 0,
            "a deletion without origin and id is not ours"
        );
        assert_eq!(batch.deleted_skipped, 1);
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
    fn a_deleted_decision_becomes_a_retraction() {
        let body = r#"{"deleted":[
            {"id":7,"origin":"cscli","type":"ban","scope":"Ip","value":"203.0.113.9","duration":"-2s"},
            {"id":8,"origin":"CAPI","type":"ban","scope":"Ip","value":"203.0.113.10"},
            {"id":9,"origin":"crowdsec","type":"ban","scope":"Range","value":"198.51.100.0/24"}
        ],"new":[{"id":10,"origin":"cscli","type":"ban","scope":"Ip","value":"203.0.113.9","duration":"5m","scenario":"again"}]}"#;
        let batch = batch_from(body, &local()).unwrap();
        assert_eq!(
            batch.signals,
            vec![
                "RETRACT#7:crowdsec|203.0.113.9\n".to_string(),
                "RETRACT#9:crowdsec|198.51.100.0/24\n".to_string(),
                "SIGNAL#10;ttl=300:crowdsec|203.0.113.9|-|again (origin cscli, crowdsec duration 5m)\n"
                    .to_string(),
            ],
            "retractions first, then the new decision; a community one is not ours"
        );
        assert_eq!((batch.deleted, batch.deleted_skipped), (2, 1));
    }

    #[test]
    fn go_durations_become_whole_seconds() {
        assert_eq!(duration_secs("3h59m59.382698294s"), Some(14400));
        assert_eq!(duration_secs("90s"), Some(90));
        assert_eq!(duration_secs("1h"), Some(3600));
        assert_eq!(duration_secs("1m0.5s"), Some(61));
        assert_eq!(duration_secs("500ms"), Some(1));
        assert_eq!(duration_secs("-2s"), None, "expired");
        assert_eq!(duration_secs("0s"), None);
        assert_eq!(duration_secs(""), None);
        assert_eq!(duration_secs("4 hours"), None);
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
