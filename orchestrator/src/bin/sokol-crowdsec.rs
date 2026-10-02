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
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

    /// Seconds after a completed poll before the next poll becomes due.
    #[arg(long, default_value = "5")]
    poll_secs: u64,

    /// Positive nominal IPC pacing rate, in commands/second (not a sliding-window quota).
    #[arg(long, default_value = "200")]
    max_signals_per_sec: NonZeroU32,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Batch {
    /// Ready-to-send `SIGNAL:` lines.
    signals: Vec<String>,
    /// Signal index, rounded source TTL, and its expiry retraction.
    deadlines: std::collections::BTreeMap<usize, (u64, String)>,
    skipped_duration: usize,
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
    // Validate the whole envelope before producing any command or advancing startup.
    // Missing/null sections are valid empty lists; present sections must be arrays
    // of decision objects. Individual decision filters below retain their semantics.
    if !doc.is_object() {
        return Err("bad decision stream: expected an object".into());
    }
    for name in ["new", "deleted"] {
        match doc.get(name) {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(items)) if items.iter().all(|item| item.is_object()) => {}
            _ => {
                return Err(format!(
                    "bad decision stream: {name} must be null or an array of objects"
                ))
            }
        }
    }
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
        // Explicit but expired/invalid durations must not fall back to node escalation.
        // Missing duration retains the legacy SIGNAL policy. Timed events need an id
        // so expiry after a lost ACK can retract the possibly applied signal.
        if decision.get("duration").is_some() {
            let Some(secs) = duration_secs(field("duration")) else {
                batch.skipped_duration += 1;
                continue;
            };
            let Some(id) = decision.get("id").and_then(|v| v.as_u64()) else {
                batch.skipped_duration += 1;
                continue;
            };
            verb.push_str(&format!(";ttl={}", secs));
            batch.deadlines.insert(
                batch.signals.len(),
                (secs, format!("RETRACT#{}:crowdsec|{}", id, ip)),
            );
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
/// has answered it. Returns on transport failure or active backoff so the main loop can poll
/// LAPI again. Yield between commands when the next poll is due. One attempt is
/// allowed even with a zero poll interval, so polling cannot starve delivery.
/// A pending retry is not a successful delivery.
fn deliver(
    outbox: &mut delivery::Outbox,
    socket: &Path,
    pause: Duration,
    poll_finished: Instant,
    poll_interval: Duration,
) {
    let mut attempted = false;
    while outbox.pending() > 0 {
        if attempted && poll_finished.elapsed() >= poll_interval {
            return;
        }
        attempted = true;
        let was_failing = outbox.failing;
        let (done, err) = outbox.flush(1);
        // Backoff reports no completion and no new error. Do not wait it out here:
        // the main loop must keep polling LAPI for new decisions and retractions.
        if done.is_empty() && err.is_none() {
            return;
        }
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

/// Smallest whole-nanosecond interval no shorter than the inverse configured rate.
/// The typed rate cannot be zero; the result is in 1 ns..=1 s, including large rates.
fn signal_pause(rate: NonZeroU32) -> Duration {
    Duration::from_nanos(1_000_000_000u64.div_ceil(u64::from(rate.get())))
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let mut outbox = delivery::Outbox::new(&args.ipc_socket, OUTBOX_CAP);
    // The first successful poll asks for all current decisions, later ones only for changes.
    let mut startup = true;
    let pause = signal_pause(args.max_signals_per_sec);
    log::info!(
        "[sokol-crowdsec] polling {} every {} s (origins: {}), signalling {}",
        args.lapi_url,
        args.poll_secs,
        args.origins.join(","),
        args.ipc_socket.display()
    );

    let poll_interval = Duration::from_secs(args.poll_secs);
    let mut poll_finished = Instant::now();
    let mut first_poll = true;
    loop {
        if first_poll || poll_finished.elapsed() >= poll_interval {
            // Conservative local anchor includes the HTTP round-trip and parsing time.
            let fetched_at = Instant::now();
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
                    if batch.skipped_duration > 0 {
                        log::warn!("[sokol-crowdsec] skipped {} invalid/expired or unidentifiable timed decisions", batch.skipped_duration);
                    }
                    let lost = outbox.lost;
                    for (index, line) in batch.signals.iter().enumerate() {
                        let queued = match batch.deadlines.get(&index) {
                            Some((seconds, expired)) => fetched_at
                                .checked_add(Duration::from_secs(*seconds))
                                .ok_or_else(|| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidInput,
                                        "decision expiry exceeds local clock range",
                                    )
                                })
                                .and_then(|until| outbox.push_with_deadline(line, until, expired)),
                            None => outbox.push(line),
                        };
                        if let Err(error) = queued {
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
                Err(e) => {
                    // The server may have advanced its cursor even when the client did
                    // not obtain a usable batch. Ask for retained full state next time.
                    startup = true;
                    log::warn!(
                        "[sokol-crowdsec] LAPI poll failed: {}; requesting full stream on next poll",
                        e
                    );
                }
            }
            poll_finished = Instant::now();
            first_poll = false;
        }
        deliver(
            &mut outbox,
            &args.ipc_socket,
            pause,
            poll_finished,
            poll_interval,
        );
        // Poll and send clocks are independent: a healthy backlog continues to
        // drain until the poll is due; an empty queue waits for that poll. Retry
        // readiness is private to Outbox, so check backoff at a bounded cadence.
        let until_poll = poll_interval.saturating_sub(poll_finished.elapsed());
        if outbox.pending() == 0 {
            std::thread::sleep(until_poll);
        } else if outbox.failing {
            std::thread::sleep(until_poll.min(Duration::from_millis(50)));
        }
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
    fn cli_rejects_zero_ipc_pacing_before_startup() {
        assert!(
            Args::try_parse_from([
                "sokol-crowdsec",
                "--api-key",
                "dummy-regression-key",
                "--max-signals-per-sec",
                "0",
            ])
            .is_err(),
            "zero pacing must not silently authorize one command per second"
        );
    }

    #[test]
    fn ipc_pacing_interval_does_not_round_below_the_configured_budget() {
        let pause = signal_pause(NonZeroU32::new(3).unwrap());
        assert!(
            pause.as_nanos() * 3 >= 1_000_000_000,
            "three configured pacing intervals must consume at least one second"
        );
    }

    #[test]
    fn cli_pacing_accepts_positive_u32_bounds_and_zero_poll_interval() {
        for value in ["1", "200", "4294967295"] {
            let args = Args::try_parse_from([
                "sokol-crowdsec",
                "--api-key",
                "dummy-regression-key",
                "--max-signals-per-sec",
                value,
                "--poll-secs",
                "0",
            ])
            .unwrap();
            assert_eq!(
                args.max_signals_per_sec.get(),
                value.parse::<u32>().unwrap()
            );
            assert_eq!(
                args.poll_secs, 0,
                "zero poll interval is a separate valid policy"
            );
        }
        let defaults =
            Args::try_parse_from(["sokol-crowdsec", "--api-key", "dummy-regression-key"]).unwrap();
        assert_eq!(defaults.max_signals_per_sec.get(), 200);
        for value in ["0", "00", "-1", "4294967296", "no"] {
            assert!(Args::try_parse_from([
                "sokol-crowdsec",
                "--api-key",
                "dummy-regression-key",
                "--max-signals-per-sec",
                value,
            ])
            .is_err());
        }
    }

    #[test]
    fn ipc_pacing_intervals_are_positive_minimal_integer_budgets() {
        for rate in (1..=10_000u32).chain([500_000_001, 1_000_000_000, 1_000_000_001, u32::MAX]) {
            let pause = signal_pause(NonZeroU32::new(rate).unwrap());
            let nanos = pause.as_nanos();
            let rate = u128::from(rate);
            assert!((1..=1_000_000_000).contains(&nanos));
            assert!(
                nanos * rate >= 1_000_000_000,
                "interval cannot understate inverse rate"
            );
            assert!(
                (nanos - 1) * rate < 1_000_000_000,
                "one nanosecond less is insufficient"
            );
        }
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
    fn explicit_expired_or_invalid_duration_never_becomes_escalated_signal() {
        for duration in [
            serde_json::json!("-1s"),
            serde_json::json!("0s"),
            serde_json::json!("nonsense"),
            serde_json::Value::Null,
            serde_json::json!(10),
        ] {
            let mut body: serde_json::Value = serde_json::from_str(STARTUP).unwrap();
            body["new"][0]["duration"] = duration;
            let batch = batch_from(&body.to_string(), &local()).unwrap();
            assert!(batch.signals.is_empty());
            assert_eq!(batch.skipped_duration, 1);
        }
        let mut body: serde_json::Value = serde_json::from_str(STARTUP).unwrap();
        body["new"][0].as_object_mut().unwrap().remove("id");
        assert!(
            batch_from(&body.to_string(), &local())
                .unwrap()
                .signals
                .is_empty(),
            "timed signals need an id to retract after a lost ACK"
        );
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
    fn stream_shape_errors_are_not_successful_empty_batches() {
        for body in [
            "null",
            "[]",
            "42",
            "true",
            r#""text""#,
            r#"{"new":{}}"#,
            r#"{"deleted":"bad"}"#,
            r#"{"new":[null]}"#,
            r#"{"deleted":[false]}"#,
            r#"{"new":[{},42]}"#,
        ] {
            assert!(
                batch_from(body, &local()).is_err(),
                "accepted invalid stream shape: {body}"
            );
        }
    }

    #[test]
    fn malformed_new_section_cannot_publish_valid_deletions() {
        let mut response: serde_json::Value = serde_json::from_str(STARTUP).unwrap();
        response["deleted"] = response["new"].clone();
        response["new"] = serde_json::json!({"not": "an array"});
        assert!(batch_from(&response.to_string(), &local()).is_err());
    }

    #[test]
    fn optional_null_and_empty_stream_sections_remain_compatible() {
        for body in [
            "{}",
            r#"{"new":null}"#,
            r#"{"deleted":[]}"#,
            r#"{"new":[],"deleted":null,"extra":"ignored"}"#,
        ] {
            assert_eq!(batch_from(body, &local()).unwrap(), Batch::default());
        }
    }

    #[test]
    fn delivery_yields_during_backoff_without_attempting_another_connection() {
        use std::os::unix::net::UnixListener;
        let directory =
            std::env::temp_dir().join(format!("sokol-cs-backoff-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let socket = directory.join("ipc.sock");
        let mut outbox = delivery::Outbox::new(&socket, 4);
        outbox.push("RETRACT#71:crowdsec|203.0.113.71").unwrap();
        // Missing socket starts the real outbox backoff, leaving the command queued.
        assert!(outbox.flush(1).1.is_some());
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        // No fake peer responds: an erroneous retry can finish via the answer timeout.
        deliver(
            &mut outbox,
            &socket,
            Duration::ZERO,
            Instant::now(),
            Duration::from_secs(60),
        );
        let attempted = listener.accept();
        drop(listener);
        std::fs::remove_dir_all(directory).unwrap();
        assert!(
            matches!(attempted, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "delivery must return to the poll loop while the outbox is backing off"
        );
        assert_eq!(outbox.pending(), 1);
        assert!(outbox.failing);
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
