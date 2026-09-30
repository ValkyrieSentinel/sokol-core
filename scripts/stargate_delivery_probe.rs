//! Observable socket traces of the production module; no model implementation here.
#[path = "../orchestrator/src/delivery.rs"]
mod delivery;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

fn main() {
    let cases: &[(&str, &[u8])] = &[
        ("applied", b"OK applied\n"),
        ("pending", b"OK pending\n"),
        ("recorded", b"OK recorded\n"),
        ("duplicate", b"OK duplicate\n"),
        ("refused", b"OK refused protected\n"),
        ("rejected", b"ERR malformed signal\n"),
        ("unknown", b"OK something else\n"),
        ("blank", b"\n"),
        ("err_prefix", b"ERRatic\n"),
        ("refused_prefix", b"OK refusedly\n"),
        ("missing_reason", b"ERR\n"),
        ("partial", b"OK applied"),
        ("eof", b""),
    ];
    let dir = std::env::temp_dir().join(format!("sokol-stargate-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    for (name, reply) in cases {
        let path = dir.join(name);
        let listener = UnixListener::bind(&path).unwrap();
        let reply = reply.to_vec();
        let node = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "ACK");
            stream.write_all(b"OK ack\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "SIGNAL:test|203.0.113.1|-|x");
            stream.write_all(&reply).unwrap();
        });
        let mut out = delivery::Outbox::new(&path, 2);
        out.push("SIGNAL:test|203.0.113.1|-|x");
        let (done, err) = out.flush(1);
        println!(
            "{}\t{}\t{}\t{}\t{}",
            name,
            out.pending(),
            done.len(),
            out.lost,
            err.is_some()
        );
        drop(out);
        node.join().unwrap();
    }
    std::fs::remove_dir_all(dir).unwrap();
}
