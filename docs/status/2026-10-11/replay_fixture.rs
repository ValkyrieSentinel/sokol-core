use common::audit_log::{AuditLog, Rotation, SEGMENT_HEADER_LEN, HEADER_LEN, CHAIN_LEN};
fn main() {
 if let Some(count) = std::env::args().nth(1) {
    let count: usize = count.parse().unwrap();
    let path = std::path::Path::new("/tmp/sokol-replay-race/large.sntl");
    let _ = std::fs::remove_file(path);
    let mut log = AuditLog::open(path).unwrap();
    let ctx = "Build:local-upgrade|Node:1|TtlBase:60|TtlMax:600";
    let digest = blake3::hash(ctx.as_bytes()).to_hex().as_str()[..16].to_string();
    log.append(format!("NODE_START|{ctx}|Digest:{digest}").as_bytes()).unwrap();
    let payload = vec![b'x'; common::audit_log::MAX_PAYLOAD];
    for _ in 0..count { log.append(&payload).unwrap(); }
    log.append(b"DYNAMIC_BLOCK_V4|IP:198.51.100.7|TTL:60s|Reason:ids: scan|Enforced|Claim:new|At:1000000|Event:ids/1").unwrap();
    return;
 }
 let path = std::path::Path::new("/tmp/sokol-replay-race/audit.sntl");
 std::fs::create_dir_all(path.parent().unwrap()).unwrap();
 let ctx = "Build:local-upgrade|Node:1|TtlBase:60|TtlMax:600";
 let digest = blake3::hash(ctx.as_bytes()).to_hex().as_str()[..16].to_string();
 let mut log = AuditLog::open_with(path, Some(Rotation { max_bytes: 1, keep: 10 })).unwrap();
 log.append(format!("NODE_START|{ctx}|Digest:{digest}").as_bytes()).unwrap();
 log.append(b"DYNAMIC_BLOCK_V4|IP:198.51.100.7|TTL:60s|Reason:ids: scan|Enforced|Claim:new|At:1000000|Event:ids/1").unwrap();
 drop(log);
 let mut bytes = std::fs::read(path).unwrap();
 bytes[12..SEGMENT_HEADER_LEN].fill(9);
 let end = bytes.len()-CHAIN_LEN;
 let mut h = blake3::Hasher::new(); h.update(&[9;CHAIN_LEN]); h.update(&bytes[SEGMENT_HEADER_LEN..SEGMENT_HEADER_LEN+HEADER_LEN]); h.update(&bytes[SEGMENT_HEADER_LEN+HEADER_LEN..end]);
 bytes[end..].copy_from_slice(h.finalize().as_bytes());
 std::fs::write("/tmp/sokol-replay-race/alternate",bytes).unwrap();
}
