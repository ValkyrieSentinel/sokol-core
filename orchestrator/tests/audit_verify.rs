//! Exercise the real monitor CLI, not a reproduction of its exit-code classifier.
use common::audit_log::{rotated_segments, AuditLog, Rotation};
use std::path::{Path, PathBuf};
use std::process::Command;

fn path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sokol-verify-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("audit.log")
}

fn check(path: &Path, status: i32, label: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_monitor"))
        .arg("--verify")
        .arg(path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(status), "{:?}", output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with(&format!("{label} {}:", path.display())),
        "{stdout}"
    );
}

#[test]
fn verify_cli_confirms_an_intact_chain() {
    let path = path("intact");
    let mut log = AuditLog::open(&path).unwrap();
    log.append(b"decision").unwrap();
    log.sync().unwrap();
    drop(log);
    check(&path, 0, "OK");
}

#[test]
fn verify_cli_reports_an_actual_hash_mismatch_as_broken() {
    let path = path("edited");
    let mut log = AuditLog::open(&path).unwrap();
    log.append(b"decision").unwrap();
    log.sync().unwrap();
    drop(log);
    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&path, bytes).unwrap();
    check(&path, 1, "BROKEN");
}

#[test]
fn verify_cli_missing_active_file_is_unverified() {
    check(&path("missing"), 2, "UNVERIFIED");
}

#[test]
fn verify_cli_unavailable_segment_directory_is_unverified() {
    check(
        &path("missing-parent").join("missing/audit.log"),
        2,
        "UNVERIFIED",
    );
}

#[test]
fn verify_cli_read_failure_is_unverified() {
    let path = path("directory");
    std::fs::create_dir(&path).unwrap();
    check(&path, 2, "UNVERIFIED");
}

#[test]
fn verify_cli_unreadable_rotated_segment_is_unverified() {
    let path = path("rotated-directory");
    std::fs::write(&path, b"").unwrap();
    std::fs::create_dir(path.with_file_name("audit.log.00000000000000000000")).unwrap();
    check(&path, 2, "UNVERIFIED");
}

#[test]
fn verify_cli_observed_segment_gap_is_broken() {
    let path = path("gap");
    let mut log = AuditLog::open_with(
        &path,
        Some(Rotation {
            max_bytes: 80,
            keep: 10,
        }),
    )
    .unwrap();
    for _ in 0..8 {
        log.append(b"decision").unwrap();
    }
    log.sync().unwrap();
    drop(log);
    let segments = rotated_segments(&path).unwrap();
    assert!(segments.len() > 2);
    std::fs::remove_file(&segments[1].1).unwrap();
    check(&path, 1, "BROKEN");
}

#[test]
fn verify_cli_trailing_bytes_in_a_rotated_segment_are_broken() {
    use std::io::Write;
    let path = path("rotated-tail");
    let mut log = AuditLog::open_with(
        &path,
        Some(Rotation {
            max_bytes: 80,
            keep: 10,
        }),
    )
    .unwrap();
    for _ in 0..4 {
        log.append(b"decision").unwrap();
    }
    log.sync().unwrap();
    drop(log);
    let segments = rotated_segments(&path).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&segments[0].1)
        .unwrap();
    file.write_all(b"torn").unwrap();
    drop(file);
    check(&path, 1, "BROKEN");
}

#[test]
fn verify_cli_retains_the_active_torn_tail_policy_without_modifying_bytes() {
    use std::io::Write;
    let path = path("active-tail");
    let mut log = AuditLog::open(&path).unwrap();
    log.append(b"decision").unwrap();
    log.sync().unwrap();
    drop(log);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(b"torn").unwrap();
    drop(file);
    let before = std::fs::read(&path).unwrap();
    check(&path, 0, "OK");
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
