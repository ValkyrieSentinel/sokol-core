//! Build identity: `--version`, the startup log and `sokol_build_info` name the exact source.
//! SOKOL_BUILD_ID wins (a release pipeline sets it); otherwise the git commit, if the source is a
//! checkout; otherwise "unknown" (e.g. a source tarball without .git).
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SOKOL_BUILD_ID");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");
    // Cargo otherwise caches this result while recompiling changed Rust source. Track
    // the actual per-worktree Git files and every tracked input, including shared code.
    for name in ["HEAD", "index", "packed-refs"] {
        if let Ok(out) = Command::new("git")
            .args(["rev-parse", "--git-path", name])
            .output()
        {
            if out.status.success() {
                println!(
                    "cargo:rerun-if-changed={}",
                    String::from_utf8_lossy(&out.stdout).trim()
                );
            }
        }
    }
    if let Ok(out) = Command::new("git")
        .args(["-C", "..", "ls-files", "-z"])
        .output()
    {
        if out.status.success() {
            for path in out
                .stdout
                .split(|byte| *byte == 0)
                .filter(|path| !path.is_empty())
            {
                println!(
                    "cargo:rerun-if-changed=../{}",
                    String::from_utf8_lossy(path)
                );
            }
        }
    }
    let id = std::env::var("SOKOL_BUILD_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            let out = Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let sha = String::from_utf8(out.stdout).ok()?.trim().to_string();
            let dirty = Command::new("git")
                .args(["status", "--porcelain", "--untracked-files=no"])
                .output()
                .map(|o| !o.stdout.is_empty())
                .unwrap_or(false);
            Some(if dirty { format!("{}-dirty", sha) } else { sha })
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SOKOL_BUILD_ID={}", id);
    println!(
        "cargo:rustc-env=SOKOL_VERSION={} (build {})",
        std::env::var("CARGO_PKG_VERSION").unwrap_or_default(),
        id
    );
}
