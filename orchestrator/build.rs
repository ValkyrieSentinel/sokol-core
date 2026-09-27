//! Build identity: `--version`, the startup log and `sokol_build_info` name the exact source.
//! SOKOL_BUILD_ID wins (a release pipeline sets it); otherwise the git commit, if the source is a
//! checkout; otherwise "unknown" (e.g. a source tarball without .git).
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SOKOL_BUILD_ID");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");
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
