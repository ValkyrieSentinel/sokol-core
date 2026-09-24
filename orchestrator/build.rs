use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../sntl_db/src/main.zig");
    println!("cargo:rerun-if-changed=../sntl_db/build.zig");

    // Install into OUT_DIR, not sntl_db/zig-out: cargo only reruns this script when the Zig
    // sources change, so an artifact outside OUT_DIR goes missing on cached or fresh checkouts.
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let status = Command::new("zig")
        .args(["build", "-Doptimize=ReleaseSafe", "--prefix"])
        .arg(&out_dir)
        .arg("--cache-dir")
        .arg(out_dir.join("zig-cache"))
        .current_dir("../sntl_db")
        .status()
        .expect("Failed to execute Zig compiler");

    if !status.success() {
        panic!("Compilation of the sntl_db Zig module failed");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.join("lib").display());
    println!("cargo:rustc-link-lib=static=sntl_db");
}
