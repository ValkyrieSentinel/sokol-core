#!/usr/bin/env python3
"""Reproduce the reviewed FlowSpec output path on Linux without editing the repository."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

PINS = {
    "orchestrator/src/flowspec.rs": "d1d0dfd1d60f08c5d66f8362e3d07ebddc02cda89b9238a03eab971c3571dfc2",
    "Cargo.lock": "a5776c0dcad4bd844cf6e9c4de9126fd2a9561418671d1e75b853e1aaa8ef683",
}
MANIFEST = '''[package]
name = "sokol-review-probe"
version = "0.1.0"
edition = "2021"
[dependencies]
tokio = { version = "1.0", features = ["full"] }
ipnet = "2.9"
log = "0.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
'''
WRAPPER = '''
pub async fn review_output_lengths(cli: &GobgpCli) -> (usize, usize) {
    let stdout = cli.run(vec!["stdout".into()]).await.unwrap().len();
    let stderr = cli.run(vec!["stderr".into()]).await.unwrap_err().len();
    (stdout, stderr)
}
'''
MAIN = '''#![allow(dead_code)]
mod flowspec;
mod block_table { pub fn show(net: &ipnet::IpNet) -> String { net.to_string() } }
pub struct SentinelDb;
impl SentinelDb { pub fn append(&self, _: String) {} }
#[tokio::main]
async fn main() {
    let cli = flowspec::GobgpCli { bin: std::env::args().nth(1).unwrap().into(), args: vec!["rib".into()], community: (64512,1) };
    let start=std::time::Instant::now();
    let (stdout, stderr) = flowspec::review_output_lengths(&cli).await;
    let rib_accepted=cli.observed().await.is_ok();
    println!("stdout_bytes={stdout} stderr_diagnostic_bytes={stderr} padded_rib_accepted={rib_accepted} elapsed_ms={}", start.elapsed().as_millis());
}
'''
PRODUCER = '''#!/usr/bin/env python3
import sys
size=64*1024*1024
mode=sys.argv[1]
if mode=="stderr":
 sys.stderr.buffer.write(b"e"*size)
 sys.exit(1)
if mode=="stdout":
 sys.stdout.buffer.write(b"x"*size)
else:
 sys.stdout.buffer.write(b"{}"+b" "*size)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Run this probe in Linux (the reviewed environment was ARM64 Lima)")
    inputs = {name: (args.repo / name).read_bytes() for name in PINS}
    for name, expected in PINS.items():
        if hashlib.sha256(inputs[name]).hexdigest() != expected:
            parser.error("Reviewed input changed: " + name)
    with tempfile.TemporaryDirectory(prefix="sokol-flowspec-output-") as directory:
        work = Path(directory)
        (work / "src").mkdir()
        (work / "Cargo.toml").write_text(MANIFEST)
        (work / "Cargo.lock").write_bytes(inputs["Cargo.lock"])
        shutil.copy(args.repo / "rust-toolchain.toml", work / "rust-toolchain.toml")
        (work / "src/flowspec.rs").write_bytes(inputs["orchestrator/src/flowspec.rs"] + WRAPPER.encode())
        (work / "src/main.rs").write_text(MAIN)
        (work / "producer.py").write_text(PRODUCER)
        (work / "producer.py").chmod(0o755)
        # The standalone package trims the original lockfile to its dependency subset.
        # Offline resolution avoids fetching different crates during reproduction.
        run = subprocess.run(["cargo", "run", "--offline", "--quiet", "--", "./producer.py"],
                             cwd=work, text=True, capture_output=True, timeout=300)
        if run.returncode:
            raise SystemExit(run.stderr)
        result = dict(item.split("=", 1) for item in run.stdout.strip().split())
        for field in ("stdout_bytes", "stderr_diagnostic_bytes", "elapsed_ms"):
            result[field] = int(result[field])
        result["padded_rib_accepted"] = result["padded_rib_accepted"] == "true"
        assert result["stdout_bytes"] == result["stderr_diagnostic_bytes"] == 64 * 1024 * 1024
        assert result["padded_rib_accepted"]
        result["source_hashes"] = PINS
        result["environment"] = platform.platform()
        result["scope"] = "actual source methods; controlled producer; no live daemon or GoBGP"
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
