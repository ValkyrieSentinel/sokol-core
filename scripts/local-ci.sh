#!/usr/bin/env bash
# The CI job (.github/workflows/ci.yml, build-test-smoke) on this Linux host, in the same order,
# with the same pinned tools and checksums, so a change can be checked before it is pushed.
# Ubuntu 24.04 on x86_64 or aarch64 (a Lima VM on macOS works: AGENTS.md). Needs sudo for the
# tool installs, the XDP smoke, the demo and the runbook rehearsal.
#
#   scripts/local-ci.sh            everything CI runs, except the artifact upload
#   scripts/local-ci.sh --quick    policy checks, build, tests, clippy, Python regressions
#
# Pins are read from ci.yml itself, so the two cannot drift: change a version there, not here.
# Policy checks that CI runs only on x86_64 (fmt, retired, claims, monitoring, cargo-deny) run
# here on either architecture; monitoring is skipped without docker.
set -euo pipefail
cd "$(dirname "$0")/.."
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1
CI=.github/workflows/ci.yml
case "$(uname -m)" in
    x86_64) ARCH=x86_64; GOBGP_ARCH=amd64 ;;
    aarch64) ARCH=aarch64; GOBGP_ARCH=arm64 ;;
    *) echo "unsupported architecture $(uname -m)"; exit 2 ;;
esac

# One value from ci.yml: a top-level env key, or a key in this architecture's matrix entry.
pin() {
    python3 - "$CI" "$ARCH" "$1" <<'PY'
import re, sys
text, arch, key = open(sys.argv[1]).read(), sys.argv[2], sys.argv[3]
m = re.search(r'^\s+%s:\s*(\S+)' % key, text, re.M)
blocks = re.split(r'\n\s+- arch: ', text)
for b in blocks[1:]:
    if b.startswith(arch):
        mm = re.search(r'^\s+%s:\s*(\S+)' % key, b, re.M)
        if mm:
            m = mm
if not m:
    sys.exit("pin %s not found in %s" % (key, sys.argv[1]))
print(m.group(1))
PY
}

step() { printf '\n=== %s\n' "$*"; }
fetch_checked() { # url sha256 out
    curl -sSfL -o "$3" "$1"
    echo "$2  $3" | sha256sum -c -
}

step "pinned Rust toolchain"
rustup show active-toolchain >/dev/null || rustup toolchain install
(cd ebpf && (rustup show active-toolchain >/dev/null || rustup toolchain install))

BPF_V=$(pin BPF_LINKER_VERSION | tr -d v)
if ! command -v bpf-linker >/dev/null || ! bpf-linker --version | grep -q "$BPF_V"; then
    step "bpf-linker $BPF_V"
    fetch_checked "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_V}/bpf-linker-${ARCH}-unknown-linux-musl.tar.zst" \
        "$(pin bpf_linker_sha256)" /tmp/bpf-linker.tar.zst
    sudo tar --zstd -x -C /usr/local/bin -f /tmp/bpf-linker.tar.zst
fi
GOBGP_V=$(pin GOBGP_VERSION)
if ! command -v gobgpd >/dev/null || ! gobgpd --version 2>&1 | grep -q "$GOBGP_V"; then
    step "GoBGP $GOBGP_V"
    fetch_checked "https://github.com/osrg/gobgp/releases/download/v${GOBGP_V}/gobgp_${GOBGP_V}_linux_${GOBGP_ARCH}.tar.gz" \
        "$(pin gobgp_sha256)" /tmp/gobgp.tar.gz
    sudo tar -xz -C /usr/local/bin -f /tmp/gobgp.tar.gz gobgp gobgpd
fi
export SOKOL_GOBGP_TEST_BIN=/usr/local/bin

step "format"; cargo fmt --all --check; (cd ebpf && cargo fmt --check)
step "retired surface"; scripts/check-retired.sh
step "cited evidence"; scripts/check-claims.sh
if command -v docker >/dev/null; then
    step "monitoring"; scripts/check-monitoring.sh
else
    step "monitoring: skipped (no docker; CI runs promtool)"
fi
if [ "$ARCH" = x86_64 ]; then
    step "dependency policy (cargo-deny $(pin CARGO_DENY_VERSION))"
    fetch_checked "https://github.com/EmbarkStudios/cargo-deny/releases/download/$(pin CARGO_DENY_VERSION)/cargo-deny-$(pin CARGO_DENY_VERSION)-x86_64-unknown-linux-musl.tar.gz" \
        "$(pin CARGO_DENY_SHA256)" /tmp/cargo-deny.tar.gz
    tar -xzf /tmp/cargo-deny.tar.gz -C /tmp --strip-components=1
    /tmp/cargo-deny check && /tmp/cargo-deny --manifest-path ebpf/Cargo.toml check
else
    step "dependency policy: skipped (CI runs cargo-deny on x86_64)"
fi

step "eBPF program"; (cd ebpf && cargo build --release --locked)
step "workspace"; cargo build --release --locked
step "tests"; cargo test --release --locked
step "clippy"; cargo clippy --release --locked --all-targets -- -D warnings
step "Python regressions"
python3 scripts/test_xdp_probe.py
python3 scripts/test_audit_smoke.py
python3 scripts/test_flowspec_smoke.py
python3 scripts/test_crowdsec_ttl.py
timeout 120 python3 scripts/test_crowdsec_stream.py target/release/sokol-crowdsec
timeout 120 python3 scripts/test_suricata_recovery.py target/release/sokol-suricata
[ "$QUICK" = 1 ] && { step "quick run done (no smoke, demo or rehearsal)"; exit 0; }

step "XDP smoke (veth + netns)"
sudo apt-get install -y -qq netcat-openbsd wireguard-tools suricata crowdsec linux-tools-generic >/dev/null
shopt -s nullglob
bpftool_bins=(/usr/lib/linux-tools*/bpftool /usr/lib/linux-tools/*/bpftool)
sudo install -m 755 "$(printf '%s\n' "${bpftool_bins[@]}" | sort -V | tail -n 1)" /usr/local/bin/bpftool
sudo systemctl stop suricata 2>/dev/null || true
sudo SMOKE_REQUIRE="suricata crowdsec gobgp wireguard" scripts/xdp-smoke.sh target/release/orchestrator

step "demo (3 nodes, attacker, rogue node, Suricata)"
sudo DEMO_AUTO=1 demo/demo.sh target/release
if pgrep -af '[o]rchestrator --interface sd-'; then echo "demo left nodes running"; exit 1; fi

step "runbook rehearsal (systemd)"
rm -rf /tmp/rh-a /tmp/rh-b && mkdir -p /tmp/rh-a /tmp/rh-b
cp target/release/orchestrator target/release/monitor /tmp/rh-a/
SOKOL_BUILD_ID="local-upgrade" cargo build --release --locked -p orchestrator
cp target/release/orchestrator target/release/monitor /tmp/rh-b/
sudo scripts/runbook-rehearsal.sh /tmp/rh-a /tmp/rh-b
step "local CI passed"
