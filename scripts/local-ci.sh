#!/usr/bin/env bash
# The CI job (.github/workflows/ci.yml, build-test-smoke) on this Linux host, in the same order,
# with the same pinned tools and checksums, so a change can be checked before it is pushed.
# Ubuntu 24.04 on x86_64 or aarch64 (a Lima VM on macOS works: AGENTS.md). Needs sudo for the
# XDP smoke, the demo and the runbook rehearsal.
#
#   scripts/local-ci.sh              everything CI runs, except the artifact upload
#   scripts/local-ci.sh --quick      policy checks, build, tests, clippy, Python regressions
#   scripts/local-ci.sh --step NAME  one step: tools, monitoring (used by test_local_ci.py)
#
# Pins (versions, SHA256, the Prometheus image digest) are read from ci.yml itself, so the two
# cannot drift: change them there, not here. Pinned tools are extracted on every run from
# archives whose checksum is verified on every run, into a directory first on PATH; what is
# already installed elsewhere is never trusted for its version text. Policy checks that CI runs
# only on x86_64 (fmt, retired, claims, monitoring, cargo-deny) run here on either architecture;
# promtool needs docker and is skipped, with a notice, without it.
set -euo pipefail
cd "$(dirname "$0")/.."
QUICK=0
ONLY=""
case "${1:-}" in
    --quick) QUICK=1 ;;
    --step) ONLY="${2:?--step needs a name}" ;;
    "") ;;
    *) echo "usage: $0 [--quick | --step tools|monitoring]"; exit 2 ;;
esac
CI=${LOCAL_CI_YML:-.github/workflows/ci.yml}
CACHE=${LOCAL_CI_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/sokol-local-ci}
TOOLS="$CACHE/bin"
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
if key == "prometheus_image":
    m = re.search(r'prom/prometheus@sha256:[0-9a-f]{64}', text)
    sys.exit("prometheus image not found") if not m else print(m.group(0))
    sys.exit(0)
m = re.search(r'^\s+%s:\s*(\S+)' % key, text, re.M)
for b in re.split(r'\n\s+- arch: ', text)[1:]:
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

# A pinned archive, verified now: a cached copy is used only if its checksum still matches.
checked_archive() { # url sha256 name -> prints the path
    local url=$1 sum=$2 out="$CACHE/archives/$3"
    mkdir -p "$CACHE/archives"
    if ! { [ -f "$out" ] && echo "$sum  $out" | sha256sum -c --quiet - >/dev/null 2>&1; }; then
        rm -f "$out"
        curl -sSfL -o "$out.part" "$url"
        echo "$sum  $out.part" | sha256sum -c --quiet - >&2 || { rm -f "$out.part"; return 1; }
        mv "$out.part" "$out"
    fi
    echo "$out"
}

# bpf-linker, gobgp and gobgpd from verified archives into $TOOLS, which then comes first on
# PATH and is what the GoBGP tests use; each must resolve there.
tools() {
    step "pinned tools (from verified archives into $TOOLS)"
    local bpf_v gobgp_v archive
    bpf_v=$(pin BPF_LINKER_VERSION)
    gobgp_v=$(pin GOBGP_VERSION)
    rm -rf "$TOOLS"
    mkdir -p "$TOOLS"
    archive=$(checked_archive \
        "https://github.com/aya-rs/bpf-linker/releases/download/${bpf_v}/bpf-linker-${ARCH}-unknown-linux-musl.tar.zst" \
        "$(pin bpf_linker_sha256)" "bpf-linker-${bpf_v}-${ARCH}.tar.zst")
    tar --zstd -x -C "$TOOLS" -f "$archive"
    archive=$(checked_archive \
        "https://github.com/osrg/gobgp/releases/download/v${gobgp_v}/gobgp_${gobgp_v}_linux_${GOBGP_ARCH}.tar.gz" \
        "$(pin gobgp_sha256)" "gobgp-${gobgp_v}-${GOBGP_ARCH}.tar.gz")
    tar -xz -C "$TOOLS" -f "$archive" gobgp gobgpd
    export PATH="$TOOLS:$PATH" SOKOL_GOBGP_TEST_BIN="$TOOLS"
    local tool
    for tool in bpf-linker gobgp gobgpd; do
        if [ "$(command -v "$tool")" != "$TOOLS/$tool" ]; then
            echo "FAIL $tool resolves to $(command -v "$tool" || echo nothing), not $TOOLS/$tool"
            return 1
        fi
        echo "using $TOOLS/$tool"
    done
}

# CI's monitoring step: metric names, then promtool on the alert rules in CI's pinned image.
monitoring() {
    step "monitoring"
    scripts/check-monitoring.sh
    if command -v docker >/dev/null; then
        docker run --rm -v "$PWD/deploy/prometheus:/w" -w /w --entrypoint promtool \
            "$(pin prometheus_image)" test rules sokol-alerts.test.yml
    else
        echo "promtool skipped: no docker (CI runs it)"
    fi
}

case "$ONLY" in
    "") ;;
    tools) tools; exit 0 ;;
    monitoring) monitoring; exit 0 ;;
    *) echo "unknown step $ONLY"; exit 2 ;;
esac

step "pinned Rust toolchain"
rustup show active-toolchain >/dev/null || rustup toolchain install
(cd ebpf && (rustup show active-toolchain >/dev/null || rustup toolchain install))
tools

step "format"; cargo fmt --all --check; (cd ebpf && cargo fmt --check)
step "retired surface"; scripts/check-retired.sh
step "cited evidence"; scripts/check-claims.sh
monitoring
if [ "$ARCH" = x86_64 ]; then
    step "dependency policy (cargo-deny $(pin CARGO_DENY_VERSION))"
    deny=$(checked_archive \
        "https://github.com/EmbarkStudios/cargo-deny/releases/download/$(pin CARGO_DENY_VERSION)/cargo-deny-$(pin CARGO_DENY_VERSION)-x86_64-unknown-linux-musl.tar.gz" \
        "$(pin CARGO_DENY_SHA256)" "cargo-deny-$(pin CARGO_DENY_VERSION).tar.gz")
    tar -xzf "$deny" -C "$TOOLS" --strip-components=1
    "$TOOLS/cargo-deny" check && "$TOOLS/cargo-deny" --manifest-path ebpf/Cargo.toml check
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
python3 scripts/test_witness_gate.py
python3 scripts/test_local_ci.py
python3 scripts/test_runbook_preflight.py
timeout 120 python3 scripts/test_crowdsec_stream.py target/release/sokol-crowdsec
timeout 120 python3 scripts/test_suricata_recovery.py target/release/sokol-suricata
[ "$QUICK" = 1 ] && { step "quick run done (no smoke, demo or rehearsal)"; exit 0; }

# sudo resets PATH; keep the verified tools first for the root steps too.
as_root() { sudo env "PATH=$PATH" "SOKOL_GOBGP_TEST_BIN=$SOKOL_GOBGP_TEST_BIN" "$@"; }

step "XDP smoke (veth + netns)"
sudo apt-get install -y -qq netcat-openbsd wireguard-tools suricata crowdsec linux-tools-generic >/dev/null
shopt -s nullglob
bpftool_bins=(/usr/lib/linux-tools*/bpftool /usr/lib/linux-tools/*/bpftool)
sudo install -m 755 "$(printf '%s\n' "${bpftool_bins[@]}" | sort -V | tail -n 1)" /usr/local/bin/bpftool
sudo systemctl stop suricata 2>/dev/null || true
as_root SMOKE_REQUIRE="suricata crowdsec gobgp wireguard" scripts/xdp-smoke.sh target/release/orchestrator

step "demo (3 nodes, attacker, rogue node, Suricata)"
as_root DEMO_AUTO=1 demo/demo.sh target/release
if pgrep -af '[o]rchestrator --interface sd-'; then echo "demo left nodes running"; exit 1; fi

step "runbook rehearsal (systemd)"
rm -rf /tmp/rh-a /tmp/rh-b && mkdir -p /tmp/rh-a /tmp/rh-b
cp target/release/orchestrator target/release/monitor /tmp/rh-a/
SOKOL_BUILD_ID="local-upgrade" cargo build --release --locked -p orchestrator
cp target/release/orchestrator target/release/monitor /tmp/rh-b/
as_root scripts/runbook-rehearsal.sh /tmp/rh-a /tmp/rh-b
step "local CI passed"
