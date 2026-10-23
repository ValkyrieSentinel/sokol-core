# Native boundary experiments

Install `cargo-fuzz 0.13.2` with `cargo +stable install --locked cargo-fuzz --version 0.13.2`.
Use the repository's pinned nightly and stage the inputs, then run:

    python3 scripts/fuzz-check.py --seconds 60 --output /tmp/sokol-fuzz-NEW

The fixed driver copies only tracked `common/` and `fuzz/` inputs into a private
tree (256 files / 8 MiB), records input hashes and tool identity, then runs both
targets and two production-fault controls. It refuses a changed lockfile. Each
process has a 600-second outer timeout and 2 MiB captured-output limit. libFuzzer
uses ASan, 16 KiB inputs, a 1 GiB RSS limit, five-second per-input timeout and seed
1729. Compiler disk/RSS and accumulated corpus disk need external limits on an
untrusted host; these command-line limits do not authenticate a toolchain.

`wire` checks that an accepted frame partitions every byte and re-encodes its
header. `canonical` checks accepted object framing, no panic on UTF-8, and refusal
of constructed duplicate keys. It does not claim to validate the complete JSON
grammar. Fault controls replace the payload split offset and duplicate refusal
in private production-source copies; a compile failure is UNCONFIRMED. Original
inputs remain unchanged. CALIBRATED_RUN covers these assertions and these faults,
not parser correctness for every input or owner acceptance. Kani remains separate.

The manual `Native fuzz calibration` workflow publishes the unsigned receipt;
this is separate from PR checks and does not add runtime dependencies to Sokol.
