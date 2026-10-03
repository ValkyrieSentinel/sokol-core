# FlowSpec: accepted withdrawal with a retained hidden-ID path

Author-run isolated experiment, 2026-10-03, Sokol base `8049fd9`. No peers or
upstream router; BGP listen disabled, ephemeral loopback gRPC. Both GoBGP binaries
were built using Go 1.27.1 from `github.com/osrg/gobgp/v4@v4.9.0`, module checksum
`h1:pKOw914kwQ4I/lWNVTfEDosEN3FuqPGytMEInXxpTyQ=`.

The injector deliberately uses the node's ownership community 65001:6666 on an
API identifier-7 path. This violates the normal exclusive CLI-writer assumption;
it is a controlled boundary experiment, not an alleged production incident.
Both families retain API identifier 7/local identifier 1, while CLI JSON reports
LocalID 0. An ID-zero CLI withdrawal exits zero, with byte-identical RIB before
and after. `results.json` preserves these raw observations. No other metadata or
upstream enforcement is inferred from them.

To reproduce, build `inject.go` in a temporary Go module requiring exactly
`github.com/osrg/gobgp/v4 v4.9.0` (Go 1.27.1, matching module checksum), with
`go build -mod=mod -o probe /absolute/path/to/inject.go`. Then invoke:

```sh
python3 run.py /path/to/pinned-gobgp-bin /path/to/probe /tmp/fresh-hidden-id.json
```

The runner asserts identifier retention, CLI zero ID, successful delete and
byte-identical retained RIB for both families, and terminates its daemon.
Fresh capture timestamps differ; compare predicates, not this dated JSON byte-for-byte.
The exact producer/CLI sources should stay pinned. Canonical native CI separately
uses the production Rust round with real daemon reads and controlled no-effect
write acknowledgements; it does not execute this Go injector. See FLOWSPEC-R5.
