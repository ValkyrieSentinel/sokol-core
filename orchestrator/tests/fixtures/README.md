# GoBGP action captures

`gobgp-4.9.0-actions.json` contains raw `global rib -a FAMILY -j` output from an
isolated GoBGP 4.9.0 daemon, router ID 127.0.0.1, AS 65001, BGP listening disabled
(port -1), ephemeral loopback gRPC port, no peers. Both IPv4 and IPv6 were captured
for owned rate-limit 100, owned discard, and foreign-local discard paths.
Ownership community: 65001:6666; foreign community: 65001:9999.

Local Darwin binaries were built with Go 1.27.1 from
`github.com/osrg/gobgp/v4@v4.9.0`, module checksum
`h1:pKOw914kwQ4I/lWNVTfEDosEN3FuqPGytMEInXxpTyQ=`.
Canonical CI uses its existing checksum-pinned Linux 4.9.0 binaries instead and
executes the production reconciliation against a real daemon for both families.
Captures are parser fixtures; they do not establish upstream enforcement or a
conditional-write guarantee. See FLOWSPEC-R3 in `docs/DETECTOR_INVARIANTS.md`.
