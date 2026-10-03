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

## Empty standard communities

`gobgp-4.9.0-empty-community.json` retains raw CLI stdout captured on 2026-10-03
from the same pinned source/toolchain and isolated configuration, for both families.
A gRPC `AddPath` used `apiutil.NewPath`, a single source component, origin 2,
`bgp.NewPathAttributeCommunities(nil)`, traffic-rate zero and MP_REACH_NLRI with
an unspecified nexthop. The CLI round trip emits type 8 with `communities: null`.
There is no ownership tag; these local paths must remain foreign. The new captures
extend parser compatibility evidence; canonical CI does not execute this Go injector.
The original action captures are unchanged.
