# Security policy

## Reporting and support status

Use [private vulnerability reporting](https://github.com/s0fractal/sokol-core/security/advisories/new)
for vulnerabilities. It is enabled on this repository. Include the exact commit,
deployment profile, attacker privileges, reproduction and observed effect. Do not
publish secrets, customer traffic or a live exploit in a public issue.

The owner, `s0fractal`, is the responsible release owner and incident responder.
Operating targets, the RC admission rule, the support horizon and a response target
(7 days, not yet measured) are in [ADR-0031](docs/adr/0031-rc1-responsibility-and-operating-targets.md).
No RC has been admitted yet; native-NIC/router qualification and the field pilot are pending.

## System and boundaries

Sokol is a Linux XDP enforcement node with local detector adapters, an
authenticated mesh, operator control and optional upstream FlowSpec. It does not
independently establish that an address is malicious. The supported lab profile,
unverified environments and operational recovery are in SUPPORT and RUNBOOK.

- External packets, detector text and event files, IPC frames, mesh envelopes,
  remote HTTP responses and restored state/audit files may be malformed.
- Mesh public keys authorize only their own issuer within the configured envelope;
  authentication does not grant authority over other peers or protected targets.
- Local IPC and operator sockets are separate authorities. Access to the operator
  socket permits operator actions. The HTTP operator additionally requires a token
  and binds local telemetry/control routes to process credentials.
- Mesh authentication is not confidentiality. Deployment supplies its private
  transport (for example WireGuard). Metrics and read-only status have no HTTP
  authentication and belong on a private management address.
- The service runs with explicit BPF/network capabilities. Untrusted candidate
  evidence is verified as data; native replay requires the separate isolated runner.
- Repository owner and provisional agent authority are distinct. Signer/checker
  transitions require existing owner authority. Reports, comments and valid evidence
  signatures do not themselves authorize merge, acceptance, release or deployment.

## Properties to challenge

Issuer/target/route binding; protected-address enforcement; bounded unauthenticated
parsing and admitted work; replay/expiry across clock changes and process exits;
desired versus applied state; honest lost-reply/readback uncertainty; durability
and degraded-mode visibility; privacy and integrity of audit/support evidence;
the isolation and trust boundaries of CI, packages and evidence import/replay.

Report concrete reachable violations of these properties, including interactions
across components. A green test, formal harness or signed manifest is evidence
within its inputs and assumptions, not a reason to suppress a counterexample.
Severity follows demonstrated authority, reachability and operational effect.

## Limits without blanket exclusions

Bounded proofs cover their harness domains; generic XDP and virtual interfaces do
not qualify native hardware. Third-party crypto, kernel, toolchain and routing
components remain dependencies. Their use is not an independent audit claim.
Root compromise can replace the host's kernel, binaries and keys; distinguish that
assumed authority from an input which unexpectedly crosses into it.

No new vulnerability class is excluded or accepted by this document. Existing
intentional trade-offs and qualifications remain in the relevant ADR and support
profile; report a demonstrated contradiction or a newly reachable effect against
that context. Proposed changes to accepted authority/risk require an owner decision.
