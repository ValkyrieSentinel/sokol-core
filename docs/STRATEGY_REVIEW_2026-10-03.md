# Stargate + Sokol: architecture and next decisions — 2026-10-03

Reviewed baselines: Stargate `8e148e904f1abce71bfa69271fe65a7dfd331462`;
Sokol `24fa7acae8765fe287b5e5e04cb8cb6e6a36348d`. This is an operator-authorized
internal architecture review of entry points, admission, delivery, enforcement,
audit/replay, shutdown and CI contracts. It is not an exhaustive security scan,
independent adoption study or release qualification. Historical experiments stay
unchanged; retired workspace subjects are not sources for this review.

## What should each system own?

| System | Useful responsibility now | Evidence and boundary |
| --- | --- | --- |
| Stargate | Check small workflow/policy proposals, preserve inherited requirements, replay evidence across agent sessions | Model/projection checkers, owned repairs and pinned consumer checks. At most six Boolean state bits and two event bits; abstraction-to-code correspondence remains a separate check. |
| Sokol | Apply bounded authorized network decisions, retain/reconcile wanted versus applied state and expose losses | Linux XDP, pinned mesh authority, detector delivery, persistence, audit and replay. veth/generic/native lab evidence does not qualify a physical NIC or production workload. |
| Agent | Select the right task/abstraction, test the actual consumer, act within operator permissions and reconcile uncertain results | A certificate, ACK, successful subprocess or green CI has a specific scope. None grants additional authority or proves a different layer's outcome. |

Stargate's existing publisher rechecks mutable PR binding before status publication;
its documented final-read/POST race remains. Agent review is useful independent
model-family evidence, not a required mathematical check or proof of arbitrary PR
correctness. Sokol observe-mode code suppresses mesh claims and FlowSpec publication
(ADR-0018); this review does not resurrect the earlier corrected observe-mode concern.

## Live repository-control readback

On 2026-10-03, Stargate ruleset `protect-main` (23849266) was active: strict base
freshness, four Python checks, model-gate bound to App 5041755 and shadow bound to
App 15368; zero mandatory approvals and no bypass actors. This is mutable GitHub
configuration, not a proof of arbitrary source correctness.

Sokol's branch endpoint reported `main.protected=false`, empty required checks
and enforcement off; its ruleset listing was empty. The current account has WRITE,
not ADMIN. Thus required CI/review in this task is an agent merge criterion, not a
GitHub-enforced Sokol admission rule. No configuration mutation was attempted.
All three existing check runs identify GitHub Actions App 15368.

[Prepared protection request](ci-protection-proposal.json) requires those three
checks with strict freshness, zero approvals, enforcement for admins and no force
push/deletion. This is a proposal, not active protection. An owner/admin must first
re-read the branch configuration; if another policy has since appeared, adapt the
request instead of overwriting it. Private-repository plan eligibility is unknown;
GitHub documents the permission and availability requirements in its
[branch protection API](https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection).
With those prerequisites established, the owner can apply from the repo root:

```sh
gh api --method PUT repos/ValkyrieSentinel/sokol-core/branches/main/protection \
  --input docs/ci-protection-proposal.json
gh api repos/ValkyrieSentinel/sokol-core/branches/main/protection
```

Readback must confirm every requested check/App pair, strict freshness, zero
approvals, admin enforcement and disabled force pushes/deletion. A refused request
or unreadable response never establishes activation. These checks improve repository
admission; their CI code and platform remain trust assumptions.

## Allocation decision

Keep the Stargate proof core and working integrations. Generic agent-adapter expansion
remains paused under its current AGENT_PROFILE and utility results. The three screened
utility obligations were excluded; no comparison ran. The Warrant maintenance study
supports ordinary code for new fixed policies unless checked projection provenance is
a named requirement. These are constraints on spending effort, not proof of no utility.

The strongest present investment is the path from a decision to an observed result in
Sokol. Recent shutdown, audit-loss/replay and smoke-verdict changes already close real
failure paths. Production readback must obey the same discipline as its tests.

## First concrete correction: CLI acceptance is not RIB observation

Production `flowspec::round` read the RIB before its writes and then returned an
arithmetically predicted count. Controlled CLI children returning success without a
route change caused a phantom announcement or disappearance. Failed/malformed later
readback was not queried at all. This reproduces a consumer contract defect, not a
claimed failure of real GoBGP or an observed production incident.

The correction reads both families again after a changed round. Failed readback
withholds a new count; unchanged rounds reuse their actual initial read. Ownership,
withdrawal-first priority and the 64-change quota stay fixed. FLOWSPEC-R1 names the
regressions, compiled refusal controls and increased call-wait allowance. Existing
operation audit records keep acknowledging CLI success. Neither local RIB presence
nor that count proves discard action, upstream enforcement or freshness forever.

## Ranked next work and stopping rules

| Priority | Next concrete question | Acceptance / stop |
| --- | --- | --- |
| 0 | Will the owner enable the prepared Sokol required-CI policy? | Owner/admin activation and exact live readback; do not claim protection from agent-side merge discipline. No human approval gate is requested. |
| 1 | Can an agent distinguish a fresh FlowSpec observation from a retained stale count after read failure? | First reproduce the ambiguous consumer decision. Expose bounded freshness/health only if a real consumer needs it; do not convert unknown into zero or success. |
| 2 | Does a local owned source rule have the intended discard action, and can a conflicting action be reconciled safely? | Use actual pinned GoBGP JSON and add/remove behavior. Preserve foreign/peer paths and exact ownership. No inference from source-prefix presence alone. |
| 3 | Which interruption loses useful detector intent rather than deliberately skipping it? | Trace one actual adapter cursor/outbox/ACK path and its documented skip/expiry policy; test a process exit and repair only an unintended loss. Do not impose toy SQLite receipt semantics on the production socket. |
| 4 | Is there a newly arising small policy decision for which Stargate changes the result? | Register task-specific baseline and cost before a new comparison. Use ordinary tests when enumeration suffices; report negative/inconclusive outcomes. Do not count existing fixtures again as new use. |
| Qualification | Does a selected physical NIC/workload meet accepted operational limits? | Requires target hardware, workload and owner-selected SLO/RPO/RTO/false-positive policy. CI and agents cannot supply those decisions. No release/pilot is declared by this review. |

## Tactics for the next agent session

Choose one reproduced consumer failure and one isolated PR. Preserve exact source and
checker pins, lost-response predecessors and historical evidence. Write a regression
that fails on behavior; include the mirror case (add/delete, presence/absence,
accepted/refused, success/unknown) and a semantic weakening that it catches. Use a small
model only when its transitions reveal information beyond the executable baseline.

Run portable checks with declared stand-ins, then the full canonical Linux jobs for
runtime changes. Obtain a separate Claude static review at the exact final head;
record that it did not run tests. Merge only that reviewed head with all required
checks and unchanged base, verify the merged tree, and remove the task's worktree.
Store the engineering decision in the repository so the next session need not trust
chat history. Do not add schedulers, trust roots, economic mechanisms, new transport
protocols or production authority without a concrete operator-authorized need.

## Fresh baseline verification

Stargate was installed into a new local environment from the reviewed main commit.
On Python 3.14.8, all 709 installed-package tests passed outside the checkout, along
with architecture/anchor/vertical checks, the public reproduction profile, retained
local intents and SQLite receipt controls. These are author-run regression results,
not new independent utility cases. The checkout stayed unchanged. No checker,
frozen evidence, consumer pin or admission rule changed in this task.

For the FlowSpec correction, the exact production module passed all 11 local Rust
tests with declared audit/target-format stand-ins; four compiled semantic controls
failed on assertions. Required final-head checks are a separate Claude static
review and complete native x86/ARM CI plus Stargate shadow before merge. Those live
statuses belong to the PR; this review does not turn prior-run evidence into a new
production qualification or claim tests inspected all possible paths.
