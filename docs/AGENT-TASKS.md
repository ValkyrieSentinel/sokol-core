# Contract tasks and witness runs

## One entry point

`python3 scripts/sokol-dev.py next` shows current signature correspondence, provisional
owner-action candidates and the fixed challenge catalog. `inventory` and `map` project
the same contracts and declared witness locations; the map is not a compiler call graph.
`context IPC-A1` (also `explain IPC-A1`) delegates to the existing bounded context;
`check IPC-A1` invokes its existing native runner. `challenge genesis` runs the existing
calibrated Kani method, including its deliberate fault. These are explicit executions.

`verify /absolute/report.json` remains correspondence-only; adding replay explicitly
requests fresh execution. `exchange` forwards caller arguments to the existing portable
counterexample tool: the caller still chooses its verifier digest, trust, actor and key.
No text in a contract's annotations, a map or an imported report becomes a recipe.
Essential inventory/map output above 64 KiB is refused; select a contract instead.
An inventory MATCH never establishes execution, semantic adequacy or deployment authority.
The detailed owners and limits below apply unchanged.

The recipient gate runs outside received source using its explicit-root interface. The
producer's checker stays data, so a recipient does not replace bytes of its signed root.

`python3 scripts/contract-task.py context IPC-A1` produces a read-only packet of at most
16 KiB. The same command accepts any contract ID: for example `MESH-K1`. It uses the gate's
normalizers and signed manifest, reports the selected binding, and leaves execution `UNKNOWN`.
`UNPINNED` and `UNSIGNED_PROPOSAL` are visible states, not acceptance. A context for a new
boundary can be requested with `--proposal docs/contracts/proposals/<proposal>.proposal.json`.
The proposal must be staged so its bytes are included in the checkout snapshot.

The packet gives the statement, witness names and source files, a fixed local verification
command when supported, edit constraints and unknowns. It does not execute annotation text.
Mixed Rust witnesses from common/orchestrator use one fixed Cargo command for both packages.
Python and witnesses outside these supported Rust paths have no fixed native runner here;
the established CI tools remain their verifier. Kani proofs use `python3 scripts/proof-task.py context` and the
calibration runner in [VERIFICATION.md](VERIFICATION.md); a unit recipe cannot record them as passed. An unsupported runner refuses a run instead of issuing a pass.

## Execution and replay

```sh
python3 scripts/contract-task.py run IPC-A1
# prints a temporary directory containing report.json and output.log
python3 scripts/contract-task.py verify /tmp/sokol-witness-run-EXAMPLE/report.json
python3 scripts/contract-task.py verify /tmp/sokol-witness-run-EXAMPLE/report.json --replay
```

`run` invokes the existing std-only delivery verifier for delivery witnesses, or Linux Cargo
unit tests for orchestrator/common witness sets, including sets spanning both packages. Cargo first queries the compiler's
list, then executes its fully qualified names with exact filters. `{witness}` in the packet's
fixed template is used only for validated names. The commands must exit zero and every
compiled match of a requested witness must appear in successful test output. A zero-test
success, ignored/missing witness, or invented pass line without compiler metadata is
`RECORDED_FAIL`. Live GoBGP witnesses require the pinned fixture binaries
through `SOKOL_GOBGP_TEST_BIN`; the unit recipe does not certify XDP smoke or deployment.
For repeated Rust runs, use an absolute `CARGO_TARGET_DIR` pointing to the existing build
cache, and keep it the same for context/run/verify. The runner uses a child namespace keyed
by snapshot and configuration, rather than the root's mutable build artifacts. Without an
explicit cache each private copy builds its own target directory. The first run of each
namespace compiles dependencies; subsequent runs for the same inputs reuse it. The cache
and compiler dependencies remain external, declared unknowns; this is isolation from normal
cross-snapshot cache reuse, not authentication of cached artifacts.

Reports are unsigned local records. Offline `verify` checks that context, input digests and
configuration still match; execution remains `UNKNOWN`, even if the imported report says
`PASS`. `--replay` ignores the imported execution claim and runs the local fixed verifier
again. Only that fresh execution can yield `REPLAYED_PASS` or `REPLAYED_FAIL`. Neither proves
semantic adequacy of the statement. An old report after an implementation, helper, tracked
fixture, trust or configuration change is `STALE`. A run first copies the inventoried bytes
and executable modes into a private directory and revalidates its context/signature. The
verifier reads that frozen copy, so a transient edit to the working tree cannot feed different
code to it. The original inputs are checked again for freshness after the run.

## Snapshot and limits

The snapshot records SHA256 and executable bits of the tracked live checkout, including helpers and fixtures; this catches
more drift than owner-pinned witness bodies. It is a conservative input inventory, not a
proven dependency closure. Untracked/generated files, other environment variables, external
binaries, compiler dependencies and remote state remain outside it. The copy has a synthetic
Git index and no original commit history; production build identity is not established. The configuration records
system, architecture and digests of the explicitly listed environment entries. A passing
witness means its compiler-listed matches ran in this configuration, not that every
conditional compilation of its body or every possible topology was exercised.

Inputs refuse symlinks, files larger than 2 MiB, more than 4,096 tracked paths, or over 128 MiB
in aggregate. Verifier output is capped at 1 MiB and execution at 900 seconds; refusal signals
the local process group with SIGKILL and reaps the direct child. Children that start a separate session are outside that
cancellation mechanism. These limits bound retained input/output, not peak RSS or kernel
work. Oversized essential packets are refused, never silently trimmed. Reports and logs stay
outside the checkout to avoid a self-referential snapshot.

Owner signature validity is relative to the supplied signer file. By default its provenance
is `LOCAL_CHECKOUT`; for a separately trusted file, put `--signers /path/to/signers` before the
subcommand. The tool does not discover authority independently or accept/sign any proposal.
The invariant gate remains authoritative; this convenience tool cannot waive it.

`python3 scripts/test_contract_task.py` exercises forged green reports, stale helper/config
and inventory changes, missing/zero tests, imported commands, unsigned proposals, byte and
process-time limits. The real delivery command and Linux unit witnesses are separate runtime
checks; mocked test output in these regressions is not native execution evidence.
