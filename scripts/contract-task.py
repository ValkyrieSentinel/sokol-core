#!/usr/bin/env python3
"""Bounded contract context and local witness execution; reports require replay for trust.

context ID [--proposal FILE]   read only; native execution UNKNOWN
run ID [--proposal FILE]       local fixed runner; retains a report outside the checkout
verify REPORT [--replay]       input correspondence only, or a fresh independent execution

The signed gate remains the owner of normalization and signature checks. This tool never
accepts a proposal, signs, imports a recipe from annotations or declares a statement proved.
"""
import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 2_097_152
MAX_FILES = 4096
MAX_CHECKOUT_BYTES = 128 * 1024 * 1024
MAX_OUTPUT_BYTES = 1_048_576
MAX_PACKET_BYTES = 16_384
RUN_TIMEOUT = 900
RECIPES = {
    'delivery': ['bash', 'scripts/check-delivery.sh'],
    'orchestrator-unit': ['cargo', 'test', '--release', '--locked', '-p', 'orchestrator', '--bins', '{witness}', '--', '--color', 'never'],
    'common-unit': ['cargo', 'test', '--release', '--locked', '-p', 'common', '--lib', '{witness}', '--', '--color', 'never'],
}


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read(path, bound=MAX_FILE_BYTES):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink input refused: ' + str(path))
    with path.open('rb') as stream:
        data = stream.read(bound + 1)
    if len(data) > bound:
        raise ValueError('Input exceeds byte bound: ' + str(path))
    return data


def run_bounded(root, command, timeout=RUN_TIMEOUT, bound=MAX_OUTPUT_BYTES, env=None):
    """Retain at most bound+1 bytes; signal the process group and reap the direct child."""
    process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True, env=env)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Verifier exceeded time bound')
                if not selector.select(min(remaining, 1)):
                    continue
                data = os.read(process.stdout.fileno(), min(65536, bound + 1 - len(output)))
                if not data:
                    selector.unregister(process.stdout)
                    continue
                output.extend(data)
                if len(output) > bound:
                    raise ValueError('Verifier exceeded output bound')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Verifier exceeded time bound')
        return process.wait(timeout=remaining), bytes(output)
    finally:
        # End this verifier's process group, also on a normal exit. Children that created
        # a separate session are outside this cancellation mechanism.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()


def checkout(root):
    status, data = run_bounded(root, ['git', 'ls-files', '-z'], timeout=10)
    if status:
        raise ValueError('Cannot enumerate checkout')
    names = sorted(set(x.decode('utf-8') for x in data.split(b'\0') if x))
    if len(names) > MAX_FILES:
        raise ValueError('Checkout exceeds file count bound')
    hashes, size = {}, 0
    for name in names:
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or '.git' in path.parts:
            raise ValueError('Invalid checkout path')
        value = read(root / path)
        size += len(value)
        if size > MAX_CHECKOUT_BYTES:
            raise ValueError('Checkout exceeds aggregate byte bound')
        hashes[name] = {'sha256': digest(value), 'executable': bool((root / path).stat().st_mode & 0o111)}
    return hashes


@contextmanager
def copied_inputs(root, inputs):
    """Freeze exactly the inventoried bytes/modes, then verify this private copy again."""
    with tempfile.TemporaryDirectory(prefix='sokol-witness-inputs-') as directory:
        work = Path(directory).resolve()
        for name, expected in inputs.items():
            source = root / name
            value = read(source)
            executable = bool(source.stat().st_mode & 0o111)
            if digest(value) != expected['sha256'] or executable != expected['executable']:
                raise ValueError('Inputs moved while copying verifier snapshot')
            target = work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
            target.chmod(0o755 if executable else 0o644)
        for command in (['git', 'init', '-q'], ['git', 'add', '-f', '--', *inputs]):
            status, _ = run_bounded(work, command, timeout=10)
            if status:
                raise ValueError('Cannot index verifier snapshot')
        yield work


def checker(root):
    spec = importlib.util.spec_from_file_location('contract_task_pin', root / 'scripts/witness-pin.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configuration():
    # Other environment and generated/untracked inputs are outside the declared closure.
    keys = ('SOKOL_GOBGP_TEST_BIN', 'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET_DIR', 'CARGO_BUILD_BUILD_DIR',
            'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
            'RUSTUP_TOOLCHAIN', 'CARGO_HOME', 'RUSTUP_HOME', 'PATH', 'SOKOL_BUILD_ID',
            'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUST_TEST_THREADS',
            'RUST_TEST_NOCAPTURE', 'PROPTEST_CASES', 'PROPTEST_RNG_SEED', 'PROPTEST_RNG_ALGORITHM')
    return {'system': platform.system(), 'machine': platform.machine(),
            'environment_sha256': {k: digest(os.environ.get(k, '').encode()) for k in keys}}


def prepare(root, rid, signers=None, proposal=None):
    pin = checker(root)
    pin.contract_marker(rid)
    hashes = checkout(root)
    contract = pin.load_contracts(root).get(rid)
    source = f'docs/contracts/{rid}.shadow.json'
    if proposal:
        source = Path(proposal).as_posix()
        if not re.fullmatch(r'docs/contracts/proposals/[A-Z0-9-]+-[0-9a-f]{12}\.proposal\.json', source):
            raise ValueError('Proposal must be a local proposal path')
        contract = json.loads(read(root / source))
        if contract.get('id') != rid or contract.get('status') != 'UNSIGNED_INTENT':
            raise ValueError('Invalid proposal identity or status')
    if not contract:
        raise ValueError('Unknown contract')
    if source not in hashes:
        raise ValueError('Stage the contract/proposal before making a reproducible context')
    trust = Path(signers).resolve() if signers else root / '.github/witness-signers'
    trust_bytes = read(trust)
    manifest_bytes = read(root / 'docs/witness-manifest.json')
    signature_bytes = read(root / 'docs/witness-manifest.json.sig')
    for name, value in [('docs/witness-manifest.json', manifest_bytes),
                        ('docs/witness-manifest.json.sig', signature_bytes)]:
        if hashes.get(name, {}).get('sha256') != digest(value):
            raise ValueError('Signed inputs moved during projection')
    # Verify exactly the declared bytes, also for an external signer file. A moving
    # path cannot make a signature valid under a different, transient trust file.
    with tempfile.TemporaryDirectory(prefix='sokol-contract-signature-') as directory:
        paths = [Path(directory) / name for name in ('manifest', 'signature', 'signers')]
        for path, data in zip(paths, (manifest_bytes, signature_bytes, trust_bytes)):
            path.write_bytes(data)
        if not pin.verify_manifest(*paths):
            raise ValueError('Owner signature verification failed')
    # Use exactly the gate's public current representation. It also validates the generated
    # projection; no row or hash implementation lives here.
    current_rows = pin.rows()
    current_contracts = pin.contract_pins(root)
    manifest = json.loads(manifest_bytes)
    witnesses = contract['witnesses']
    if not isinstance(witnesses, list) or not witnesses or len(witnesses) > 256:
        raise ValueError('Invalid witness set')
    body_locations = {}
    rust = {w for w in witnesses if pin.RUST_TEST.fullmatch(w)}
    candidate = re.compile(r'\bfn\s+(?:' + '|'.join(re.escape(w) for w in sorted(rust)) + r')\s*[(<]') if rust else None
    for name in hashes:
        if name.endswith('.rs') and candidate:
            text = read(root / name).decode()
            if not candidate.search(text):
                continue
            found = pin.rust_witness_hashes(text, name, rust)
            for witness, locations in found.items():
                body_locations.setdefault(witness, []).extend(locations)
    python = pin.py_bodies({w for w in witnesses if pin.PY_TEST.fullmatch(w)}) if any(
        pin.PY_TEST.fullmatch(w) for w in witnesses) else {}
    for witness in witnesses:
        if pin.PY_TEST.fullmatch(witness):
            body_locations[witness] = python.get(witness, [])
        if not body_locations.get(witness):
            raise ValueError('Missing witness body: ' + witness)
    correspondence = 'UNSIGNED_PROPOSAL' if proposal else 'UNPINNED'
    if not proposal and rid in manifest['rows']:
        if current_rows[rid] != manifest['rows'][rid] or any(
                sorted(body_locations[w]) != manifest['witnesses'].get(w) for w in witnesses):
            raise ValueError('Selected contract or witness differs from owner pin')
        if current_contracts[rid] != manifest.get('contracts', {}).get(rid):
            raise ValueError('Selected contract history differs from owner pin')
        correspondence = 'MATCH'
    files = sorted({location.rsplit(':', 1)[0] for v in body_locations.values() for location in v})
    if all(file == 'orchestrator/src/delivery.rs' for file in files):
        recipe = 'delivery'
    elif all(file.startswith('orchestrator/src/') for file in files) and not any('.' in w for w in witnesses):
        recipe = 'orchestrator-unit'
    elif all(file.startswith('common/src/') for file in files) and not any('.' in w for w in witnesses):
        recipe = 'common-unit'
    else:
        recipe = None
    config = configuration()
    body = {'profile': 'sokol.agent.contract-task.v1', 'contract_id': rid, 'source': source,
            'statement': contract['statement'], 'witnesses': witnesses, 'witness_files': files,
            'binding': {'owner_signature': 'VERIFIED_AGAINST_SUPPLIED_SIGNERS',
                        'signers_sha256': digest(trust_bytes),
                        'signer_provenance': 'CALLER_SUPPLIED' if signers else 'LOCAL_CHECKOUT',
                        'correspondence': correspondence,
                        'annotations': 'UNSIGNED', 'proposal_acceptance': 'NOT_ESTABLISHED'},
            'snapshot': 'sha256:' + digest(encode(hashes)), 'tracked_files': len(hashes),
            'configuration': config, 'recipe': recipe, 'command': RECIPES.get(recipe),
            'execution': 'UNKNOWN', 'semantic_adequacy': 'NOT_ESTABLISHED',
            'execution_policy': 'REVALIDATE_AND_RUN_HASH_CHECKED_PRIVATE_TRACKED_COPY',
            'edit_rule': 'Fixes start with an assertion-red counterexample. Preserve pinned witnesses; changing a boundary requires an owner proposal and signature.',
            'unknowns': ['Helper completeness and untracked/generated/external inputs are not established.',
                         'A matching signed body does not prove its statement or a kernel/remote effect.',
                         'Recorded reports are unsigned and untrusted; offline verification does not establish execution.',
                         'Execution covers named unit witnesses; Kani, full CI and deployment qualification remain separate.']}
    body['cargo_cache_policy'] = 'SNAPSHOT_CONFIGURATION_NAMESPACE_OR_PRIVATE_TARGET'
    packet = {'id': 'sha256:' + digest(encode(body)), 'body': body}
    if len(encode(packet)) > MAX_PACKET_BYTES:
        raise ValueError('Essential context exceeds packet bound')
    if checkout(root) != hashes or read(trust) != trust_bytes or configuration() != config:
        raise ValueError('Inputs moved during context generation')
    return packet, hashes


def execute(root, packet):
    body = packet['body']
    recipe = body['recipe']
    if recipe not in RECIPES or body['command'] != RECIPES[recipe]:
        raise ValueError('No supported fixed witness runner')
    if recipe != 'delivery' and platform.system() != 'Linux':
        raise ValueError('Rust verification requires Linux')
    if any(w.startswith('live_gobgp_') for w in body['witnesses']) and not os.environ.get('SOKOL_GOBGP_TEST_BIN'):
        raise ValueError('Live GoBGP witnesses require the pinned fixture binaries')
    if not body['witnesses'] or not all(re.fullmatch(r'[a-z][a-z0-9_]*', w) for w in body['witnesses']):
        raise ValueError('Invalid witness filter')
    deadline = time.monotonic() + RUN_TIMEOUT
    output = bytearray()
    status = 0
    passed_counts = Counter()
    compiled_counts = Counter()
    rejected = set()
    runner_env = os.environ.copy()
    if recipe != 'delivery' and runner_env.get('CARGO_TARGET_DIR'):
        cache = Path(runner_env['CARGO_TARGET_DIR'])
        if not cache.is_absolute():
            raise ValueError('Witness cache requires an absolute CARGO_TARGET_DIR')
        namespace = digest(encode({'snapshot': body['snapshot'], 'configuration': body['configuration']}))
        runner_env['CARGO_TARGET_DIR'] = str(cache / 'sokol-contract-task' / namespace)
        runner_env['CARGO_BUILD_TARGET_DIR'] = runner_env['CARGO_TARGET_DIR']
        runner_env['CARGO_BUILD_BUILD_DIR'] = str(Path(runner_env['CARGO_TARGET_DIR']) / 'build')
    elif recipe != 'delivery':
        runner_env['CARGO_TARGET_DIR'] = str(root / 'target')
        runner_env['CARGO_BUILD_TARGET_DIR'] = runner_env['CARGO_TARGET_DIR']
        runner_env['CARGO_BUILD_BUILD_DIR'] = str(root / 'target/build')

    def run(command):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Verifier exceeded total time bound')
        code, text = run_bounded(root, command, timeout=remaining,
                                 bound=MAX_OUTPUT_BYTES - len(output), env=runner_env)
        output.extend(text)
        return code, text

    def listed(text):
        return Counter(name.decode() for name in re.findall(rb'^([A-Za-z0-9_:]+): test$', text, re.M))

    def passed(text):
        return Counter(name.decode() for name in re.findall(rb'^test ([A-Za-z0-9_:]+) \.\.\. ok$', text, re.M))

    def ignored(text):
        return {name.decode() for name in re.findall(rb'^test ([A-Za-z0-9_:]+) \.\.\. ignored\b', text, re.M)}

    if recipe == 'delivery':
        status, text = run(RECIPES[recipe])
        compiled = listed(text)
        successes = passed(text)
        for witness in body['witnesses']:
            matches = {name: n for name, n in compiled.items() if name.rsplit('::', 1)[-1] == witness}
            compiled_counts[witness] = sum(matches.values())
            passed_counts[witness] = sum(successes[name] for name in matches)
            if not matches or any(successes[name] != n or name in ignored(text) for name, n in matches.items()):
                rejected.add(witness)
    else:
        for witness in body['witnesses']:
            command = [witness if arg == '{witness}' else arg for arg in RECIPES[recipe]]
            status, listing = run(command[:-3] + ['--', '--list', '--format', 'terse', '--color', 'never'])
            matches = {name: n for name, n in listed(listing).items() if name.rsplit('::', 1)[-1] == witness}
            compiled_counts[witness] = sum(matches.values())
            if status or not matches:
                rejected.add(witness)
                break
            # Use the compiler's full names and exact filters. A similarly named helper
            # cannot print an invented successful line in place of a missing witness.
            for name, expected in sorted(matches.items()):
                exact = [name if arg == '{witness}' else arg for arg in RECIPES[recipe]]
                status, text = run(exact[:-3] + ['--', '--exact', '--color', 'never'])
                observed = passed(text)[name]
                passed_counts[witness] += observed
                if status or observed != expected or name in ignored(text):
                    rejected.add(witness)
                    break
            if rejected:
                break
    output = bytes(output)
    missing = sorted({w for w in body['witnesses'] if not passed_counts[w]} | rejected)
    result = 'RECORDED_PASS' if status == 0 and not missing else 'RECORDED_FAIL'
    return {'status': result, 'returncode': status, 'missing_witnesses': missing,
            'named_pass_counts': {w: passed_counts[w] for w in body['witnesses']},
            'compiled_match_counts': {w: compiled_counts[w] for w in body['witnesses']},
            'output_sha256': digest(output)}, output


def make_report(root, rid, signers=None, proposal=None):
    packet, inputs = prepare(root, rid, signers, proposal)
    with copied_inputs(root, inputs) as work:
        frozen, frozen_inputs = prepare(work, rid, signers, proposal)
        if frozen != packet or frozen_inputs != inputs:
            raise ValueError('Private verifier snapshot differs from context')
        execution, output = execute(work, frozen)
        execution['input_binding'] = 'HASH_CHECKED_PRIVATE_TRACKED_COPY'
    after, after_inputs = prepare(root, rid, signers, proposal)
    if after != packet or after_inputs != inputs:
        execution['status'] = 'STALE'
    report = {'profile': 'sokol.agent.witness-run.v1', 'context': packet,
              'inputs': inputs, 'execution': execution, 'authenticity': 'UNSIGNED_LOCAL_REPORT'}
    if len(encode(report)) > MAX_FILE_BYTES:
        raise ValueError('Essential report exceeds byte bound')
    return report, output


def verify_report(root, report, signers=None, replay=False):
    if not isinstance(report, dict) or report.get('profile') != 'sokol.agent.witness-run.v1':
        raise ValueError('Unsupported report profile')
    old = report['context']
    if not isinstance(old, dict) or not isinstance(old.get('body'), dict):
        raise ValueError('Invalid report context')
    body = old['body']
    if not isinstance(body.get('binding'), dict):
        raise ValueError('Invalid report binding')
    proposal = body['source'] if body['binding']['correspondence'] == 'UNSIGNED_PROPOSAL' else None
    packet, inputs = prepare(root, body['contract_id'], signers, proposal)
    if packet != old or inputs != report['inputs']:
        return {'binding': 'STALE', 'execution': 'UNKNOWN'}
    if not replay:
        return {'binding': 'MATCH', 'execution': 'UNKNOWN', 'historical_execution': 'UNVERIFIED',
                'reason': 'Matching bytes and an unsigned report cannot establish a past run'}
    # Ignore every execution claim and command in the imported report; rerun our fixed recipe.
    fresh, _ = make_report(root, body['contract_id'], signers, proposal)
    return {'binding': 'MATCH' if fresh['execution']['status'] != 'STALE' else 'STALE',
            'execution': {'RECORDED_PASS': 'REPLAYED_PASS', 'RECORDED_FAIL': 'REPLAYED_FAIL',
                          'STALE': 'UNKNOWN'}[fresh['execution']['status']],
            'fresh_result': fresh['execution']}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--signers', type=Path)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('context', 'run'):
        p = sub.add_parser(action)
        p.add_argument('id')
        p.add_argument('--proposal')
    p = sub.add_parser('verify')
    p.add_argument('report', type=Path)
    p.add_argument('--replay', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'context':
            value, _ = prepare(ROOT, args.id, args.signers, args.proposal)
        elif args.action == 'run':
            value, output = make_report(ROOT, args.id, args.signers, args.proposal)
            directory = Path(tempfile.mkdtemp(prefix='sokol-witness-run-')).resolve()
            (directory / 'report.json').write_bytes(encode(value) + b'\n')
            (directory / 'output.log').write_bytes(output)
            print(directory)
            return 0 if value['execution']['status'] == 'RECORDED_PASS' else 1
        else:
            value = verify_report(ROOT, json.loads(read(args.report)), args.signers, args.replay)
        print(encode(value).decode())
        return 0 if value.get('binding') != 'STALE' and value.get('execution') != 'REPLAYED_FAIL' else 1
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'REFUSED', 'execution': 'UNKNOWN', 'reason': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
