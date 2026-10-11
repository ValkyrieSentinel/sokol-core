#!/usr/bin/env python3
"""context | run | verify REPORT [--replay]: Kani proofs challenged by broken implementations.

No imported commands execute. Matching unsigned reports establish bytes, never a past run.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('proof_task_inputs', ROOT / 'scripts/contract-task.py')
inputs_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs_tool)
encode, digest, read = inputs_tool.encode, inputs_tool.digest, inputs_tool.read
MAX_CASES = 16
MAX_PATCH_BYTES = 4096
MAX_CHECKS = 8192
MAX_RESULT_BYTES = 2_097_152
TOTAL_TIMEOUT = 1800
CATALOG = 'scripts/proof-challenges.json'
RECIPE = ['cargo', 'kani', '-p', 'common', '--force-build', '-Z', 'unstable-options']


def catalog(root):
    value = json.loads(read(root / CATALOG))
    if value.get('profile') != 'sokol.proof-challenges.v1' or value.get('authority') != 'UNSIGNED_NEGATIVE_CONTROLS':
        raise ValueError('Unsupported challenge catalog')
    cases = value['cases']
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError('Challenge count outside bound')
    ids, targets = set(), set()
    for case in cases:
        identity, file, harness = case['id'], case['file'], case['harness']
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', identity) or identity in ids:
            raise ValueError('Invalid or repeated challenge id')
        if not re.fullmatch(r'common/src/[a-z_]+\.rs', file):
            raise ValueError('Challenge must name a common source file')
        if not re.fullmatch(r'[a-z_]+::proofs::[a-z_]+', harness):
            raise ValueError('Invalid fully qualified proof name')
        if not isinstance(case['assertion'], str) or not case['assertion'].startswith('assertion failed: '):
            raise ValueError('Challenge must name an assertion, not a tool failure')
        if len(case['assertion'].encode()) > MAX_PATCH_BYTES:
            raise ValueError('Assertion description exceeds bound')
        before, after = case['replace']['before'], case['replace']['after']
        if not all(isinstance(s, str) and 0 < len(s.encode()) <= MAX_PATCH_BYTES for s in (before, after)) or before == after:
            raise ValueError('Invalid patch')
        source = read(root / file).decode()
        if source.count(before) != 1:
            raise ValueError('Patch anchor must occur exactly once: ' + identity)
        ids.add(identity)
        targets.add(harness)
    return cases, targets


def select_cases(root, challenge=None):
    cases, _ = catalog(root)
    if challenge is not None:
        cases = [c for c in cases if c['id'] == challenge]
        if not cases:
            raise ValueError('Unknown challenge')
    return cases, {c['harness'] for c in cases}


def context(root, challenge=None):
    files = inputs_tool.checkout(root)
    cases, targets = select_cases(root, challenge)
    required = {CATALOG, 'scripts/proof-task.py', 'scripts/contract-task.py'} | {c['file'] for c in cases}
    if not required.issubset(files):
        raise ValueError('Stage proof inputs before making a context')
    pin = re.search(r'^\s*KANI_VERSION: (\S+)\s*$', read(root / '.github/workflows/ci.yml').decode(), re.M)
    if not pin:
        raise ValueError('Missing Kani version pin')
    body = {'snapshot': 'sha256:' + digest(encode(files)), 'catalog_sha256': files[CATALOG]['sha256'],
            'configuration': inputs_tool.configuration(), 'kani_version': pin.group(1),
            'recipe': 'kani-calibration-v1', 'harnesses': sorted(targets),
            'selected_challenge': challenge,
            'inventory_scope': 'ALL_COMPILER_HARNESSES' if challenge is None else 'NAMED_HARNESS_ONLY',
            'challenges': cases, 'execution': 'UNKNOWN',
            'authority': 'UNSIGNED_NEGATIVE_CONTROLS',
            'scope': 'Assertions under the harness assumptions; sensitivity to the listed changes only'}
    packet = {'id': 'sha256:' + digest(encode(body)), 'body': body}
    if len(encode(packet)) > inputs_tool.MAX_PACKET_BYTES:
        raise ValueError('Context exceeds byte bound')
    if files != inputs_tool.checkout(root) or body['configuration'] != inputs_tool.configuration():
        raise ValueError('Inputs moved while making context')
    return packet, files


def results(value, expected, version):
    """Reject partial/foreign results, missing checks and indeterminate verifier outcomes."""
    if value['metadata']['version'] != '1.0' or value['metadata']['kani_version'] != version:
        raise ValueError('Unsupported Kani JSON/version')
    data = value['verification_results']
    summary = data['summary']
    if summary['status'] != 'completed' or summary['executed'] != len(expected) or summary['total_harnesses'] != len(expected):
        raise ValueError('Incomplete verifier execution')
    rows = data['results']
    if not isinstance(rows, list) or len(rows) != len(expected) or {r['harness_id'] for r in rows} != expected:
        raise ValueError('Harness inventory differs from challenge inventory')
    errors = value['error_details']
    if not isinstance(errors, list) or len(errors) != len(expected) or {e['harness_id'] for e in errors} != expected:
        raise ValueError('Missing verifier error metadata')
    if any(e['has_errors'] is not False and not (e['has_errors'] is True
            and e.get('error_type') == 'assertion_failure'
            and e.get('exit_status') == 'properties_failed') for e in errors):
        raise ValueError('Verifier resource or tool failure is not a counterexample')
    output = {}
    for row in rows:
        checks = row['checks']
        if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS:
            raise ValueError('Missing checks or check count outside bound')
        if row['status'] not in ('Success', 'Failure') or any(c['status'] not in ('Success', 'Failure', 'Unreachable') for c in checks):
            raise ValueError('Indeterminate checks are not proof')
        failures = [c for c in checks if c['status'] == 'Failure']
        if (row['status'] == 'Success') != (not failures):
            raise ValueError('Contradictory verifier result')
        output[row['harness_id']] = row
    if summary['successful'] != sum(r['status'] == 'Success' for r in rows) or summary['failed'] != sum(r['status'] == 'Failure' for r in rows):
        raise ValueError('Contradictory verifier summary')
    return output


def assertion_check(row, case, status):
    return any(c['category'] == 'assertion' and c['function'] == case['harness']
               and c['description'] == case['assertion'] and c['status'] == status for c in row['checks'])


def evaluate(value, cases, version, returncode, negative=None):
    expected = {negative['harness']} if negative else {c['harness'] for c in cases}
    rows = results(value, expected, version)
    if negative:
        row = rows[negative['harness']]
        failures = [c for c in row['checks'] if c['status'] == 'Failure']
        # Kani 0.68 exits 1 for a completed counterexample. Compiler crashes, OOM, unwind
        # failures and unrelated assertions do not qualify the method's claimed property.
        caught = returncode == 1 and assertion_check(row, negative, 'Failure') and all(
            c['category'] == 'assertion' and c['function'] == negative['harness'] for c in failures)
        return 'CAUGHT' if caught else 'NOT_CAUGHT'
    passed = returncode == 0 and all(r['status'] == 'Success' for r in rows.values()) and all(
        assertion_check(rows[c['harness']], c, 'Success') for c in cases)
    return 'PASS' if passed else 'FAIL'


def execute(root, packet, artifacts):
    import time
    if platform.system() != 'Linux':
        raise ValueError('Kani execution requires Linux')
    cases, targets = select_cases(root, packet['body']['selected_challenge'])
    version = packet['body']['kani_version']
    code, output = inputs_tool.run_bounded(root, ['cargo', 'kani', '--version'], timeout=20)
    if code or not re.search(r'\b' + re.escape(version) + r'\b', output.decode()):
        raise ValueError('Installed Kani differs from CI pin')
    deadline = time.monotonic() + TOTAL_TIMEOUT
    env = os.environ.copy()
    # This private, fixed target is never shared with another snapshot or caller cache.
    for name in ('CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET_DIR', 'CARGO_BUILD_BUILD_DIR'):
        env.pop(name, None)
    env['CARGO_TARGET_DIR'] = str(root / 'target')
    env['CARGO_BUILD_TARGET_DIR'] = env['CARGO_TARGET_DIR']
    env['CARGO_BUILD_BUILD_DIR'] = str(root / 'target/build')

    def run(name, case=None):
        export = artifacts / (name + '.kani.json')
        command = RECIPE + ['--export-json', str(export)]
        if not case and packet['body']['selected_challenge'] is not None:
            command += ['--exact', '--harness', cases[0]['harness']]
        if case:
            command += ['--exact', '--harness', case['harness'], '-Z', 'concrete-playback', '--concrete-playback', 'print']
        code, output = inputs_tool.run_bounded(root, command, timeout=max(0, deadline - time.monotonic()),
                                               bound=MAX_RESULT_BYTES, env=env)
        (artifacts / (name + '.log')).write_bytes(output)
        value = json.loads(read(export, MAX_RESULT_BYTES))
        status = evaluate(value, cases, version, code, case)
        return {'status': status, 'returncode': code, 'output_sha256': digest(output),
                'result_sha256': digest(read(export, MAX_RESULT_BYTES)), 'tools': value['tools']}

    baseline = run('baseline')
    outcomes = []
    if baseline['status'] == 'PASS':
        for case in cases:
            source = root / case['file']
            original = read(source)
            before, after = case['replace']['before'], case['replace']['after']
            source.write_text(original.decode().replace(before, after, 1))
            try:
                outcome = run(case['id'], case)
                outcomes.append({'id': case['id'], **outcome})
            finally:
                source.write_bytes(original)
    calibrated = baseline['status'] == 'PASS' and len(outcomes) == len(cases) and all(
        c['status'] == 'CAUGHT' and c['tools'] == baseline['tools'] for c in outcomes)
    return {'status': 'RECORDED_CALIBRATED' if calibrated else 'RECORDED_NOT_CALIBRATED',
            'baseline': baseline, 'challenges': outcomes, 'input_binding': 'HASH_CHECKED_PRIVATE_TRACKED_COPY'}


def make_report(root, artifacts, challenge=None):
    packet, files = context(root, challenge)
    with inputs_tool.copied_inputs(root, files) as private:
        execution = execute(private, packet, artifacts)
    fresh, fresh_files = context(root, challenge)
    if fresh != packet or fresh_files != files:
        execution['status'] = 'STALE'
    report = {'profile': 'sokol.agent.proof-run.v1', 'context': packet, 'inputs': files,
              'execution': execution, 'authenticity': 'UNSIGNED_LOCAL_REPORT'}
    if len(encode(report)) > MAX_RESULT_BYTES:
        raise ValueError('Essential report exceeds byte bound')
    return report


def verify(root, report, replay=False):
    if not isinstance(report, dict) or report.get('profile') != 'sokol.agent.proof-run.v1':
        raise ValueError('Unsupported proof report')
    challenge = report['context']['body']['selected_challenge']
    packet, files = context(root, challenge)
    if packet != report['context'] or files != report['inputs']:
        return {'binding': 'STALE', 'execution': 'UNKNOWN'}
    if not replay:
        return {'binding': 'MATCH', 'execution': 'UNKNOWN', 'historical_execution': 'UNVERIFIED'}
    artifacts = Path(tempfile.mkdtemp(prefix='sokol-proof-run-')).resolve()
    fresh = make_report(root, artifacts, challenge)
    (artifacts / 'report.json').write_bytes(encode(fresh) + b'\n')
    status = fresh['execution']['status']
    return {'binding': 'STALE' if status == 'STALE' else 'MATCH',
            'execution': {'RECORDED_CALIBRATED': 'REPLAYED_CALIBRATED',
                          'RECORDED_NOT_CALIBRATED': 'REPLAYED_NOT_CALIBRATED', 'STALE': 'UNKNOWN'}[status],
            'artifacts': str(artifacts), 'fresh_result': fresh['execution']}


def summary(report):
    body, execution = report['context']['body'], report['execution']
    return {'context_id': report['context']['id'], 'snapshot': body['snapshot'],
            'inventory_scope': body['inventory_scope'], 'execution': execution['status'],
            'baseline': execution['baseline']['status'],
            'challenges': [{'id': c['id'], 'status': c['status']} for c in execution['challenges']],
            'authenticity': 'UNSIGNED_LOCAL_REPORT', 'playback': 'NOT_EXECUTED',
            'scope': body['scope']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('context', 'run'):
        p = sub.add_parser(action)
        p.add_argument('--challenge')
    p = sub.add_parser('verify')
    p.add_argument('report', type=Path)
    p.add_argument('--replay', action='store_true')
    args = parser.parse_args()
    artifacts = None
    try:
        if args.action == 'context':
            value, _ = context(ROOT, args.challenge)
        elif args.action == 'run':
            artifacts = Path(tempfile.mkdtemp(prefix='sokol-proof-run-')).resolve()
            value = make_report(ROOT, artifacts, args.challenge)
            (artifacts / 'report.json').write_bytes(encode(value) + b'\n')
            essential = summary(value)
            (artifacts / 'summary.json').write_bytes(encode(essential) + b'\n')
            print(encode({'artifacts': str(artifacts), **essential}).decode())
            return 0 if value['execution']['status'] == 'RECORDED_CALIBRATED' else 1
        else:
            value = verify(ROOT, json.loads(read(args.report)), args.replay)
        print(encode(value).decode())
        return 1 if value.get('binding') == 'STALE' or value.get('execution') == 'REPLAYED_NOT_CALIBRATED' else 0
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        refusal = {'status': 'REFUSED', 'execution': 'UNKNOWN', 'reason': str(error)}
        if artifacts:
            (artifacts / 'refusal.json').write_bytes(encode(refusal) + b'\n')
            refusal['artifacts'] = str(artifacts)
        print(encode(refusal).decode(), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
