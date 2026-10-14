#!/usr/bin/env python3
"""Trusted pilot worker. Run only through counterexample-task.py's isolated profile."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

OUTPUT_BYTES = 1_048_576
COMMAND_SECONDS = 900
CASE_FILE = 'orchestrator/src/bin/sokol-operator.rs'
BEFORE = 'Err(error) if attempted_write => ControlOutcome::Unknown(error),'
AFTER = 'Err(error) if attempted_write => ControlOutcome::NotSent(error),'
FOCUS = 'a_command_applied_without_a_reply_has_an_unknown_outcome'
ASSERTION = 'lost reply cannot prove rejection:'
FRAME = 'SOKOL_WORKER_REPORT_V1 '
WITNESSES = (
    FOCUS, 'a_list_reply_reports_its_total_and_refuses_malformed_targets',
    'a_live_heartbeat_cannot_make_failed_ban_readback_fresh',
    'a_written_command_timeout_is_unknown_and_has_a_fixed_deadline',
    'ban_readback_age_is_independent_of_heartbeat_and_wall_time',
    'control_outcomes_require_an_exact_bounded_complete_reply',
    'late_readback_cannot_overwrite_a_new_attempt_or_route',
    'unread_and_invalid_lists_stay_unknown_then_recover',
)
MAX_SOURCE_FILES = 4096
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024


def source_snapshot(root=Path('/source')):
    files, total = {}, 0
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('SOURCE_SYMLINK')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('SOURCE_SPECIAL_FILE')
        with path.open('rb') as stream:
            data = stream.read(MAX_SOURCE_FILE_BYTES + 1)
        total += len(data)
        if len(data) > MAX_SOURCE_FILE_BYTES or total > MAX_SOURCE_BYTES or len(files) >= MAX_SOURCE_FILES:
            raise ValueError('SOURCE_BUDGET')
        files[path.relative_to(root).as_posix()] = {
            'sha256': hashlib.sha256(data).hexdigest(), 'executable': bool(path.stat().st_mode & 0o111)}
    canonical = json.dumps(files, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
    return hashlib.sha256(canonical).hexdigest()


def command(argv, cwd='/source'):
    p = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         start_new_session=True)
    output = bytearray()
    deadline = time.monotonic() + COMMAND_SECONDS
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout, selectors.EVENT_READ)
            while sel.get_map():
                if time.monotonic() >= deadline:
                    raise ValueError('TIME_BUDGET')
                if not sel.select(.2):
                    continue
                data = os.read(p.stdout.fileno(), min(65536, OUTPUT_BYTES + 1 - len(output)))
                if not data:
                    sel.unregister(p.stdout)
                    continue
                output.extend(data)
                if len(output) > OUTPUT_BYTES:
                    raise ValueError('OUTPUT_BUDGET')
        code = p.wait(timeout=max(.01, deadline - time.monotonic()))
        if code < 0:
            raise ValueError('NATIVE_SIGNAL_REFUSAL')
        return code, output.decode('utf-8', 'replace')
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        p.stdout.close()


def build(root):
    code, log = command(['/toolchain/bin/cargo', 'test', '--offline', '--locked',
                         '-p', 'orchestrator', '--bin', 'sokol-operator', '--no-run',
                         '--message-format=json'], cwd=root)
    paths = []
    for line in log.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get('reason') == 'compiler-artifact' and row.get('profile', {}).get('test'):
            exe = row.get('executable')
            if exe and row.get('target', {}).get('name') == 'sokol-operator':
                paths.append(exe)
    if code or len(paths) != 1:
        return None, {'status': 'BUILD_ERROR', 'returncode': code, 'output': log}
    path = Path(paths[0]).resolve()
    if not path.is_relative_to('/target') or not path.is_file():
        raise ValueError('EXECUTABLE_OUTSIDE_TARGET')
    return str(path), {'status': 'BUILT', 'returncode': code, 'output': log,
                       'executable_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def classify(code, output, witness, defect=False):
    name = 'tests::' + witness
    # The signed witness assertion is the scope. Never infer a counterexample from
    # nonzero status alone, a compiler failure, an empty filter or fixture failure.
    if defect:
        if (code == 101 and f'test {name} ... FAILED' in output
                and ASSERTION in output and 'assertion `left == right` failed' in output
                and '1 failed' in output and '0 passed' in output):
            return 'ASSERTION_RED'
        return 'NOT_REPRODUCED'
    if code == 0 and f'test {name} ... ok' in output and '1 passed' in output and '0 failed' in output:
        return 'PASS'
    return 'FAIL'


def phase(label, defect=False):
    root = Path('/defect') if defect else Path('/source')
    snapshot = source_snapshot(root)
    exe, compilation = build(root)
    if source_snapshot(root) != snapshot:
        raise ValueError('SOURCE_MOVED_DURING_BUILD')
    result = {'phase': label, 'snapshot': snapshot, 'build': compilation, 'witnesses': []}
    if not exe:
        return result
    for witness in ((FOCUS,) if defect else WITNESSES):
        code, output = command([exe, 'tests::' + witness, '--exact', '--nocapture', '--color', 'never'], cwd=root)
        if source_snapshot(root) != snapshot:
            raise ValueError('SOURCE_MOVED_DURING_TEST')
        result['witnesses'].append({'witness': witness, 'returncode': code,
                                    'status': classify(code, output, witness, defect), 'output': output})
    return result


def main():
    try:
        original = (Path('/source') / CASE_FILE).read_bytes().decode()
        mutated = (Path('/defect') / CASE_FILE).read_bytes().decode()
        if original.count(BEFORE) != 1 or mutated != original.replace(BEFORE, AFTER):
            raise ValueError('MUTATION_ANCHOR')
        repair = phase('repair')
        defect = phase('defect', True)
        restored = phase('restored')
        report = {'profile': 'sokol.counterexample-execution.v1', 'phases': [repair, defect, restored]}
        success = all(p['build']['status'] == 'BUILT' and p['build']['returncode'] == 0
                      and len(p['witnesses']) == (1 if p['phase'] == 'defect' else len(WITNESSES))
                      and all(r['status'] == ('ASSERTION_RED' if p['phase'] == 'defect' else 'PASS')
                              for r in p['witnesses']) for p in report['phases'])
        code = 0 if success else 1
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        report = {'profile': 'sokol.counterexample-execution.v1', 'refusal': str(error), 'phases': []}
        code = 3
    print(FRAME + json.dumps(report, sort_keys=True, separators=(',', ':')))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
