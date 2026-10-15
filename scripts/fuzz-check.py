#!/usr/bin/env python3
"""Two bounded native libFuzzer targets and real production-fault controls; no imported commands."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from support_bundle import capture

ROOT = Path(__file__).resolve().parents[1]
FAULTS = {
    'wire': ('common/src/wire.rs', '.split_at_checked(payload_len)', '.split_at_checked(0)', 'payload'),
    'canonical': ('common/src/canonical.rs', 'return Err(CanonicalError::DuplicateKey);', 'return Ok(());', 'object'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 300:
        parser.error('seconds must be 1..300 per baseline target')
    version = subprocess.check_output(['cargo', 'fuzz', '--version'], text=True).strip()
    if version != 'cargo-fuzz 0.13.2':
        parser.error('install cargo-fuzz 0.13.2 with --locked first')
    out = args.output.resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = subprocess.check_output(['git', 'ls-files', '-z', 'common', 'fuzz'], cwd=ROOT).decode().split('\0')
    files = [p for p in files if p]
    if len(files) > 256:
        parser.error('too many fuzz inputs')
    report = {'profile': 'sokol.native-fuzz.v1', 'status': 'RUNNING', 'tool': version,
              'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'inputs': {}, 'cases': [], 'authority': 'EXPERIMENT_NOT_ACCEPTANCE',
              'limits': {'input_bytes': 16384, 'rss_mb': 1024, 'log_bytes_per_case': 2097152,
                         'baseline_seconds_per_target': args.seconds, 'seed': 1729},
              'scope': 'framing/partition and duplicate-key checks; canonical target is not a full JSON validator proof'}
    with tempfile.TemporaryDirectory(prefix='sokol-fuzz-') as directory:
        tree = Path(directory); total = 0
        for rel in files:
            path = ROOT / rel
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1048576:
                parser.error('unsafe or oversized fuzz input')
            data = path.read_bytes(); total += len(data)
            if total > 8388608:
                parser.error('fuzz input copy exceeds 8 MiB')
            report['inputs'][rel] = hashlib.sha256(data).hexdigest()
            dest = tree / rel; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(data)
        lock = tree / 'fuzz/Cargo.lock'; original_lock = lock.read_bytes()
        for target, (rel, before, after, seed) in FAULTS.items():
            corpus = out / (target + '-corpus'); corpus.mkdir()
            crashes = out / (target + '-crashes'); crashes.mkdir()
            for control in (False, True):
                path = tree / rel; original = path.read_text()
                if control:
                    if before not in original:
                        parser.error('fault anchor absent')
                    path.write_text(original.replace(before, after, 1))
                selected = [str(tree / 'fuzz/seeds' / target / seed)] if control else [str(corpus), str(tree / 'fuzz/seeds' / target)]
                command = ['cargo', 'fuzz', 'run', '--fuzz-dir', 'fuzz', target, *selected, '--',
                           '-max_total_time=' + str(1 if control else args.seconds), '-max_len=16384',
                           '-timeout=5', '-rss_limit_mb=1024', '-seed=1729', '-verbosity=0',
                           '-artifact_prefix=' + str(crashes) + '/']
                result = capture(command, seconds=600, bound=2097152, cwd=tree)
                path.write_text(original)
                label = target + ('-fault' if control else '-baseline')
                (out / (label + '.log')).write_text(result.pop('output'))
                log = (out / (label + '.log')).read_text()
                complete = result['status'] == 'COMPLETE' and lock.read_bytes() == original_lock
                ok = complete and (result['returncode'] != 0 and 'assertion `left == right` failed' in log
                                   if control else result['returncode'] == 0)
                report['cases'].append({'case': label, **result, 'command': command,
                                        'result': ('CAUGHT' if control else 'PASS') if ok else 'UNCONFIRMED'})
                (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        report['status'] = 'CALIBRATED_RUN' if all(c['result'] != 'UNCONFIRMED' for c in report['cases']) else 'UNCONFIRMED'
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(out / 'report.json'), 'status': report['status']}))
    return 0 if report['status'] == 'CALIBRATED_RUN' else 1


if __name__ == '__main__': raise SystemExit(main())
