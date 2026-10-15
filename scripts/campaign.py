#!/usr/bin/env python3
"""Launch a bounded 24h -> 72h mesh experiment on a disposable systemd VM only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
HOURS = (24, 72)


def write(path, value):
    staged = path.with_suffix('.staged')
    staged.write_text(json.dumps(value, indent=2) + '\n')
    staged.replace(path)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            value.update(chunk)
    return value.hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(ROOT), *args], cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--monitor', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if platform.system() != 'Linux' or os.geteuid() != 0:
        parser.error('root on a disposable Linux systemd VM is required')
    vm = subprocess.run(['systemd-detect-virt', '--vm'], capture_output=True, text=True)
    if vm.returncode != 0:
        parser.error('a VM must be detected; physical hosts and containers are refused')
    args.binary = args.binary.resolve(strict=True)
    args.monitor = args.monitor.resolve(strict=True)
    args.output = args.output.resolve()
    if not args.worker:
        if git('status', '--porcelain'):
            parser.error('commit the experiment source first')
        args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        unit = 'sokol-campaign-' + str(time.time_ns())
        receipt = {'profile': 'sokol.vm-campaign.v1', 'status': 'LAUNCHING', 'unit': unit,
                   'source_commit': git('rev-parse', 'HEAD'),
                   'bench_sha256': digest(ROOT / 'bench/mesh.sh'),
                   'binary_sha256': digest(args.binary), 'monitor_sha256': digest(args.monitor),
                   'vm': vm.stdout.strip(), 'seed': 1729, 'hours': HOURS,
                   'limits': {'memory_bytes': 4294967296, 'tasks': 256, 'cpu_percent': 200,
                              'tmp_bytes': 4294967296, 'file_bytes': 134217728,
                              'runtime_seconds': 96 * 3600 + 1800},
                   'admission': 'NOT_ADMITTED', 'hardware': 'NOT_QUALIFIED',
                   'scope': 'existing mesh soak assertions; RSS growth is observed, not an accepted SLO',
                   'phases': []}
        write(args.output / 'report.json', receipt)
        command = ['systemd-run', '--unit=' + unit, '--collect',
                   '--property=MemoryMax=4G', '--property=TasksMax=256', '--property=CPUQuota=200%',
                   '--property=RuntimeMaxSec=' + str(96 * 3600 + 1800),
                   '--property=LimitFSIZE=128M', '--property=PrivateTmp=yes',
                   '--property=TemporaryFileSystem=/tmp:rw,size=4G,mode=1777',
                   sys.executable, str(Path(__file__).resolve()), '--worker',
                   '--binary', str(args.binary), '--monitor', str(args.monitor), '--output', str(args.output)]
        result = subprocess.run(command)
        if result.returncode:
            receipt['status'] = 'LAUNCH_FAILED'; write(args.output / 'report.json', receipt)
        print(json.dumps({'unit': unit, 'report': str(args.output / 'report.json'),
                          'launch_returncode': result.returncode,
                          'status': 'SUBMITTED_TO_SYSTEMD' if not result.returncode else 'LAUNCH_FAILED'}))
        return result.returncode
    path = args.output / 'report.json'
    receipt = json.loads(path.read_text())
    if digest(args.binary) != receipt['binary_sha256'] or digest(args.monitor) != receipt['monitor_sha256']:
        receipt['status'] = 'REFUSED_CHANGED_BINARY'; write(path, receipt); return 1
    # Privileged experiment, not a sandbox for untrusted native code. A hard cgroup kill
    # can prevent this write; a remaining RUNNING receipt then requires systemd readback.
    for hours in HOURS:
        if git('rev-parse', 'HEAD') != receipt['source_commit'] or digest(ROOT / 'bench/mesh.sh') != receipt['bench_sha256']:
            receipt['status'] = 'REFUSED_CHANGED_EXPERIMENT'; write(path, receipt); return 1
        out = args.output / str(hours); out.mkdir(mode=0o700)
        phase = {'hours': hours, 'status': 'RUNNING', 'started_unix': time.time()}
        receipt['phases'].append(phase); receipt['status'] = 'RUNNING'; write(path, receipt)
        with (out / 'console.log').open('wb') as log:
            result = subprocess.run(['bash', str(ROOT / 'bench/mesh.sh'), 'soak',
                                     str(args.binary), str(args.monitor), '3', str(hours * 60)],
                                    cwd=ROOT, env={**os.environ, 'BENCH_OUT': str(out), 'BENCH_SEED': '1729'},
                                    stdout=log, stderr=subprocess.STDOUT)
        phase.update(status='LIMITED_PASS' if result.returncode == 0 else 'FAILED',
                     returncode=result.returncode, finished_unix=time.time())
        write(path, receipt)
        if result.returncode:
            receipt['status'] = 'FAILED'; write(path, receipt); return 1
    receipt['status'] = 'LIMITED_PASS'; write(path, receipt)
    return 0


if __name__ == '__main__': raise SystemExit(main())
