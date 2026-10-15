#!/usr/bin/env python3
"""Private, bounded diagnostics; raw node keys/state/audit are never read here."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

MAX_OUTPUT = 131_072
MAX_TOTAL = 2_097_152
COMMAND_SECONDS = 5
TOTAL_SECONDS = 60


def capture(argv, seconds=COMMAND_SECONDS, bound=MAX_OUTPUT):
    start = time.monotonic()
    try:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    except OSError as error:
        return {'status': 'UNAVAILABLE', 'returncode': None, 'output': str(error)}
    output, state = bytearray(), 'COMPLETE'
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                left = seconds - (time.monotonic() - start)
                if left <= 0:
                    state = 'TIME_LIMIT'; break
                if not selector.select(min(left, .1)):
                    continue
                data = os.read(child.stdout.fileno(), min(65536, bound + 1 - len(output)))
                if not data:
                    selector.unregister(child.stdout); continue
                output.extend(data)
                if len(output) > bound:
                    state = 'OUTPUT_LIMIT'; break
        if state == 'COMPLETE':
            try: child.wait(timeout=max(.001, seconds - (time.monotonic() - start)))
            except subprocess.TimeoutExpired: state = 'TIME_LIMIT'
    finally:
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        try: child.wait(timeout=1)
        except subprocess.TimeoutExpired: state = 'CLEANUP_UNKNOWN'
        child.stdout.close()
    return {'status': state, 'returncode': child.returncode,
            'output': bytes(output[:bound]).decode('utf-8', 'replace'),
            'partial': len(output) > bound or state != 'COMPLETE'}


def commands():
    get = os.environ.get
    metrics = get('METRICS', 'http://127.0.0.1:9469/metrics')
    return {
        'system.txt': ['uname', '-a'],
        'version.txt': [get('BIN', '/usr/local/bin/sokol-orchestrator'), '--version'],
        'binary.txt': ['sha256sum', get('BIN', '/usr/local/bin/sokol-orchestrator')],
        'systemd.txt': ['systemctl', 'status', '--no-pager', get('UNIT', 'sokol-orchestrator')],
        'journal.txt': ['journalctl', '-u', get('UNIT', 'sokol-orchestrator'), '--no-pager', '-n', '3000'],
        'metrics.txt': ['curl', '-fsS', '--max-time', '5', metrics],
        'status.txt': ['curl', '-fsS', '--max-time', '5', metrics.removesuffix('/metrics') + '/status'],
        'audit-verify.txt': [get('MONITOR', '/usr/local/bin/sokol-monitor'), '--verify', get('AUDIT', '/var/lib/sokol/audit.log')],
        'links.txt': ['ip', '-d', 'link', 'show'],
        'bpf.txt': ['bpftool', 'prog', 'show'],
        'bans.txt': [sys.executable, '-c',
                     'import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(2); '
                     's.connect(sys.argv[1]); s.sendall(b"LIST_BANS\\n"); '
                     'data=s.recv(131073); sys.stdout.buffer.write(data); '
                     'raise SystemExit(0 if data.endswith(b"\\n") else 3)',
                     get('CONTROL', '/run/sokol/control.sock')],
        'peers.txt': [sys.executable, '-c',
                      'import json,sys; f=open(sys.argv[1],"rb"); data=f.read(524289); '
                      'assert len(data)<=524288; rows=json.loads(data); assert len(rows)<=4096; '
                      'print("\\n".join(str(r.get("node_id"))+" ML-DSA-key-configured="+'
                      'str(bool(r.get("public_key") or r.get("public_keys"))) for r in rows))',
                      get('PEERS', '/etc/sokol/peers.json')],
    }


def collect(output):
    os.umask(0o077)
    started = time.monotonic()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = output.resolve(strict=True)
    archive = output / ('sokol-support-' + stamp + '-' + os.urandom(3).hex() + '.tar.gz')
    with tempfile.TemporaryDirectory(prefix='sokol-support-') as directory:
        root = Path(directory)
        records, total = {}, 0
        for name, argv in commands().items():
            remaining = TOTAL_SECONDS - (time.monotonic() - started)
            result = capture(argv, seconds=min(COMMAND_SECONDS, remaining - 1)) if remaining > 1 else {
                'status': 'TOTAL_TIME_LIMIT', 'returncode': None, 'output': '', 'partial': True}
            data = (result.pop('output') + '\n[exit ' + str(result['returncode']) + ']\n').encode()
            total += len(data)
            if total > MAX_TOTAL:
                raise ValueError('Support collection exceeds retained-byte budget')
            (root / name).write_bytes(data)
            records[name] = {**result, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        manifest = {'profile': 'sokol.support.v1', 'commands': records,
                    'limits': {'per_command_seconds': COMMAND_SECONDS, 'total_seconds': TOTAL_SECONDS,
                               'per_command_bytes': MAX_OUTPUT, 'total_bytes': MAX_TOTAL},
                    'privacy': 'PRIVATE_ARCHIVE; inspect addresses and attacker-controlled log text before sharing',
                    'raw_keys_state_audit': 'NOT_COLLECTED', 'provenance': 'UNSIGNED_LOCAL_OBSERVATIONS'}
        (root / 'collection.json').write_text(json.dumps(manifest, indent=2) + '\n')
        with tarfile.open(archive, 'x:gz') as tar:
            for path in sorted(root.iterdir()):
                tar.add(path, arcname='sokol-support-' + stamp + '/' + path.name, recursive=False)
        archive.chmod(0o600)
    return archive


if __name__ == '__main__':
    print(collect(Path(os.environ.get('OUT', '.'))))
