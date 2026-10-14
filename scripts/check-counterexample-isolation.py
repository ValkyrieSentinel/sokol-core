#!/usr/bin/env python3
"""Real Linux isolation negative controls, with tiny recipient-owned probes."""
import importlib.util
import os
from pathlib import Path
import platform
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('counterexample_task', Path(__file__).with_name('counterexample-task.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def main():
    if platform.system() != 'Linux' or os.geteuid() == 0:
        print('REFUSED: Linux non-root worker required')
        return 3
    with tempfile.TemporaryDirectory(prefix='sokol-isolation-controls-') as directory:
        base = Path(directory).resolve()
        source, toolchain, registry = [base / n for n in ('source', 'toolchain', 'registry')]
        for path in (source, toolchain, registry):
            path.mkdir()
        secret = base / 'host-secret'
        secret.write_text('not mounted')
        (source / 'read-only').write_text('public')
        runner = base / 'probe.py'
        runner.write_text(f'''
import os, socket
assert not os.path.exists({str(secret)!r}), 'host filesystem leaked'
assert not os.path.exists('/home'), 'home mounted'
assert 'SOKOL_TEST_SECRET' not in os.environ, 'environment leaked'
try:
    open('/source/read-only', 'w')
except OSError:
    pass
else:
    raise AssertionError('source writable')
s = socket.socket()
s.settimeout(.2)
try:
    s.connect(('1.1.1.1', 443))
except OSError:
    pass
else:
    raise AssertionError('external network reachable')
print('ISOLATION_CONTROLS_PASSED')
''')
        with patch.dict(os.environ, {'SOKOL_TEST_SECRET': 'must not enter worker'}):
            code, output = tool.isolated_run(source, toolchain, registry, runner)
        if code or output.strip() != b'ISOLATION_CONTROLS_PASSED':
            print('FAIL: capability controls', code, output.decode('utf-8', 'replace'))
            return 1
        print('PASS: no home, host secret, inherited secret, source writes or external network')
        runner.write_text('x = bytearray(256 * 1024 * 1024)\nprint("memory limit absent")\n')
        with patch.object(tool, 'MEMORY_BYTES', 64 * 1024 * 1024):
            code, output = tool.isolated_run(source, toolchain, registry, runner)
        if not code or b'memory limit absent' in output:
            print('FAIL: memory control', code, output)
            return 1
        print('PASS: over-budget memory worker terminated; not a verdict')
        runner.write_text('while True: pass\n')
        with patch.object(tool, 'TOTAL_SECONDS', 1):
            code, _ = tool.isolated_run(source, toolchain, registry, runner)
        if not code:
            print('FAIL: time control')
            return 1
        print('PASS: wall-time cgroup terminated; not a verdict')
        runner.write_text('print("x" * 10000)\n')
        try:
            with patch.object(tool, 'MAX_BLOB', 128):
                tool.isolated_run(source, toolchain, registry, runner)
        except ValueError as error:
            if 'output bound' not in str(error):
                raise
        else:
            print('FAIL: output control')
            return 1
        print('PASS: excess output refused and named worker cgroup stopped')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
