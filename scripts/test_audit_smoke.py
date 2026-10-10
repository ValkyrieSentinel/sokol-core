"""Run the three actual audit smoke commands against a fallible monitor CLI."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
EXPECTATIONS = {
    'monitor --verify accepts the audit chain': 'intact',
    'monitor --verify accepts the chain across rotated segments': 'intact',
    'monitor --verify detects an edited segment': 'broken',
}


def commands():
    text = (ROOT / 'scripts/xdp-smoke.sh').read_text().replace('\\\n', ' ')
    found = [(name, cmd) for name, cmd in re.findall(r'^\s*check "([^"\n]+)"\s+([^\n]+)$', text, re.M)
             if name in EXPECTATIONS]
    if len(found) != 3 or {name for name, _ in found} != set(EXPECTATIONS):
        raise AssertionError('missing, duplicate or renamed audit smoke check')
    return found


class AuditSmoke(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='sokol-audit-smoke-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name, target in [('python3', sys.executable), ('bash', '/bin/bash'), ('grep', '/usr/bin/grep')]:
            (self.root / name).symlink_to(target)
        self.cli = self.root / 'monitor'
        self.cli.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
assert sys.argv[1:] == ['--verify', os.environ['AUDIT_PATH']], sys.argv
Path(os.environ['AUDIT_CALLS']).write_text(json.dumps(sys.argv[1:]))
sys.stdout.write(os.environ['AUDIT_OUTPUT'].replace('{path}', sys.argv[2]))
sys.exit(int(os.environ['AUDIT_STATUS']))
''')
        self.cli.chmod(0o755)

    def run_command(self, command, status, output, wrapper=False):
        helper = ROOT / 'scripts/audit-verdict.sh'
        setup = 'MONITOR_BIN="$AUDIT_CLI"; WORK="$AUDIT_WORK"\n'
        if helper.exists():
            setup += 'source "$AUDIT_HELPER"\n'
        if wrapper:
            source = (ROOT / 'scripts/xdp-smoke.sh').read_text()
            check = re.search(r'^check\(\) \{\n.*?^\}', source, re.M | re.S)
            if not check:
                raise AssertionError('missing smoke wrapper')
            setup += check.group() + '\nFAILED=0\n'
            command = 'check probe ' + command + '\nexit "$FAILED"'
        calls = self.root / 'calls.json'
        calls.unlink(missing_ok=True)
        result = subprocess.run(['bash', '-euo', 'pipefail', '-c', setup + command],
                                env={**os.environ, 'PATH': str(self.root), 'AUDIT_CLI': str(self.cli),
                                     'AUDIT_WORK': str(self.root), 'AUDIT_PATH': str(self.root / 'events.sntl'),
                                     'AUDIT_HELPER': str(helper), 'AUDIT_CALLS': str(calls),
                                     'AUDIT_STATUS': str(status), 'AUDIT_OUTPUT': output},
                                capture_output=True, text=True, timeout=3)
        return result, calls

    def test_actual_commands_accept_only_the_expected_verified_outcome(self):
        for name, cmd in commands():
            for status, label, actual in [(0, 'OK', 'intact'), (1, 'BROKEN', 'broken')]:
                with self.subTest(name=name, label=label):
                    result, calls = self.run_command(cmd, status, label + ' {path}: probe\n')
                    self.assertEqual(result.returncode, 0 if EXPECTATIONS[name] == actual else 1, result.stderr)
                    self.assertTrue(calls.exists(), 'missing verification call')

    def test_unverified_and_inconsistent_results_cannot_pass_any_actual_command(self):
        bad = [(2, 'UNVERIFIED {path}: probe\n'), (7, ''), (7, 'OK {path}: partial\n'),
               (7, 'BROKEN {path}: partial\n'), (0, 'BROKEN {path}: inconsistent\n'),
               (1, 'OK {path}: inconsistent\n'), (1, ''), (0, ''),
               (1, 'BROKEN /other/path: probe\n'), (0, 'OK /other/path: probe\n'),
               (137, 'OK {path}: partial\n'), (0, 'OK'), (1, 'BROKEN')]
        for name, cmd in commands():
            for status, output in bad:
                with self.subTest(name=name, status=status, output=output):
                    result, _ = self.run_command(cmd, status, output)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    result, _ = self.run_command(cmd, status, output, wrapper=True)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn('FAIL  probe', result.stdout)
                    self.assertNotIn('PASS', result.stdout)

    def test_invalid_arguments_do_not_invoke_the_monitor(self):
        for cmd in ['audit_verdict unknown "$AUDIT_PATH"', 'audit_verdict broken',
                    'MONITOR_BIN=; audit_verdict intact "$AUDIT_PATH"']:
            with self.subTest(command=cmd):
                result, calls = self.run_command(cmd, 0, 'OK {path}: probe\n')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(calls.exists())

    def test_missing_monitor_cannot_confirm_audit_integrity_or_corruption(self):
        self.cli.unlink()
        for name, cmd in commands():
            with self.subTest(name=name):
                result, _ = self.run_command(cmd, 0, '')
                self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == '__main__':
    unittest.main()
