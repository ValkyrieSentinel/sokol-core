"""runbook-rehearsal.sh refuses a host it does not own, and the refusal changes nothing.

Review of #153 (b48c098): the refusal of unmarked state ran after the EXIT cleanup trap was
armed, so it stopped sokol-orchestrator and deleted the pilot0 link and the remote namespace
on the way out. Only file bytes were preserved. Here systemctl and ip are recording stubs and
the state paths are relocated (REHEARSAL_ROOT); only the refusal path is run (it exits before
any real change, so the stubs are never asked to do one).

    python3 scripts/test_runbook_preflight.py
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / 'runbook-rehearsal.sh'
MUTATING = ('systemctl stop', 'systemctl start', 'ip link del', 'ip link add', 'ip netns del',
            'ip netns add', 'ip addr', 'ip link set')


class Preflight(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root, self.stubs = self.tmp / 'root', self.tmp / 'stubs'
        self.stubs.mkdir()
        self.calls = self.tmp / 'calls.log'
        for build in ('a', 'b'):
            (self.tmp / build).mkdir()

    def stub(self, name, body):
        path = self.stubs / name
        path.write_text('#!/bin/sh\necho "%s $*" >> %s\n%s\n' % (name, self.calls, body))
        path.chmod(0o755)

    def run_rehearsal(self, link_exists=False, netns=''):
        self.stub('systemctl', 'exit 0')
        self.stub('ip', 'case "$1 $2" in\n'
                        '  "link show") exit %d ;;\n'
                        '  "netns list") printf "%s" ;;\n'
                        'esac\nexit 0' % (0 if link_exists else 1, netns))
        env = dict(os.environ, REHEARSAL_ROOT=str(self.root),
                   PATH=str(self.stubs) + os.pathsep + os.environ['PATH'])
        result = subprocess.run([str(SCRIPT), str(self.tmp / 'a'), str(self.tmp / 'b')],
                                capture_output=True, text=True, env=env, timeout=30)
        calls = self.calls.read_text().splitlines() if self.calls.exists() else []
        return result, calls

    def assert_refused_untouched(self, result, calls):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('nothing changed', result.stdout)
        changed = [c for c in calls if c.startswith(MUTATING)]
        self.assertEqual(changed, [], 'a refusal stopped or removed something')

    def test_unmarked_state_is_refused_and_nothing_is_stopped_or_removed(self):
        data = self.root / 'var/lib/sokol/audit.log'
        data.parent.mkdir(parents=True)
        data.write_bytes(b'operator evidence')
        result, calls = self.run_rehearsal()
        self.assert_refused_untouched(result, calls)
        self.assertEqual(data.read_bytes(), b'operator evidence')

    def test_an_installed_unit_without_the_marker_is_refused(self):
        unit = self.root / 'etc/systemd/system/sokol-orchestrator.service'
        unit.parent.mkdir(parents=True)
        unit.write_text('[Service]\n')
        self.assert_refused_untouched(*self.run_rehearsal())

    def test_an_existing_interface_or_namespace_is_refused(self):
        with self.subTest('pilot0'):
            self.assert_refused_untouched(*self.run_rehearsal(link_exists=True))
        self.calls.unlink(missing_ok=True)
        with self.subTest('remote'):
            self.assert_refused_untouched(*self.run_rehearsal(netns='remote (id: 0)\\n'))


if __name__ == '__main__':
    unittest.main()
