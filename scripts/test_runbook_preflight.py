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


class CurrentJournal(unittest.TestCase):
    def test_restore_failure_requires_current_invocation_and_drains_the_producer(self):
        source = SCRIPT.read_text()
        if 'restore_failure_in_current_journal()' in source:
            function = source.split('restore_failure_in_current_journal() {', 1)[1].split('\n}', 1)[0]
            predicate = 'restore_failure_in_current_journal() {' + function + '\n}\nrestore_failure_in_current_journal'
        else:
            predicate = next(line.split(' && pass', 1)[0] for line in source.splitlines()
                             if line.startswith('journalctl ') and 'Restore failed' in line)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / 'payload'
            payload.write_text('filler\n' * 100000)
            invocation = 'a' * 32
            for mode, expected in [('large-current', 0), ('stale-only', 1), ('unreadable', 1), ('partial-current', 1), ('bad-id', 1)]:
                (root / 'systemctl').write_text('#!/bin/sh\nprintf "%s\\n" "' + ('bad' if mode == 'bad-id' else invocation) + '"\n')
                (root / 'systemctl').chmod(0o755)
                journal = '#!/bin/sh\n'
                if mode == 'unreadable':
                    journal += 'exit 1\n'
                elif mode == 'partial-current':
                    journal += 'printf "Restore failed in this run\\n"\nexit 1\n'
                elif mode == 'stale-only':
                    journal += 'case "$*" in *"_SYSTEMD_INVOCATION_ID="*) exit 0 ;; esac\nprintf "Restore failed from a previous run\\n"\n'
                else:
                    journal += 'printf "Restore failed in this run\\n"\nexec cat "' + str(payload) + '"\n'
                (root / 'journalctl').write_text(journal)
                (root / 'journalctl').chmod(0o755)
                result = subprocess.run(['bash', '-c', 'set -o pipefail\n' + predicate],
                    capture_output=True, env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH']), timeout=10)
                self.assertEqual(result.returncode, expected, mode + ': ' + result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
