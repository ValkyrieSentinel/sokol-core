"""scripts/anchor-ots.sh and scripts/check-anchors.sh (ADR-0022), against stub commands.

    python3 scripts/test_anchor_scripts.py
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
GOOD = 'anchored heads for node 1: 2 confirmed, 0 contradicted, 0 missing, 0 pruned (Bitcoin ...)'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.stubs = self.tmp / 'stubs'
        self.stubs.mkdir()
        self.calls = self.tmp / 'calls.log'

    def stub(self, name, body):
        path = self.stubs / name
        path.write_text('#!/bin/sh\necho "%s $*" >> %s\n%s\n' % (name, self.calls, body))
        path.chmod(0o755)

    def run_script(self, *args, with_stubs=True):
        path = str(self.stubs) + os.pathsep + '/usr/bin:/bin' if with_stubs else '/usr/bin:/bin'
        return subprocess.run([str(HERE / args[0]), *args[1:]], capture_output=True, text=True,
                              env=dict(os.environ, PATH=path))

    def calls_of(self, verb):
        if not self.calls.exists():
            return []
        return [l for l in self.calls.read_text().splitlines() if l.startswith('ots ' + verb)]


class Stamping(Base):
    def statements(self, *names):
        d = self.tmp / 'anchors'
        d.mkdir(exist_ok=True)
        for n in names:
            (d / n).write_text('sokol-audit-head v1 node=1 records=1 head=%s\n' % ('0' * 64))
        return d

    def test_only_unstamped_statements_are_stamped_and_stamps_are_upgraded(self):
        d = self.statements('head-1-01.txt', 'head-1-02.txt', 'notes.txt')
        (d / 'head-1-01.txt.ots').write_bytes(b'existing')
        self.stub('ots', '[ "$1" = stamp ] && : > "$2.ots"; exit 0')
        result = self.run_script('anchor-ots.sh', str(d))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.calls_of('stamp'), ['ots stamp %s/head-1-02.txt' % d])
        self.assertEqual(sorted(self.calls_of('upgrade')),
                         ['ots upgrade %s/head-1-01.txt.ots' % d, 'ots upgrade %s/head-1-02.txt.ots' % d])
        self.assertEqual((d / 'head-1-01.txt.ots').read_bytes(), b'existing', 'a stamp is never redone')

    def test_a_failed_stamp_fails_the_run_and_a_pending_upgrade_does_not(self):
        d = self.statements('head-1-01.txt', 'head-1-02.txt')
        self.stub('ots', 'case "$1 $2" in *head-1-01.txt) exit 1 ;; stamp*) : > "$2.ots" ;; upgrade*) exit 1 ;; esac')
        result = self.run_script('anchor-ots.sh', str(d))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('stamped 1, failed 1', result.stdout)

    def test_without_the_client_it_says_so(self):
        d = self.statements('head-1-01.txt')
        self.assertEqual(self.run_script('anchor-ots.sh', str(d), with_stubs=False).returncode, 2)


class Gate(Base):
    def run_gate(self, summary, status):
        self.stub('orchestrator', 'echo "head-1-01.txt: head after 7 records confirmed"\n'
                                  'echo "%s"\nexit %d' % (summary, status))
        return self.run_script('check-anchors.sh', str(self.stubs / 'orchestrator'), 'own.log', 'dir', '1').returncode

    def test_a_confirmed_summary_from_a_successful_verifier_passes(self):
        self.assertEqual(self.run_gate(GOOD, 0), 0)

    def test_a_valid_summary_from_a_failed_verifier_fails(self):
        for status in (1, 2, 143):
            with self.subTest(status):
                self.assertNotEqual(self.run_gate(GOOD, status), 0)

    def test_contradicted_missing_or_unconfirmed_summaries_fail(self):
        for summary in (GOOD.replace('0 contradicted', '1 contradicted'),
                        GOOD.replace('0 missing', '1 missing'),
                        GOOD.replace('2 confirmed', '0 confirmed'), ''):
            with self.subTest(summary):
                self.assertNotEqual(self.run_gate(summary, 0), 0)


if __name__ == '__main__':
    unittest.main()
