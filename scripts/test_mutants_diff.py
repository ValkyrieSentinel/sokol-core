"""scripts/mutants-diff.sh: what fails the mutation check of a change, with a stub cargo.

    python3 scripts/test_mutants_diff.py
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class MutantsDiff(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo)
        (self.repo / 'scripts').mkdir()
        shutil.copy(HERE / 'mutants-diff.sh', self.repo / 'scripts' / 'mutants-diff.sh')
        (self.repo / 'orchestrator').mkdir()
        (self.repo / 'orchestrator' / 'lib.rs').write_text('fn f() {}\n')
        self.git('init', '-q')
        self.git('add', '-A')
        self.git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD').strip()
        (self.repo / 'orchestrator' / 'lib.rs').write_text('fn f() {}\nfn g() {}\n')
        self.stubs = self.repo / 'stubs'
        self.stubs.mkdir()
        self.calls = self.repo / 'calls.log'

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, capture_output=True, text=True,
                              check=True).stdout

    def cargo(self, status, missed=''):
        """A cargo stub: records its arguments, writes missed.txt under -o, exits `status`."""
        path = self.stubs / 'cargo'
        path.write_text(f'''#!/bin/sh
echo "cargo $*" >> {self.calls}
while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done
mkdir -p "$out/mutants.out"
printf '%s' "{missed}" > "$out/mutants.out/missed.txt"
exit {status}
''')
        path.chmod(0o755)

    def run_check(self):
        env = dict(os.environ, PATH=str(self.stubs) + os.pathsep + os.environ['PATH'])
        return subprocess.run([str(self.repo / 'scripts' / 'mutants-diff.sh'), self.base],
                              cwd=self.repo, capture_output=True, text=True, env=env)

    def test_all_caught_passes_and_both_packages_run_on_the_change(self):
        self.cargo(0)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls.read_text()
        self.assertIn('-p orchestrator', calls)
        self.assertIn('--cargo-arg=--bins', calls.splitlines()[0], 'the node runs unit tests only')
        self.assertIn('-p common', calls)
        diff = (self.repo / 'target' / 'mutants-diff' / 'change.diff').read_text()
        self.assertIn('+fn g() {}', diff, 'the uncommitted change is the one checked')

    def test_a_missed_mutant_fails_and_is_named(self):
        self.cargo(2, 'orchestrator/lib.rs:2:1: replace g with ()\n')
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('replace g with ()', result.stdout)

    def test_a_timeout_alone_counts_as_caught(self):
        self.cargo(3)
        self.assertEqual(self.run_check().returncode, 0)

    def test_a_failing_baseline_is_not_a_pass(self):
        self.cargo(4)
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('exited 4', result.stdout)


if __name__ == '__main__':
    unittest.main()
