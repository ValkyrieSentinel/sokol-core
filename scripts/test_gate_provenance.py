"""CI's witness gate takes its checker and signers from BASE (ADR-0023). In the depth-1
checkout CI uses, BASE was not in the clone and the step silently fell back to the pull
request's own checker and signers (since #1, found 2026-10-12): a pull request could re-sign
with its own key and pass. The step now fetches the base and fails if it cannot.

Builds a fixture repo pinned by an owner key; a "pull request" swaps in its own key and re-signs;
a merge commit (as refs/pull/N/merge) is fetched with --depth=1 as actions/checkout does; the
step body is extracted verbatim from .github/workflows/ci.yml (minus --executed) and run.

    python3 scripts/test_gate_provenance.py
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
CI = HERE.parent / '.github/workflows/ci.yml'
INVARIANTS = '| ID | Invariant | Evidence |\n|---|---|---|\n| T-1 | A refusal creates no cooldown. | `a_refusal_creates_no_cooldown` |\n'
RUST = '#[cfg(test)]\nmod tests {\n    #[test]\n    fn a_refusal_creates_no_cooldown() {\n        assert_eq!(gate(), 0);\n    }\n}\n'


def sh(cwd, *cmd, **kw):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, **kw)


def step_body() -> str:
    text = CI.read_text()
    m = re.search(r"- name: Pinned witnesses unchanged.*?\n        run: \|\n(.*?)\n\n", text, re.S)
    body = '\n'.join(line[10:] for line in m.group(1).splitlines())
    return body.replace('\\\n  --executed /tmp/sokol-cargo-test.log', '')


class Provenance(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / 'repo'
        for sub in ('scripts', 'docs', '.github', 'src'):
            (self.repo / sub).mkdir(parents=True)
        shutil.copy(HERE / 'witness-pin.py', self.repo / 'scripts/witness-pin.py')
        (self.repo / 'docs/INVARIANTS.md').write_text(INVARIANTS)
        (self.repo / 'src/gate.rs').write_text(RUST)
        owner, attacker = self.key('owner'), self.key('attacker')
        (self.repo / '.github/witness-signers').write_text(self.signer(owner))
        git = lambda *a: sh(self.repo, 'git', '-c', 'user.name=t', '-c', 'user.email=t@t', *a)
        git('init', '-q', '-b', 'main')
        git('config', 'uploadpack.allowAnySHA1InWant', 'true')
        git('add', '-A')
        self.assertEqual(sh(self.repo, 'python3', 'scripts/witness-pin.py', 'sign', '--key', owner).returncode, 0)
        git('add', '-A'); git('commit', '-qm', 'base')
        self.base = git('rev-parse', 'HEAD').stdout.strip()
        git('checkout', '-qb', 'pr')
        (self.repo / 'src/gate.rs').write_text(RUST.replace('assert_eq!(gate(), 0);', 'let _ = gate();'))
        (self.repo / '.github/witness-signers').write_text(self.signer(attacker))
        self.assertEqual(sh(self.repo, 'python3', 'scripts/witness-pin.py', 'sign', '--key', attacker).returncode, 0)
        git('commit', '-qam', 'weaken'); git('checkout', '-q', 'main')
        git('merge', '-q', '--no-ff', '-m', 'merge', 'pr')
        self.merge = git('rev-parse', 'HEAD').stdout.strip()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def key(self, name):
        path = str(self.tmp / name)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', path], check=True)
        return path

    def signer(self, key):
        return f'owner namespaces="sokol-witness" {Path(key + ".pub").read_text()}'

    def test_the_gate_step_refuses_a_re_signed_pull_request_in_a_depth_1_checkout(self):
        ci = self.tmp / 'ci'
        ci.mkdir()
        sh(ci, 'git', 'init', '-q')
        sh(ci, 'git', 'remote', 'add', 'origin', str(self.repo))
        sh(ci, 'git', 'fetch', '-q', '--depth=1', 'origin', self.merge)
        sh(ci, 'git', 'checkout', '-q', 'FETCH_HEAD')
        for every_pin in ('', '--every-pin'):
            with self.subTest(every_pin or 'pull_request'):
                r = sh(ci, 'bash', '-e', '-c', step_body(),
                       env={'PATH': '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin', 'BASE': self.base, 'EVERY_PIN': every_pin})
                self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("checker and signers from base " + self.base, r.stdout)
                self.assertIn("is not signed by a key in", r.stdout)

    def test_a_base_that_cannot_be_fetched_fails_the_step(self):
        ci = self.tmp / 'ci'
        ci.mkdir()
        sh(ci, 'git', 'init', '-q')
        sh(ci, 'git', 'remote', 'add', 'origin', str(self.repo))
        sh(ci, 'git', 'fetch', '-q', '--depth=1', 'origin', self.merge)
        sh(ci, 'git', 'checkout', '-q', 'FETCH_HEAD')
        r = sh(ci, 'bash', '-e', '-c', step_body(),
               env={'PATH': '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin', 'BASE': '1' * 40, 'EVERY_PIN': ''})
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn(" match the owner's pins", r.stdout)


if __name__ == '__main__':
    unittest.main()
