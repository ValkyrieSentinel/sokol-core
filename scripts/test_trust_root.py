"""The next base's authority is part of what the current owner signs.

Use the staged checker: the legacy base workflow overwrites its working-tree copy before
running Python witnesses. This also exercises the exact candidate bytes during bootstrap.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = subprocess.check_output(['git', 'show', ':scripts/witness-pin.py'], cwd=ROOT)


class TrustRoot(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = self.tmp / 'candidate'
        for d in ('scripts', 'docs', '.github', 'src'):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        self.checker = self.root / 'scripts/witness-pin.py'
        self.checker.write_bytes(SOURCE)
        self.trusted = self.tmp / 'trusted-checker.py'
        self.trusted.write_bytes(SOURCE)
        (self.root / '.github/workflows').mkdir()
        (self.root / '.github/workflows/witness-gate.yml').write_text('name: base gate\n')
        (self.root / 'docs/INVARIANTS.md').write_text(
            '| ID | Invariant | Evidence |\n|---|---|---|\n'
            '| T-1 | A refusal has no effect. | `a_refusal_has_no_effect` |\n')
        (self.root / 'src/lib.rs').write_text(
            '#[cfg(test)] mod tests { #[test] fn a_refusal_has_no_effect() { assert!(true); } }\n')
        self.keys = {}
        for name in ('owner', 'outsider'):
            key = self.tmp / name
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
            self.keys[name] = key
        self.signers = self.root / '.github/witness-signers'
        self.signers.write_text(self.line('owner', 'owner'))
        self.base_signers = self.tmp / 'base-signers'
        shutil.copy(self.signers, self.base_signers)
        self.call('git', 'init', '-q')
        self.call('git', 'add', '.')
        self.sign()

    def line(self, principal, key):
        return principal + ' namespaces="sokol-witness" ' + self.keys[key].with_suffix('.pub').read_text()

    def call(self, *cmd):
        return subprocess.run(cmd, cwd=self.root, capture_output=True, text=True, timeout=30)

    def sign(self, key='owner'):
        r = self.call(sys.executable, '-I', str(self.checker), 'sign', '--key', str(self.keys[key]))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def check(self, external=False):
        args = [sys.executable, '-I', str(self.trusted), '--root', str(self.root)] if external else [sys.executable, '-I', str(self.checker)]
        return self.call(*args, 'check', '--every-pin', '--signers', str(self.base_signers))

    def test_a_future_owner_or_agent_cannot_be_enrolled_without_the_old_owner(self):
        for principal in ('owner', 'agent'):
            with self.subTest(principal=principal):
                self.signers.write_text(self.base_signers.read_text() + self.line(principal, 'outsider'))
                r = self.check()
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn('trust root', r.stdout)

    def test_namespace_edits_and_key_removal_are_authority_changes(self):
        for text in (self.line('owner', 'outsider'), '', self.base_signers.read_text().replace('sokol-witness', '*')):
            self.signers.write_text(text)
            r = self.check()
            self.assertNotEqual(r.returncode, 0, r.stdout)

    def test_the_old_owner_can_authorize_overlapping_rotation(self):
        self.signers.write_text(self.base_signers.read_text() + self.line('owner', 'outsider'))
        self.sign()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        shutil.copy(self.signers, self.base_signers)
        self.signers.write_text(self.line('owner', 'outsider'))
        self.sign('outsider')
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_candidate_checker_is_checked_without_overwriting_it(self):
        self.checker.write_bytes(SOURCE + b'\n# changed future authority\n')
        r = self.check(external=True)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('trust root', r.stdout)

    def test_python_arguments_are_future_authority_but_ci_comments_are_not(self):
        test = self.root / 'scripts/test_adapter.py'
        test.write_text('import unittest\n')
        ci = self.root / '.github/workflows/ci.yml'
        ci.write_text('run: python3 scripts/test_adapter.py target/debug/adapter\n')
        self.call('git', 'add', '.')
        self.sign()
        ci.write_text(ci.read_text() + '# artifact retention changed\n')
        r = self.check(external=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        ci.write_text('run: python3 scripts/test_adapter.py fixtures/fake-adapter\n')
        # The base's execution-policy override must not hide candidate changes from pins.
        base_ci = self.tmp / 'base-ci.yml'
        base_ci.write_text('run: python3 scripts/test_adapter.py target/debug/adapter\n')
        from unittest.mock import patch
        with patch.dict(os.environ, {'WITNESS_PIN_CI': str(base_ci)}):
            r = self.check(external=True)
            self.assertNotEqual(r.returncode, 0, r.stdout)
            self.assertIn('trust root', r.stdout)
        ci.write_text('run: python3 scripts/test_adapter.py\n')
        self.assertNotEqual(self.check(external=True).returncode, 0)
        ci.unlink()
        ci.symlink_to(base_ci)
        self.assertNotEqual(self.check(external=True).returncode, 0)

    def test_a_missing_or_symlinked_trust_input_is_refused(self):
        self.signers.unlink()
        r = self.check(external=True)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.signers.symlink_to(self.base_signers)
        r = self.check(external=True)
        self.assertNotEqual(r.returncode, 0, r.stdout)

    def test_an_owner_signed_manifest_without_the_root_field_is_refused(self):
        path = self.root / 'docs/witness-manifest.json'
        value = json.loads(path.read_text())
        self.assertIn('trust_root_v2', value)
        value.pop('trust_root_v2')
        path.write_text(json.dumps(value))
        Path(str(path) + '.sig').unlink()
        self.call('ssh-keygen', '-q', '-Y', 'sign', '-f', str(self.keys['owner']), '-n', 'sokol-witness', str(path))
        r = self.check()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('trust root', r.stdout)


if __name__ == '__main__':
    unittest.main()
