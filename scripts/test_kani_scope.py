"""scripts/kani-scope.sh: which changes make the Kani proofs run again.

Review of #165: the first filter looked at common/ and ci.yml only, so a change of Kani's own
configuration in the workspace Cargo.toml ([workspace.metadata.kani]) skipped the proofs. Its
replacement first missed a new untracked file among the inputs (test_every_input_proves).

    python3 scripts/test_kani_scope.py
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FILES = {
    'common/src/lib.rs': 'pub fn f() {}\n',
    'Cargo.toml': '[workspace]\nmembers = ["common"]\n',
    'Cargo.lock': '# lock\n',
    'rust-toolchain.toml': '[toolchain]\nchannel = "nightly"\n',
    '.github/workflows/ci.yml': 'env:\n  KANI_VERSION: 0.68.0\n',
    'docs/VERIFICATION.md': '# proofs\n',
    'README.md': '# readme\n',
}


class Scope(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo)
        (self.repo / 'scripts').mkdir()
        shutil.copy(HERE / 'kani-scope.sh', self.repo / 'scripts' / 'kani-scope.sh')
        for name, text in FILES.items():
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(text)
        self.git('init', '-q')
        self.git('add', '-A')
        self.git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD').strip()

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, capture_output=True, text=True,
                              check=True).stdout

    def scope(self, base=None):
        result = subprocess.run([str(self.repo / 'scripts' / 'kani-scope.sh'), base or self.base],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def append(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a') as f:
            f.write(text)

    def test_nothing_or_documentation_changed_skips(self):
        self.assertEqual(self.scope(), 'skip')
        self.append('docs/VERIFICATION.md', 'more prose\n')
        self.append('README.md', 'more prose\n')
        self.assertEqual(self.scope(), 'skip')

    def test_kani_configuration_in_the_workspace_manifest_proves(self):
        self.append('Cargo.toml', '[workspace.metadata.kani.flags]\nharness = "x"\n')
        self.assertEqual(self.scope(), 'prove')

    def test_every_input_proves(self):
        for name in ('common/src/lib.rs', 'Cargo.lock', 'rust-toolchain.toml',
                     '.cargo/config.toml', '.github/workflows/ci.yml', 'scripts/kani-scope.sh'):
            with self.subTest(name):
                self.append(name, '\n# changed\n')
                self.assertEqual(self.scope(), 'prove')
                self.git('checkout', '-q', '.')
                self.git('clean', '-qfd')
                self.assertEqual(self.scope(), 'skip')

    def test_a_committed_change_proves_against_its_base(self):
        self.append('common/src/lib.rs', 'pub fn g() {}\n')
        self.git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qam', 'change')
        self.assertEqual(self.scope(), 'prove')

    def test_a_base_git_cannot_read_proves(self):
        self.assertEqual(self.scope('0' * 40), 'prove')


if __name__ == '__main__':
    unittest.main()
