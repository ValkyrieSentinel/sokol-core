"""Exercise the scope decision on real Git states, including inputs absent from git diff."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class MutationScope(unittest.TestCase):
    def test_unknown_build_mutation_inputs_and_new_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'scripts').mkdir()
            shutil.copy(HERE / 'mutants-scope.sh', root / 'scripts/')
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, text=True).strip()
            git('init', '-q'); git('config', 'maintenance.auto', 'false'); git('config', 'gc.auto', '0')
            (root / 'README.md').write_text('baseline\n')
            git('add', '.'); git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'base')
            base = git('rev-parse', 'HEAD')
            def scope(ref=base):
                return subprocess.check_output(['bash', 'scripts/mutants-scope.sh', ref], cwd=root, text=True).strip()
            (root / 'README.md').write_text('documentation\n')
            self.assertEqual(scope(), 'skip')
            self.assertEqual(scope('missing-base'), 'mutate')
            for rel in ('orchestrator/src/new.rs', 'common/src/new.rs', 'Cargo.toml', 'Cargo.lock',
                        '.cargo/config.toml', '.cargo/mutants.toml', 'rust-toolchain.toml',
                        'scripts/mutants-diff.sh', 'scripts/test_mutants_scope.py'):
                path = root / rel; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('changed\n')
                self.assertEqual(scope(), 'mutate', rel + ' (untracked)')
                git('add', rel); self.assertEqual(scope(), 'mutate', rel + ' (staged)')
                git('reset', '-q', base, '--', rel); path.unlink()
            path = root / 'scripts/mutants-scope.sh'; path.write_text(path.read_text() + '\n')
            self.assertEqual(scope(), 'mutate')


if __name__ == '__main__': unittest.main()
