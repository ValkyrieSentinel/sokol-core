"""Incremental source changes cannot keep a clean build identity cached."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BuildIdentity(unittest.TestCase):
    def test_incremental_dirty_and_restored_builds_name_the_actual_source_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'orchestrator'
            (package / 'src').mkdir(parents=True)
            (root / '.gitignore').write_text('target/\n')
            (root / 'Cargo.toml').write_text('[workspace]\nmembers=["orchestrator"]\nresolver="2"\n')
            (package / 'Cargo.toml').write_text('[package]\nname="identity-probe"\nversion="0.1.0"\nedition="2021"\n')
            shutil.copy(ROOT / 'orchestrator/build.rs', package / 'build.rs')
            source = package / 'src/main.rs'
            original = 'fn main() { println!("v1 {}", env!("SOKOL_BUILD_ID")); }\n'
            source.write_text(original)
            env = dict(os.environ)
            for key in ('SOKOL_BUILD_ID', 'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET_DIR'):
                env.pop(key, None)
            def run(*args):
                return subprocess.check_output(args, cwd=root, env=env, text=True, stderr=subprocess.STDOUT, timeout=90).strip()
            run('git', 'init', '-q')
            run('cargo', 'generate-lockfile', '--offline')
            run('git', 'add', '.')
            run('git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'base')
            clean = run('cargo', 'run', '--offline', '--quiet')
            self.assertNotIn('-dirty', clean)
            source.write_text(original.replace('v1 ', 'v2 '))
            dirty = run('cargo', 'run', '--offline', '--quiet')
            self.assertTrue(dirty.startswith('v2 '), dirty)
            self.assertTrue(dirty.endswith('-dirty'), dirty)
            source.write_text(original)
            restored = run('cargo', 'run', '--offline', '--quiet')
            self.assertEqual(restored, clean)


if __name__ == '__main__':
    unittest.main()
