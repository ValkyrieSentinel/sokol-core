"""scripts/counterexample-task.py: a replay's Cargo registry holds only the received lockfile's crates.

Review of #33. Kept apart from test_counterexample_task.py, whose pinned witnesses (EXCHANGE-P1)
pin the whole module's import-time code: a new test there would change their closure.

    python3 scripts/test_counterexample_registry.py
"""
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('counterexample_task', HERE / 'counterexample-task.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

LOCK = ('[[package]]\nname = "serde"\nversion = "1.0.228"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
        '[[package]]\nname = "common"\nversion = "0.1.0"\n')
REG = 'index.crates.io-1949cf8c6b5b557f'


class RegistryWithinLock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        (self.path / 'cache' / REG).mkdir(parents=True)
        (self.path / 'cache' / REG / 'serde-1.0.228.crate').write_bytes(b'x')
        (self.path / 'src' / REG / 'serde-1.0.228').mkdir(parents=True)
        (self.path / 'index' / REG / '.cache' / 'se' / 'rd').mkdir(parents=True)
        (self.path / 'index' / REG / '.cache' / 'se' / 'rd' / 'serde').write_bytes(b'x')
        (self.path / 'index' / REG / 'config.json').write_bytes(b'{}')

    def tearDown(self):
        self.tmp.cleanup()

    def refused(self, needle):
        with self.assertRaisesRegex(ValueError, needle):
            tool.registry_within_lock(self.path, LOCK)

    def test_a_dedicated_registry_for_the_lockfile_is_admitted(self):
        tool.registry_within_lock(self.path, LOCK)

    def test_a_crate_of_another_project_or_version_is_refused(self):
        for name in ('tokio-1.0.0.crate', 'serde-1.0.1.crate'):
            extra = self.path / 'cache' / REG / name
            extra.write_bytes(b'x')
            self.refused('does not name; use a dedicated CARGO_HOME')
            extra.unlink()

    def test_unpacked_sources_of_another_project_are_refused(self):
        (self.path / 'src' / REG / 'other-project-dep-0.1.0').mkdir()
        self.refused('other-project-dep-0.1.0')

    def test_the_index_cache_is_metadata_and_not_restricted(self):
        # cargo caches index entries of every name the resolver considered (e.g. wasi).
        (self.path / 'index' / REG / '.cache' / 'se' / 'rd' / 'wasi').write_bytes(b'x')
        tool.registry_within_lock(self.path, LOCK)


if __name__ == '__main__':
    unittest.main()
