"""scripts/check-claims.sh: a cited test must be a test, a cited proof must be a proof.

The check used to look four lines up from `fn name` for a test attribute, so a plain helper
defined just after a test passed as a test. Tests now come from the compiler's own list
(SOKOL_TEST_LIST here, `cargo test -- --list` in CI) and proofs from attributes attached to the
function (scripts/attached-fns.py).

    python3 scripts/test_check_claims.py
"""
import importlib.util
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location('attached_fns', HERE / 'attached-fns.py')
attached_fns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attached_fns)

# A proof, then a helper right after it: the old four-lines-up search took the helper for a proof.
SOURCE = '''\
#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn a_proof() {}
    fn helper_after_a_proof() {}

    /// Documented, with another attribute between.
    #[kani::proof]
    #[kani::unwind(
        3
    )]
    pub(crate) fn a_documented_proof() {}

    #[kani::proof]
    // a comment between is still attached

    fn a_proof_after_a_blank_line() {}
}
'''


def every_fn_as_a_test():
    """A test list naming every function of the tree: a superset of the real tests."""
    files = subprocess.run(['git', 'ls-files', '*.rs'], cwd=ROOT, capture_output=True, text=True,
                           check=True).stdout.split()
    names = set()
    for f in files:
        names.update(re.findall(r'\bfn\s+([a-z_][a-z0-9_]*)', (ROOT / f).read_text()))
    return names


def cited_tests():
    result = subprocess.run(['bash', '-c', '''
        grep -ohE '`[^`]+`' README.md ARCHITECTURE.md ROADMAP.md AGENTS.md docs/*.md docs/adr/*.md \
            docs/measurements/*/README.md | tr -d '`' \
            | grep -oxE '[a-z][a-z0-9]*(_[a-z0-9]+){3,}' | grep -v '^sokol_' | sort -u'''],
        cwd=ROOT, capture_output=True, text=True, check=True)
    return result.stdout.split()


class Claims(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def check(self, names, extra=''):
        path = self.dir / 'tests.txt'
        path.write_text(''.join(f'some::module::{n}: test\n' for n in sorted(names)) + extra)
        return subprocess.run([str(HERE / 'check-claims.sh')], cwd=ROOT, capture_output=True,
                              text=True, env={**os.environ, 'SOKOL_TEST_LIST': str(path)})

    def test_every_cited_test_in_the_list_passes(self):
        result = self.check(every_fn_as_a_test())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_cited_name_missing_from_the_list_fails_by_name(self):
        cited = cited_tests()
        self.assertGreater(len(cited), 100, 'the docs cite tests')
        missing = cited[0]
        result = self.check(every_fn_as_a_test() - {missing})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(f'test {missing} is cited but no test has that name', result.stdout)

    def test_a_list_without_tests_fails(self):
        result = self.check(set(), extra='0 tests, 0 benchmarks\n')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('the test list names no test', result.stdout)

    def test_a_benchmark_is_not_a_test(self):
        cited = cited_tests()
        result = self.check(every_fn_as_a_test() - {cited[0]},
                            extra=f'some::module::{cited[0]}: benchmark\n')
        self.assertNotEqual(result.returncode, 0, result.stdout)


class Attached(unittest.TestCase):
    def test_only_functions_carrying_the_attribute_are_named(self):
        self.assertEqual(attached_fns.attached('#[kani::proof]', SOURCE),
                         ['a_proof', 'a_documented_proof', 'a_proof_after_a_blank_line'])

    def test_the_old_search_took_the_helper_for_a_proof(self):
        # What the replaced check did: an attribute within four lines above `fn name`.
        lines = SOURCE.splitlines()
        i = next(n for n, line in enumerate(lines) if 'fn helper_after_a_proof' in line)
        self.assertTrue(any('#[kani::proof]' in line for line in lines[max(0, i - 4):i]))
        self.assertNotIn('helper_after_a_proof', attached_fns.attached('#[kani::proof]', SOURCE))

    def test_a_statement_between_breaks_the_chain(self):
        source = '#[kani::proof]\nconst X: u8 = 1;\nfn not_a_proof() {}\n'
        self.assertEqual(attached_fns.attached('#[kani::proof]', source), [])

    def test_the_real_proofs_are_found(self):
        files = subprocess.run(['git', 'ls-files', 'common/src/*.rs'], cwd=ROOT,
                               capture_output=True, text=True, check=True).stdout.split()
        names = [n for f in files
                 for n in attached_fns.attached('#[kani::proof]', (ROOT / f).read_text())]
        self.assertIn('advancing_never_wraps', names)


if __name__ == '__main__':
    unittest.main()
