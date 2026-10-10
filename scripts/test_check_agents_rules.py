"""scripts/check-agents-rules.sh: every rule under "Changing code" carries its own marker.

Review of #168: rules were split on "- " only, so a "* " rule joined the rule before it and
passed on that rule's "Checked by:".

    python3 scripts/test_check_agents_rules.py
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
CHECKED = '- An annotated rule.\n  *Checked by:* `some_test`.\n'


def doc(rules):
    return '# Agents\n\n## Changing code\n\nIntro paragraph, not a rule.\n\n' + rules + \
        '\n## Review\n\nNot checked here.\n'


class Rules(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def check(self, text):
        path = self.dir / 'AGENTS.md'
        path.write_text(text)
        return subprocess.run([str(HERE / 'check-agents-rules.sh'), str(path)],
                              capture_output=True, text=True)

    def test_annotated_rules_pass_whatever_their_marker(self):
        for marker in ('-', '*', '+', '1.', '2)'):
            with self.subTest(marker):
                result = self.check(doc(CHECKED + f'{marker} Another rule. *Review only.*\n'))
                self.assertEqual(result.returncode, 0, result.stdout)

    def test_an_unannotated_rule_after_an_annotated_one_fails_for_every_marker(self):
        for marker in ('-', '*', '+', '1.', '2)'):
            with self.subTest(marker):
                result = self.check(doc(CHECKED + f'{marker} Bound every review queue.\n'))
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn('Bound every review queue', result.stdout)

    def test_a_marker_on_a_continuation_line_counts_for_its_own_rule(self):
        rule = '- A rule over\n  two lines. *Review only.*\n'
        self.assertEqual(self.check(doc(rule)).returncode, 0)

    def test_unindented_text_after_the_list_is_a_rule_of_its_own(self):
        result = self.check(doc(CHECKED + 'A paragraph that slipped out of the list.\n'))
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_a_section_without_rules_fails(self):
        self.assertEqual(self.check(doc('')).returncode, 1)

    def test_the_repository_rules_pass_and_the_review_counterexample_fails(self):
        real = (HERE.parent / 'AGENTS.md').read_text()
        self.assertEqual(self.check(real).returncode, 0)
        broken = real.replace('\n## Review\n', '* Bound every review queue.\n\n## Review\n', 1)
        self.assertEqual(self.check(broken).returncode, 1)



class ThroughCheckClaims(unittest.TestCase):
    """check-claims.sh honours the rule checker's exit status, not only its lines (review of
    #168: a checker that could not run left the whole check green)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def run_with(self, body):
        stub = self.dir / 'rules-check'
        stub.write_text('#!/bin/sh\n' + body + '\n')
        stub.chmod(0o755)
        env = dict(os.environ, AGENTS_RULES_CHECK=str(stub))
        return subprocess.run([str(HERE / 'check-claims.sh')], capture_output=True, text=True,
                              env=env, cwd=HERE.parent)

    def test_a_checker_that_fails_without_output_fails_the_check(self):
        result = self.run_with('exit 126')
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('exited 126 without output', result.stdout)

    def test_a_checker_that_cannot_run_fails_the_check(self):
        stub = self.dir / 'not-executable'
        stub.write_text('#!/bin/sh\nexit 0\n')  # no executable bit: Permission denied
        env = dict(os.environ, AGENTS_RULES_CHECK=str(stub))
        result = subprocess.run([str(HERE / 'check-claims.sh')], capture_output=True, text=True,
                                env=env, cwd=HERE.parent)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_its_findings_are_reported_and_a_passing_checker_passes(self):
        failing = self.run_with('echo "FAIL AGENTS.md rule names no check: x"; exit 1')
        self.assertNotEqual(failing.returncode, 0)
        self.assertIn('rule names no check: x', failing.stdout)
        self.assertEqual(self.run_with('exit 0').returncode, 0)


if __name__ == '__main__':
    unittest.main()
