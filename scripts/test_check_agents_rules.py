"""scripts/check-agents-rules.sh: every rule under "Changing code" carries its own marker.

Review of #168: rules were split on "- " only, so a "* " rule joined the rule before it and
passed on that rule's "Checked by:".

    python3 scripts/test_check_agents_rules.py
"""
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


if __name__ == '__main__':
    unittest.main()
