"""scripts/check-witnesses.sh, the xdp-smoke gate for ADR-0021, against a stub verifier.

Review of #153: the gate parsed the summary of a pipeline without pipefail, so a verifier that
printed a valid summary and then failed (exit 2, 143) was a PASS. The gate needs both.

    python3 scripts/test_witness_gate.py
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

GATE = Path(__file__).resolve().parent / 'check-witnesses.sh'
GOOD = 'witnesses for node 1: 1 confirmed, 0 contradicted, 0 missing, 0 pruned'


class Gate(unittest.TestCase):
    def run_gate(self, summary, status):
        with tempfile.TemporaryDirectory() as tmp:
            cli = Path(tmp) / 'orchestrator'
            cli.write_text(f'#!/bin/sh\necho "peer record 3: head after 7 records confirmed"\n'
                           f'echo "{summary}"\nexit {status}\n')
            cli.chmod(0o755)
            return subprocess.run([str(GATE), str(cli), 'own.log', 'peer.log', '1'],
                                  capture_output=True, text=True).returncode

    def test_a_confirmed_summary_from_a_successful_verifier_passes(self):
        self.assertEqual(self.run_gate(GOOD, 0), 0)

    def test_a_valid_summary_from_a_failed_verifier_fails(self):
        for status in (1, 2, 143):
            with self.subTest(status):
                self.assertNotEqual(self.run_gate(GOOD, status), 0)

    def test_contradicted_missing_or_unconfirmed_summaries_fail(self):
        for summary in (
            'witnesses for node 1: 1 confirmed, 1 contradicted, 0 missing, 0 pruned',
            'witnesses for node 1: 1 confirmed, 0 contradicted, 2 missing, 0 pruned',
            'witnesses for node 1: 0 confirmed, 0 contradicted, 0 missing, 3 pruned',
            '',
        ):
            with self.subTest(summary):
                self.assertNotEqual(self.run_gate(summary, 0), 0)


if __name__ == '__main__':
    unittest.main()
