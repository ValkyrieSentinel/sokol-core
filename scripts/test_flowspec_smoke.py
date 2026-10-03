"""Exercise the actual XDP smoke assertions with a fallible GoBGP CLI."""
import json
import importlib.util
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
# The expectation is independent of the command implementation under test.
ABSENT = {
    "Flowspec: expired block is withdrawn upstream",
    "observe mode: no Flowspec rule reaches upstream for a new block",
    "Flowspec: shutdown withdraws the node's rules upstream",
    "Flowspec: the next run withdraws the crashed run's stale rule",
    "Flowspec: removed static rule is absent upstream during the fault",
}
PRESENT = {
    "Flowspec: upstream receives a discard rule for the dynamic block",
    "Flowspec: upstream receives a discard rule for the static block",
    "observe mode: another system's upstream rule is untouched",
    "Flowspec: another system's rule is left alone",
    "Flowspec: a crashed node's rule stays upstream",
    "Flowspec: the next run keeps announcing its wanted rules",
    "Flowspec: recovered worker restores the wanted static rule",
}
RIB = """   Network                 Next Hop             AS_PATH              Age        Attrs
*> [source: 10.231.0.2/32] fictitious 00:00:01 [{Extcomms: [discard]}]
*> [source: 10.231.0.3/32] fictitious 00:00:01 [{Extcomms: [discard]}]
*> [source: 192.0.2.99/32] fictitious 00:00:01 [{Extcomms: [discard]}]
"""


def assertions():
    # Run the actual commands at all actual call sites, including Bash children.
    # A helper-only test would miss a caller still using `!` to invert its error.
    text = (ROOT / 'scripts/xdp-smoke.sh').read_text().replace('\\\n', ' ')
    matches = re.findall(r'^\s*check "([^"\n]+)"\s+([^\n]+)$', text, re.MULTILINE)
    relevant = [(name, command) for name, command in matches if name in ABSENT | PRESENT]
    if len(relevant) != len(ABSENT | PRESENT):
        raise AssertionError('duplicate or missing FlowSpec smoke assertion')
    selected = dict(relevant)
    if set(selected) != ABSENT | PRESENT:
        raise AssertionError('missing or renamed FlowSpec smoke assertions')
    return selected


class FlowSpecMetrics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("flowspec_metrics", ROOT / "scripts/flowspec-metrics.py")
        cls.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.helper)

    def samples(self, enabled=1, ok=0, count=1, age=3, discard=None):
        return "\n".join(f"{name} {value}" for name, value in zip(
            self.helper.NAMES, (enabled, ok, count, age, count if discard is None else discard))) + "\n"

    def test_retained_count_only_passes_with_explicit_failure_and_age(self):
        self.assertTrue(self.helper.matches(self.samples(), "failed", 1, 2))
        for text in (self.samples(ok=1), self.samples(age=-1),
                     self.samples(age=0), self.samples(count=0), self.samples(discard=0)):
            self.assertFalse(self.helper.matches(text, "failed", 1, 2))

    def test_disabled_and_observed_empty_are_different(self):
        self.assertTrue(self.helper.matches(self.samples(0, 0, 0, -1), "disabled", 0, 0))
        self.assertFalse(self.helper.matches(self.samples(1, 0, 0, -1), "disabled", 0, 0))
        self.assertTrue(self.helper.matches(self.samples(1, 1, 0, 0), "ok", 0, 0))

    def test_missing_duplicate_and_nonfinite_samples_are_unverified(self):
        for text in (self.samples().replace("sokol_flowspec_readback_ok 0\n", ""),
                     self.samples() + "sokol_flowspec_announced 1\n",
                     self.samples(age="nan"), self.samples(age="inf"),
                     self.samples(ok=2), self.samples(count=1.5), self.samples(discard=2), self.samples(discard="nan")):
            with self.assertRaises(ValueError):
                self.helper.matches(text, "failed", 1, 2)


class RunbookHealth(unittest.TestCase):
    # Exercise the actual consumer; the old wildcard rejected correctly disabled
    # FlowSpec. Missing mandatory health and HTTP failures must still fail.
    REQUIRED = ("sokol_audit_healthy", "sokol_state_healthy",
                "sokol_state_restore_ok", "sokol_protected_refresh_ok")

    def run_health(self, text, status=0):
        source = (ROOT / "scripts/runbook-rehearsal.sh").read_text()
        function = re.search(r"^node_health\(\) \{\n.*?^\}", source, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(function, "missing actual runbook health consumer")
        # An actual function instead of a Python imitation, with only HTTP replaced.
        script = "curl() { printf '%s\\n' \"$HEALTH_BODY\"; return \"$HEALTH_STATUS\"; }\n"
        script += function.group() + "\nnode_health\n"
        return subprocess.run(["bash", "-uo", "pipefail", "-c", script],
                              env={**os.environ, "HEALTH_BODY": text, "HEALTH_STATUS": str(status)},
                              capture_output=True, text=True, timeout=3)

    def healthy(self):
        return "\n".join(f"{name} 1" for name in self.REQUIRED) + "\n"

    def test_disabled_or_pending_optional_readback_is_not_node_failure(self):
        for enabled in (0, 1):
            result = self.run_health(self.healthy() + f"sokol_flowspec_enabled {enabled}\nsokol_flowspec_readback_ok 0\n")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_every_required_health_sample_must_exist_and_succeed(self):
        for name in self.REQUIRED:
            for replacement in ("", f"{name} 0\n", f"{name} nan\n", f"{name} 1 extra\n"):
                result = self.run_health(self.healthy().replace(f"{name} 1\n", replacement))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(self.run_health(self.healthy() + f"{name} 1\n").returncode, 1)

    def test_empty_and_failed_http_cannot_report_healthy(self):
        self.assertEqual(self.run_health("").returncode, 1)
        for text in ("", self.healthy()):
            result = self.run_health(text, status=7)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("UNVERIFIED", result.stderr)


class FlowSpecSmoke(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='sokol-rib-gate-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, target in [('python3', sys.executable), ('bash', '/bin/bash'), ('grep', '/usr/bin/grep'), ('sleep', '/usr/bin/true')]:
            (self.root / name).symlink_to(target)
        self.cli = self.root / 'gobgp'
        self.cli.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ['RIB_CALLS']).open('a') as calls:
    calls.write(json.dumps(args) + '\\n')
assert args == ['-p', '50052', 'global', 'rib', '-a', 'ipv4-flowspec'], args
sys.stdout.write(os.environ['RIB_OUTPUT'])
if int(os.environ['RIB_STATUS']):
    sys.stderr.write('rpc unavailable (probe)\\n')
sys.exit(int(os.environ['RIB_STATUS']))
''')
        self.cli.chmod(0o755)

    def run_assertion(self, command, output, status=0, through_check=False):
        calls = self.root / 'calls.jsonl'
        calls.unlink(missing_ok=True)
        helper = ROOT / 'scripts/flowspec-rib.sh'
        setup = 'ALLOWED_IP=10.231.0.2; BLOCKED_IP=10.231.0.3; FOREIGN_RULE=192.0.2.99/32\n'
        if helper.exists():
            setup = 'source "$RIB_HELPER"\n' + setup
        if through_check:
            smoke = (ROOT / 'scripts/xdp-smoke.sh').read_text()
            wrapper = re.search(r'^check\(\) \{\n.*?^\}', smoke, re.MULTILINE | re.DOTALL)
            if wrapper is None:
                raise AssertionError('missing smoke check wrapper')
            setup += wrapper.group() + '\nFAILED=0\n'
            command = 'check probe ' + command + '\nexit "$FAILED"'
        result = subprocess.run(
            ['bash', '-euo', 'pipefail', '-c', setup + command],
            env={**os.environ, 'PATH': str(self.root),
                 'RIB_HELPER': str(helper), 'RIB_CALLS': str(calls),
                 'RIB_OUTPUT': output, 'RIB_STATUS': str(status)},
            capture_output=True, text=True, timeout=3,
        )
        return result, calls

    def test_successful_reads_distinguish_presence_and_absence(self):
        for name, command in assertions().items():
            for output, present in [(RIB, True), ('', False)]:
                with self.subTest(name=name, present=present):
                    result, calls = self.run_assertion(command, output)
                    expected = 0 if (name in PRESENT) == present else 1
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertTrue(calls.exists(), 'assertion skipped the readback')
                    # Only the propagation waiter retries a known mismatch.
                    attempts = 20 if command.startswith('wait_flowspec_rule ') and expected == 1 else 1
                    self.assertEqual(len(calls.read_text().splitlines()), attempts)

    def test_unavailable_api_is_unverified_at_every_actual_call_site(self):
        for name, command in assertions().items():
            with self.subTest(name=name):
                result, calls = self.run_assertion(command, '', 7)
                self.assertEqual(result.returncode, 2, 'API error became a RIB verdict: ' + name)
                self.assertEqual(len(calls.read_text().splitlines()), 1, 'unverified reads must not be retried')

    def test_partial_output_before_cli_failure_cannot_authorize_either_verdict(self):
        for name, command in assertions().items():
            with self.subTest(name=name):
                result, _ = self.run_assertion(command, RIB, 7)
                self.assertEqual(result.returncode, 2, 'failed CLI output was trusted: ' + name)

    def test_a_missing_cli_is_unverified_at_every_actual_call_site(self):
        self.cli.unlink()
        for name, command in assertions().items():
            with self.subTest(name=name):
                result, _ = self.run_assertion(command, '')
                self.assertEqual(result.returncode, 2, 'missing CLI became a RIB verdict: ' + name)

    def test_failed_reads_make_the_actual_smoke_wrapper_fail(self):
        for name, command in assertions().items():
            for output in ['', RIB]:
                with self.subTest(name=name, partial=bool(output)):
                    result, _ = self.run_assertion(command, output, 7, through_check=True)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn('FAIL  probe', result.stdout)
                    self.assertNotIn('PASS', result.stdout)
                    self.assertIn('UNVERIFIED FlowSpec', result.stderr)

    def test_invalid_expectations_do_not_read_the_rib(self):
        for command in ['flowspec_rule unknown 10.231.0.2/32', 'flowspec_rule absent']:
            with self.subTest(command=command):
                result, calls = self.run_assertion(command, RIB)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(calls.exists())

    def test_source_prefix_is_literal_and_complete(self):
        cases = [
            ('10.231.0.2/32', '[source: 110.231.0.2/32]', False),
            ('10.231.0.2/32', '[source: 10.231.0.2/320]', False),
            ('10.231.0.2/32', '[source: 10x231x0x2/32]', False),
            ('10.231.0.2/32', '[source: 10.231.0.2/32]', True),
            ('*', '[source: 10.231.0.2/32]', False),
            ('*', '[source: *]', True),
        ]
        for prefix, output, present in cases:
            for expected in ['present', 'absent']:
                with self.subTest(prefix=prefix, output=output, expected=expected):
                    # shlex quotes the argument as data, including wildcard metacharacters.
                    command = 'flowspec_rule ' + expected + ' ' + shlex.quote(prefix)
                    result, _ = self.run_assertion(command, output)
                    self.assertEqual(result.returncode, 0 if (expected == 'present') == present else 1)


if __name__ == '__main__':
    unittest.main()
