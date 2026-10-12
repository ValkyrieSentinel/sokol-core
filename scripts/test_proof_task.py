"""Calibration must distinguish a property's counterexample from missing or broken evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('proof_task', ROOT / 'scripts/proof-task.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class ProofTask(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        # Every source the catalog challenges, so a new proof file needs no edit here.
        sources = sorted({c['file'] for c in json.loads((ROOT / tool.CATALOG).read_text())['cases']})
        for name in ('scripts/proof-task.py', 'scripts/contract-task.py', tool.CATALOG,
                     *sources, '.github/workflows/ci.yml'):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', 'add', '-A'], cwd=self.root, check=True)
        self.cases, _ = tool.catalog(self.root)

    def result(self, cases=None, failed=False):
        cases = self.cases if cases is None else cases
        rows = [{'harness_id': c['harness'], 'status': 'Failure' if failed else 'Success',
                 'checks': [{'category': 'assertion', 'function': c['harness'],
                             'description': c['assertion'], 'status': 'Failure' if failed else 'Success'}]}
                for c in cases]
        return {'metadata': {'version': '1.0', 'kani_version': '0.68.0'},
                'error_details': [{'harness_id': c['harness'], 'has_errors': failed,
                                   'error_type': 'assertion_failure', 'exit_status': 'properties_failed'} for c in cases],
                'verification_results': {'summary': {'status': 'completed', 'executed': len(rows),
                    'total_harnesses': len(rows), 'successful': 0 if failed else len(rows),
                    'failed': len(rows) if failed else 0}, 'results': rows}}

    def evaluate(self, value, code=0, case=None):
        return tool.evaluate(value, self.cases, '0.68.0', code, case)

    def test_complete_baseline_and_assertion_counterexample_are_distinct(self):
        self.assertEqual(self.evaluate(self.result()), 'PASS')
        case = self.cases[0]
        self.assertEqual(self.evaluate(self.result([case], True), 1, case), 'CAUGHT')
        self.assertEqual(self.evaluate(self.result([case]), 0, case), 'NOT_CAUGHT')

    def test_empty_proof_never_calibrates(self):
        value = self.result()
        value['verification_results']['results'][0]['checks'] = []
        with self.assertRaisesRegex(ValueError, 'Missing checks'):
            self.evaluate(value)

    def test_trivial_assertions_cannot_substitute_for_the_declared_assertion(self):
        value = self.result()
        value['verification_results']['results'][0]['checks'][0]['description'] = 'assertion failed: true'
        self.assertEqual(self.evaluate(value), 'FAIL')

    def test_assume_false_and_unwinding_failures_are_not_counterexamples(self):
        value = self.result()
        value['verification_results']['results'][0]['checks'][0]['status'] = 'Unreachable'
        self.assertEqual(self.evaluate(value), 'FAIL')
        for status in ('Undetermined', 'Unknown'):
            value = self.result()
            value['verification_results']['results'][0]['checks'][0]['status'] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.evaluate(value)
        case = self.cases[0]
        value = self.result([case], True)
        value['verification_results']['results'][0]['checks'][0]['category'] = 'unwind'
        self.assertEqual(self.evaluate(value, 1, case), 'NOT_CAUGHT')

    def test_unreachable_library_paths_do_not_erase_a_reached_property(self):
        value = self.result()
        value['verification_results']['results'][0]['checks'].append({
            'category': 'assertion', 'function': 'library', 'description': 'unreachable panic',
            'status': 'Unreachable'})
        self.assertEqual(self.evaluate(value), 'PASS')

    def test_crash_or_timeout_cannot_be_a_caught_mutation(self):
        case = self.cases[0]
        for code in (0, 2, -9, 137):
            with self.subTest(code=code):
                self.assertEqual(self.evaluate(self.result([case], True), code, case), 'NOT_CAUGHT')

    def test_out_of_memory_is_unknown_even_beside_claimed_assertion_failures(self):
        case = self.cases[0]
        value = self.result([case], True)
        value['error_details'][0].update(error_type='verification_failure', exit_status='out_of_memory')
        with self.assertRaisesRegex(ValueError, 'resource or tool failure'):
            self.evaluate(value, 1, case)

    def test_an_unrelated_failure_cannot_qualify_an_assertion(self):
        case = self.cases[0]
        for key, value in (('description', 'assertion failed: unrelated'), ('function', 'elsewhere'),
                           ('category', 'pointer_dereference')):
            data = self.result([case], True)
            data['verification_results']['results'][0]['checks'][0][key] = value
            self.assertEqual(self.evaluate(data, 1, case), 'NOT_CAUGHT')
        data = self.result([case], True)
        data['verification_results']['results'][0]['checks'].append({
            'category': 'overflow', 'function': 'elsewhere', 'description': 'overflow', 'status': 'Failure'})
        self.assertEqual(self.evaluate(data, 1, case), 'NOT_CAUGHT')

    def test_harness_inventory_is_closed_not_a_successful_subset(self):
        for cases in (self.cases[:-1], self.cases + [self.cases[0]]):
            with self.subTest(count=len(cases)), self.assertRaises(ValueError):
                self.evaluate(self.result(cases))
        value = self.result()
        value['verification_results']['results'][0]['harness_id'] = 'elsewhere'
        with self.assertRaises(ValueError):
            self.evaluate(value)

    def test_incomplete_and_foreign_verifier_output_is_refused(self):
        for key, field, replacement in (('metadata', 'kani_version', '0.67.0'),
                                        ('metadata', 'version', '2.0')):
            value = self.result()
            value[key][field] = replacement
            with self.assertRaises(ValueError):
                self.evaluate(value)
        value = self.result()
        value['verification_results']['summary']['status'] = 'timeout'
        with self.assertRaises(ValueError):
            self.evaluate(value)

    def test_summary_cannot_claim_success_for_failed_checks(self):
        value = self.result()
        value['verification_results']['results'][0]['checks'][0]['status'] = 'Failure'
        with self.assertRaises(ValueError):
            self.evaluate(value)
        value = self.result()
        value['verification_results']['summary']['successful'] += 1
        with self.assertRaises(ValueError):
            self.evaluate(value)

    def test_patch_anchor_changes_and_noop_patches_are_refused(self):
        path = self.root / tool.CATALOG
        original = path.read_bytes()
        for mutation in ('absent', 'noop', 'duplicate', 'traversal', 'unbounded'):
            data = json.loads(original)
            case = data['cases'][0]
            if mutation == 'absent':
                case['replace']['before'] = 'missing anchor'
            elif mutation == 'noop':
                case['replace']['after'] = case['replace']['before']
            elif mutation == 'duplicate':
                data['cases'].append(copy.deepcopy(case))
            elif mutation == 'traversal':
                case['file'] = 'common/src/../../elsewhere.rs'
            else:
                case['replace']['after'] = 'x' * (tool.MAX_PATCH_BYTES + 1)
            path.write_text(json.dumps(data))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                tool.catalog(self.root)
        path.write_bytes(original)

    def test_context_is_small_unknown_and_changes_with_inputs(self):
        packet, _ = tool.context(self.root)
        self.assertEqual(packet, tool.context(self.root)[0])
        self.assertLess(len(tool.encode(packet)), tool.inputs_tool.MAX_PACKET_BYTES)
        self.assertEqual(packet['body']['execution'], 'UNKNOWN')
        self.assertEqual(packet['body']['authority'], 'UNSIGNED_NEGATIVE_CONTROLS')
        path = self.root / 'common/src/audit_log.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        self.assertNotEqual(packet, tool.context(self.root)[0])

    def test_fast_context_names_one_harness_and_never_claims_full_inventory(self):
        packet, _ = tool.context(self.root, 'genesis')
        self.assertEqual(packet['body']['inventory_scope'], 'NAMED_HARNESS_ONLY')
        self.assertEqual(packet['body']['harnesses'], [self.cases[0]['harness']])
        self.assertEqual(len(packet['body']['challenges']), 1)
        with self.assertRaisesRegex(ValueError, 'Unknown challenge'):
            tool.context(self.root, '--import-command')

    def report(self):
        context, files = tool.context(self.root)
        return {'profile': 'sokol.agent.proof-run.v1', 'context': context, 'inputs': files,
                'execution': {'status': 'RECORDED_CALIBRATED'}, 'command': ['malicious-import']}

    def test_forged_unsigned_report_never_establishes_execution(self):
        result = tool.verify(self.root, self.report())
        self.assertEqual(result['binding'], 'MATCH')
        self.assertEqual(result['execution'], 'UNKNOWN')
        self.assertEqual(result['historical_execution'], 'UNVERIFIED')

    def test_replay_ignores_imported_commands_and_execution_claims(self):
        report = self.report()
        fresh = copy.deepcopy(report)
        fresh['execution']['status'] = 'RECORDED_NOT_CALIBRATED'
        with patch.object(tool, 'make_report', return_value=fresh) as runner:
            result = tool.verify(self.root, report, replay=True)
            runner.assert_called_once()
        self.addCleanup(shutil.rmtree, result['artifacts'])
        self.assertEqual(result['execution'], 'REPLAYED_NOT_CALIBRATED')

    def test_source_change_makes_report_stale_without_execution(self):
        report = self.report()
        path = self.root / 'common/src/canonical.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        with patch.object(tool, 'make_report') as runner:
            self.assertEqual(tool.verify(self.root, report, replay=True), {'binding': 'STALE', 'execution': 'UNKNOWN'})
            runner.assert_not_called()

    def test_private_mutation_cannot_change_the_original_checkout(self):
        _, files = tool.context(self.root)
        path = self.root / self.cases[0]['file']
        original = path.read_bytes()
        with tool.inputs_tool.copied_inputs(self.root, files) as work:
            target = work / self.cases[0]['file']
            target.write_text(target.read_text().replace(self.cases[0]['replace']['before'], 'false'))
            self.assertEqual(path.read_bytes(), original)
            self.assertNotEqual(target.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
