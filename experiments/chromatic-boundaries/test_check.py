import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check


class ChromaticExperiment(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((check.HERE / 'manifest.json').read_text())

    def test_declared_ports_accept_baseline(self):
        self.assertEqual(check.check_ports(self.manifest['ports']), [])

    def test_policy_cannot_acquire_io_through_port(self):
        ports = self.manifest['ports']
        ports['endpoints']['policy.observation']['effects'] = ['disk']
        self.assertIn('effect budget', '\n'.join(check.check_ports(ports)))

    def test_exporter_cannot_acquire_block_authority(self):
        ports = self.manifest['ports']
        ports['endpoints']['exporter.evidence']['requires'] = ['apply_block']
        ports['endpoints']['exporter.evidence']['effects'].append('kernel')
        errors = '\n'.join(check.check_ports(ports))
        self.assertIn('authority', errors)
        self.assertIn('effect budget', errors)

    def test_network_cannot_change_trust_even_with_correct_schema_and_effects(self):
        ports = self.manifest['ports']
        ports['connections'].append(['peer.trust-shaped', 'trust.update'])
        errors = check.check_ports(ports)
        self.assertEqual(len(errors), 1)
        self.assertIn('missing', errors[0])
        self.assertIn('change_trust', errors[0])

    def test_observation_cannot_become_command(self):
        ports = self.manifest['ports']
        ports['connections'].append(['detector.observation', 'enforcement.apply'])
        errors = '\n'.join(check.check_ports(ports))
        for kind in ['schema', 'authority', 'effect budget']:
            self.assertIn(kind, errors)

    def test_same_schema_does_not_grant_apply(self):
        ports = self.manifest['ports']
        ports['connections'].append(['peer.proposal', 'enforcement.apply'])
        self.assertIn('authority', '\n'.join(check.check_ports(ports)))

    def test_unknown_endpoint_and_reversed_direction(self):
        ports = self.manifest['ports']
        ports['connections'] += [['absent', 'trust.update'], ['trust.update', 'operator.trust']]
        # Reversed endpoints must be rejected without trying missing direction-specific fields.
        errors = check.check_ports(ports)
        self.assertTrue(any('unknown endpoint' in x for x in errors))
        self.assertTrue(any('direction' in x for x in errors))

    def test_source_mutation_is_detected_without_changing_manifest(self):
        spec = {'modules': {'policy': {'path': 'policy.rs'}, 'io': {'path': 'io.rs'}},
                'aliases': {}, 'pure_module_hypotheses': ['policy'],
                'ports': {'endpoints': {}, 'connections': []}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'policy.rs').write_text('pub fn decide(x: bool) -> bool { x }')
            (root / 'io.rs').write_text('pub fn read() { std::fs::read_to_string("x"); }')
            self.assertEqual(check.audit(root, spec)['hypotheses'][0]['status'], 'unknown')
            (root / 'policy.rs').write_text('pub fn decide() { crate::io::read(); }')
            result = check.audit(root, spec)
            self.assertEqual(result['hypotheses'][0]['witnesses'][0]['path'], ['policy', 'io'])
            self.assertIn('disk', result['nodes']['policy']['reachable'])

    def test_masks_nested_comments_raw_strings_and_test_module(self):
        source = '''// std::fs::read_to_string("x")
/* outer /* aya::maps */ TcpStream */
const X: &str = r##"crate::io::x(); println!(\"hi\")"##;
#[cfg(test)] mod tests { fn x() { std::fs::read_to_string("x"); } }
'''
        got = check.inspect_source(source, {'io'}, {})
        self.assertEqual(got['signals'], [])
        self.assertEqual(got['dependencies'], [])

    def test_pure_local_mutation_does_not_imply_effect(self):
        got = check.inspect_source('fn f(x: i32) -> i32 { let mut y = x; y += 1; y }', set(), {})
        self.assertEqual(got['signals'], [])

    def test_cycle_terminates_and_union_preserves_signal(self):
        graph = {'a': ['b'], 'b': ['a', 'c'], 'c': []}
        self.assertEqual(check.closure(graph, 'a')['c'], ['a', 'b', 'c'])
        self.assertEqual(check.rgb({'disk'} | {'network'}), '#FF0')
        self.assertEqual(check.rgb({'disk'} | set()), '#F00')

    def test_equal_color_does_not_prove_dag(self):
        self.assertEqual(check.rgb({'disk'}), check.rgb({'kernel'}))
        self.assertIn('b', check.closure({'a': ['b'], 'b': ['a']}, 'a'))

    def test_no_detection_is_explicitly_not_purity(self):
        # Deliberately unsupported alias/call resolution: document a surviving blind spot.
        got = check.inspect_source('use std::fs::read as fetch; fn f() { fetch("x"); }', set(), {})
        self.assertIn('disk', {s['kind'] for s in got['signals']})
        got = check.inspect_source('fn f() { some_external_crate::hidden_io(); }', set(), {})
        self.assertEqual(got['signals'], [])

    def test_port_cli_rejects_mutant_with_nonzero_status(self):
        self.manifest['ports']['connections'].append(['peer.trust-shaped', 'trust.update'])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'mutant.json'
            path.write_text(json.dumps(self.manifest))
            run = subprocess.run([sys.executable, str(check.HERE / 'check.py'),
                                  '--manifest', str(path), '--ports-only'], capture_output=True, text=True)
            self.assertEqual(run.returncode, 1)
            self.assertIn('change_trust', run.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
