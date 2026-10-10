"""Counterexamples to a shadow projection's correspondence and status boundaries."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import subprocess
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('contract_shadow', ROOT / 'scripts/contract-shadow.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class ContractShadow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        for name in tool.INPUTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        # Every row is generated (ADR-0024), so the gate needs every contract, not only IPC-A1's.
        for source in (ROOT / 'docs/contracts').glob('*.shadow.json'):
            shutil.copyfile(source, self.root / 'docs/contracts' / source.name)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, edit):
        path = self.root / tool.SOURCE
        value = json.loads(path.read_text())
        edit(value)
        path.write_text(json.dumps(value))

    def test_matching_bytes_never_promote_signature_execution_or_acceptance(self):
        original_run = subprocess.run
        def signature_only(command, **kwargs):
            self.assertEqual(command[:3], ['ssh-keygen', '-Y', 'verify'])
            return original_run(command, **kwargs)
        with patch('subprocess.run', side_effect=signature_only):
            md, packet, document = tool.project(self.root)
            self.assertEqual((md, packet, document), tool.project(self.root))
        self.assertIn('overflow test above', md)
        self.assertLessEqual(len(tool.encode(packet)), 16384)
        self.assertEqual(packet['body']['execution']['status'], 'UNKNOWN')
        self.assertEqual(packet['body']['binding']['owner_signature'], 'VERIFIED_AGAINST_SUPPLIED_SIGNERS')
        self.assertEqual(packet['body']['binding']['draft_acceptance'], 'NOT_ESTABLISHED')

    def test_reworded_statement_is_refused(self):
        self.change(lambda v: v.update(statement='ACK proves kernel enforcement.'))
        with self.assertRaisesRegex(ValueError, 'pinned statement'):
            tool.project(self.root)

    def test_dropped_witness_is_refused(self):
        self.change(lambda v: v['witnesses'].pop())
        with self.assertRaisesRegex(ValueError, 'witness list'):
            tool.project(self.root)

    def test_weakened_witness_assertion_is_refused(self):
        path = self.root / 'orchestrator/src/delivery.rs'
        text = path.read_text()
        marker = 'fn an_unterminated_ack_does_not_retire_the_signal()'
        before, body = text.split(marker, 1)
        body = body.replace('assert_eq!((out.pending(), out.lost), (1, 0));',
                            'assert_eq!((out.pending(), out.lost), (0, 0));', 1)
        path.write_text(before + marker + body)
        with self.assertRaisesRegex(ValueError, 'Witness body differs'):
            tool.project(self.root)

    def test_unsigned_annotation_cannot_be_labelled_accepted(self):
        self.change(lambda v: v['annotations'].update(status='ACCEPTED'))
        with self.assertRaisesRegex(ValueError, 'unsigned draft'):
            tool.project(self.root)

    def test_changed_explanation_changes_packet_identity_without_signed_claim(self):
        _, first, _ = tool.project(self.root)
        self.change(lambda v: v['annotations'].update(answer='A different explanatory draft.'))
        _, second, _ = tool.project(self.root)
        self.assertNotEqual(first['id'], second['id'])
        self.assertEqual(second['body']['binding']['annotations'], 'UNSIGNED')

    def test_coordinated_contract_and_manifest_tamper_refuses_unsigned_manifest(self):
        self.change(lambda v: v.update(statement='ACK proves kernel enforcement.'))
        path = self.root / 'docs/witness-manifest.json'
        value = json.loads(path.read_text())
        value['rows']['IPC-A1']['statement'] = tool.digest(b'ACK proves kernel enforcement.')
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'signature verification failed'):
            tool.project(self.root)

    def test_stale_display_is_regenerated_from_contract(self):
        path = self.root / 'docs/INVARIANTS.md'
        text = path.read_text()
        old = next(x for x in text.splitlines() if x.startswith('| IPC-A1 |'))
        path.write_text(text.replace(old, '| IPC-A1 | stale display | stale evidence |'))
        _, packet, document = tool.project(self.root)
        self.assertIn(old, document)
        self.assertNotIn('stale display', document)
        self.assertEqual(packet['body']['binding']['legacy_row'], 'GENERATED_FROM_CONTRACT')
        # The actual gate refuses this stale checked-in projection.
        spec = importlib.util.spec_from_file_location('gate_test', self.root / 'scripts/witness-pin.py')
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with self.assertRaisesRegex(ValueError, 'stale'):
            gate.rows()

    def test_removed_declaration_cannot_detach_sources_from_gate(self):
        path = self.root / 'docs/INVARIANTS.md'
        text = path.read_text()
        path.write_text('\n'.join(x for x in text.splitlines() if not x.startswith('<!-- Every invariant row')))
        with self.assertRaisesRegex(ValueError, 'generated IPC-A1 slot'):
            tool.project(self.root)
        with self.assertRaisesRegex(ValueError, 'generated [A-Z0-9-]+ slot'):
            self.gate().rows()

    def gate(self):
        spec = importlib.util.spec_from_file_location('generic_gate', self.root / 'scripts/witness-pin.py')
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        return gate

    def test_gate_accepts_multiple_arbitrary_contract_ids(self):
        gate = self.gate()
        base = json.loads((self.root / tool.SOURCE).read_text())
        path = self.root / 'docs/INVARIANTS.md'
        for rid in ('DEMO-A2', 'QUEUE-B7'):
            contract = {**base, 'id': rid, 'statement': 'A second independent contract.'}
            source = self.root / ('docs/contracts/' + rid + '.shadow.json')
            source.write_text(json.dumps(contract))
            path.write_text(path.read_text() + '\n' + gate.contract_row(contract) + '\n')
        rows = gate.rows()
        self.assertIn('DEMO-A2', rows)
        self.assertIn('QUEUE-B7', rows)
        self.assertIn('IPC-A1', rows)

    def test_contract_filename_cannot_alias_another_id(self):
        path = self.root / tool.SOURCE
        path.rename(path.with_name('ALIAS-X1.shadow.json'))
        with self.assertRaisesRegex(ValueError, 'filename differs'):
            self.gate().rows()

    def test_missing_source_leaves_its_row_unbacked(self):
        (self.root / tool.SOURCE).unlink()
        with self.assertRaisesRegex(ValueError, 'IPC-A1 has no contract source'):
            self.gate().rows()

    def test_duplicate_row_cannot_override_a_generated_row(self):
        path = self.root / 'docs/INVARIANTS.md'
        row = next(x for x in path.read_text().splitlines() if x.startswith('| IPC-A1 |'))
        path.write_text(path.read_text() + row + '\n')
        with self.assertRaisesRegex(ValueError, 'needs exactly one row'):
            self.gate().rows()

    def test_symlink_input_is_refused(self):
        path = self.root / tool.SOURCE
        path.unlink()
        path.symlink_to(ROOT / tool.SOURCE)
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            tool.project(self.root)


if __name__ == '__main__':
    unittest.main()
