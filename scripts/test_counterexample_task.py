"""Portable evidence must survive a recipient and fail for the intended reasons."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('counterexample_task', ROOT / 'scripts/counterexample-task.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
W = tool.worker


def green(name):
    return {'witness': name, 'status': 'PASS', 'returncode': 0,
            'output': f'test tests::{name} ... ok\ntest result: ok. 1 passed; 0 failed;'}


def red():
    return {'witness': W.FOCUS, 'status': 'ASSERTION_RED', 'returncode': 101,
            'output': f'assertion `left == right` failed: {W.ASSERTION}\n'
                      f'test tests::{W.FOCUS} ... FAILED\n0 passed; 1 failed;'}


def execution():
    return {'profile': 'sokol.counterexample-execution.v1', 'phases': [
        {'phase': label, 'build': {'status': 'BUILT', 'returncode': 0},
         'witnesses': [red()] if label == 'defect' else [green(n) for n in W.WITNESSES]}
        for label in ('repair', 'defect', 'restored')]}


class Interpretation(unittest.TestCase):
    def test_only_named_assertion_red_and_complete_repair_reproduce(self):
        self.assertEqual(tool.evaluate(execution()), 'REPRODUCED')
        value = execution()
        value['phases'][2]['witnesses'].pop()
        self.assertEqual(tool.evaluate(value), 'INCOMPLETE')
        value = execution()
        value['phases'][0]['build']['status'] = 'BUILD_ERROR'
        self.assertEqual(tool.evaluate(value), 'BUILD_ERROR')
        for text in ('error: could not compile', 'fixture did not receive a request',
                     '0 passed; 0 failed', 'assertion `left == right` failed: unrelated'):
            value = execution()
            value['phases'][1]['witnesses'][0]['output'] = text
            self.assertEqual(tool.evaluate(value), 'NOT_REPRODUCED')

    def test_author_status_cannot_override_transcript(self):
        for field, replacement in [('returncode', 0), ('status', 'PASS'), ('witness', 'another_test')]:
            value = execution()
            value['phases'][1]['witnesses'][0][field] = replacement
            self.assertNotEqual(tool.evaluate(value), 'REPRODUCED')
        value = execution()
        value['phases'][1]['witnesses'] = [green(W.FOCUS)]
        self.assertEqual(tool.evaluate(value), 'NOT_REPRODUCED')

    def test_unrun_budget_and_wrong_phase_are_never_success(self):
        self.assertEqual(tool.evaluate({'profile': 'sokol.counterexample-execution.v1',
                                       'refusal': 'TIME_BUDGET', 'phases': []}), 'REFUSED')
        value = execution()
        value['phases'].reverse()
        self.assertEqual(tool.evaluate(value), 'REFUSED')

    def test_executed_snapshot_must_equal_the_declared_phase(self):
        descriptor = {'repair_snapshot': 'a' * 64, 'defect_snapshot': 'b' * 64}
        value = execution()
        for phase in value['phases']:
            phase['snapshot'] = descriptor['defect_snapshot'] if phase['phase'] == 'defect' else descriptor['repair_snapshot']
        self.assertEqual(tool.evaluate(value, descriptor), 'REPRODUCED')
        value['phases'][1]['snapshot'] = 'c' * 64
        self.assertEqual(tool.evaluate(value, descriptor), 'SOURCE_MISMATCH')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b'fn main() {}\r\n'
            (root / 'main.rs').write_bytes(data)
            files = {'main.rs': {'sha256': tool.digest(data), 'executable': False}}
            self.assertEqual(W.source_snapshot(root), tool.digest(tool.encode(files)))
            (root / 'main.rs').chmod(0o755)
            self.assertNotEqual(W.source_snapshot(root), tool.digest(tool.encode(files)))

    def test_fixed_isolation_profile_exposes_no_home_key_or_network(self):
        argv = tool.sandbox(Path('/selected/source'), Path('/selected/toolchain'),
                            Path('/selected/registry'), Path('/selected/worker'))
        for option in ('--unshare-all', '--clearenv', '--die-with-parent', '--new-session'):
            self.assertIn(option, argv)
        for limit in (f'MemoryMax={tool.MEMORY_BYTES}', f'TasksMax={tool.MAX_TASKS}',
                      f'RuntimeMaxSec={tool.TOTAL_SECONDS}', 'KillMode=control-group'):
            self.assertIn(limit, argv)
        self.assertNotIn('--share-net', argv)
        self.assertNotIn('--bind', argv)
        self.assertNotIn('/', [argv[i+1] for i, a in enumerate(argv[:-1]) if a == '--ro-bind'])
        self.assertEqual(argv[-2:], ['/usr/bin/python3', '/runner.py'])

    def test_json_and_paths_are_closed_before_execution(self):
        for value in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.5}'):
            with self.assertRaises(ValueError):
                tool.document(value)
        for path in ('../escape', '/abs', 'a//b', '.git/config', '.cargo/config.toml', 'a\\b'):
            with self.assertRaises(ValueError):
                tool.safe_source(path)
        self.assertEqual(tool.safe_source('ebpf/.cargo/config.toml'), 'ebpf/.cargo/config.toml')

    def test_pack_rejects_extra_directories_symlinks_and_misaddressed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            pack = Path(directory).resolve()
            (pack / 'extra').mkdir()
            with self.assertRaisesRegex(ValueError, 'directory'):
                tool.inventory(pack)
            (pack / 'extra').rmdir()
            (pack / 'extra').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'Symlink'):
                tool.inventory(pack)
            (pack / 'extra').unlink()
            address = tool.put(pack, b'good')
            (pack / '.warrants/blobs' / address).write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError, 'address'):
                tool.inventory(pack)

    def test_output_and_verifier_budgets_refuse_instead_of_trusting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'binary'
            path.write_bytes(b'not the selected verifier')
            with self.assertRaisesRegex(ValueError, 'digest'):
                tool.selected_verifier(path, '0' * 64)
            with patch.object(tool, 'MAX_BLOB', 4):
                with self.assertRaisesRegex(ValueError, 'byte bound'):
                    tool.read(path)

    def test_private_cargo_registry_is_not_exposed_to_candidate_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'src' / 'index.crates.io-1949cf8c6b5b557f').mkdir(parents=True)
            tool.registry_layout(path)
            (path / 'src' / 'private-registry').mkdir()
            with self.assertRaisesRegex(ValueError, 'Private or unsupported'):
                tool.registry_layout(path)

    def test_output_cancellation_stops_the_service_not_only_its_client(self):
        with patch.object(tool.inputs, 'run_bounded', side_effect=ValueError('Verifier exceeded output bound')):
            with patch.object(tool.subprocess, 'run') as stop:
                with self.assertRaisesRegex(ValueError, 'output bound'):
                    tool.isolated_run(Path('/src'), Path('/tools'), Path('/registry'), Path('/worker'))
                argv = stop.call_args.args[0]
                self.assertEqual(argv[:3], ['/usr/bin/systemctl', '--user', 'stop'])
                self.assertRegex(argv[3], r'^sokol-counterexample-[a-f0-9]{32}\.service$')


@unittest.skipUnless(os.environ.get('SOKOL_WARRANT_BIN'), 'set SOKOL_WARRANT_BIN for real released-CLI integration')
class PublicWarrant(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='sokol-warrant-specimen-')
        cls.base = Path(cls.tmp.name).resolve()
        cls.binary = Path(os.environ['SOKOL_WARRANT_BIN']).resolve()
        cls.key = cls.base / 'author.key'
        subprocess.run([str(cls.binary), 'keygen', '--out', str(cls.key)], check=True, stdout=subprocess.DEVNULL)
        cls.original = cls.base / 'exported'
        tool.export(cls.original, cls.binary, 'demo-author-NOT-A-MODEL-IDENTITY', cls.key,
                    ROOT / '.github/witness-signers')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sokol-pack-attack-')
        self.addCleanup(self.temp.cleanup)
        self.pack = Path(self.temp.name).resolve() / 'pack'
        shutil.copytree(self.original, self.pack)
        self.manifest, self.desc, _, _, _ = self.inspect()

    def inspect(self):
        return tool.inspect(self.pack, self.binary, ROOT / '.github/witness-signers')

    def test_real_export_is_signed_but_never_claims_execution_or_actor_binding(self):
        value = tool.view(self.pack, self.binary, ROOT / '.github/witness-signers')
        self.assertEqual(value['observations'], [])
        self.assertTrue(any('binding unverified' in row['message'] for row in value['warrant_findings']))
        self.assertEqual(value['defect_origin'], 'DERIVED_COUNTERFACTUAL_NOT_HISTORICAL_COMMIT')
        self.assertFalse(list(self.pack.rglob('*.key')))

    def test_proposal_signature_and_subject_substitution_are_refused(self):
        path = self.pack / '.warrants/records' / (self.manifest['proposal'] + '.json')
        envelope = tool.document(tool.read(path))
        envelope['sigs'][0]['sig'] = '0' * 128
        path.write_bytes(tool.encode(envelope))
        with self.assertRaisesRegex(ValueError, 'Warrant verification'):
            self.inspect()
        envelope['body']['subject']['hash'] = '0' * 64
        path.write_bytes(tool.encode(envelope))
        with self.assertRaisesRegex(ValueError, 'outside experimental'):
            self.inspect()

    def test_blob_and_owner_signature_tampering_are_refused(self):
        entry = self.desc['files'][W.CASE_FILE]
        (self.pack / '.warrants/blobs' / entry['sha256']).write_bytes(b'changed source')
        with self.assertRaisesRegex(ValueError, 'address'):
            self.inspect()

    def test_readdressing_a_changed_witness_cannot_bypass_owner_pin(self):
        source = tool.blob(self.pack, self.desc['files'][W.CASE_FILE]['sha256']).decode()
        source = source.replace('lost reply cannot prove rejection:', 'this changed witness is not signed:')
        self.desc['files'][W.CASE_FILE]['sha256'] = tool.put(self.pack, source.encode())
        self.desc['repair_snapshot'] = tool.digest(tool.encode(self.desc['files']))
        defect = copy.deepcopy(self.desc['files'])
        defect[W.CASE_FILE]['sha256'] = tool.digest(source.replace(W.BEFORE, W.AFTER).encode())
        self.desc['defect_snapshot'] = tool.digest(tool.encode(defect))
        context = tool.document(tool.blob(self.pack, self.desc['contract_context']))
        context['body']['snapshot'] = 'sha256:' + self.desc['repair_snapshot']
        context['id'] = 'sha256:' + tool.digest(tool.inputs.encode(context['body']))
        self.desc['contract_context'] = tool.put(self.pack, tool.inputs.encode(context))
        with self.assertRaisesRegex(ValueError, 'Witness differs from owner pin'):
            tool.validate_descriptor(self.pack, self.desc, ROOT / '.github/witness-signers')

    def test_recipient_signers_and_local_method_are_not_selected_by_pack(self):
        with self.assertRaisesRegex(ValueError, 'signer identity'):
            tool.validate_descriptor(self.pack, self.desc, self.key)
        self.desc['worker_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'local method'):
            tool.validate_descriptor(self.pack, self.desc, ROOT / '.github/witness-signers')

    def test_unchanged_body_does_not_hide_changed_test_attributes_or_build_script(self):
        for name, changed in (
            (W.CASE_FILE, tool.blob(self.pack, self.desc['files'][W.CASE_FILE]['sha256']).replace(
                b'#[tokio::test]\n    async fn a_command_applied',
                b'#[ignore]\n    #[tokio::test]\n    async fn a_command_applied')),
            ('orchestrator/build.rs', b'fn main() { println!("cargo:rustc-cfg=disable_witnesses"); }'),
        ):
            descriptor = copy.deepcopy(self.desc)
            files = descriptor['files']
            files[name]['sha256'] = tool.put(self.pack, changed)
            descriptor['repair_snapshot'] = tool.digest(tool.encode(files))
            source = tool.blob(self.pack, files[W.CASE_FILE]['sha256']).decode()
            defect = copy.deepcopy(files)
            defect[W.CASE_FILE]['sha256'] = tool.digest(source.replace(W.BEFORE, W.AFTER).encode())
            descriptor['defect_snapshot'] = tool.digest(tool.encode(defect))
            context = tool.document(tool.blob(self.pack, descriptor['contract_context']))
            context['body']['snapshot'] = 'sha256:' + descriptor['repair_snapshot']
            context['id'] = 'sha256:' + tool.digest(tool.inputs.encode(context['body']))
            descriptor['contract_context'] = tool.put(self.pack, tool.inputs.encode(context))
            with self.assertRaisesRegex(ValueError, 'owner gate refused'):
                tool.validate_descriptor(self.pack, descriptor, ROOT / '.github/witness-signers')

    def test_inconsistent_verifier_report_does_not_pass_on_counts_alone(self):
        _, _, _, records, report = self.inspect()
        for change in ({'grade': 'settlement'}, {'ok': False}, {'records': len(records)+1}, {'warnings': 0}):
            bad = {**report, **change}
            with patch.object(tool, 'warrant', return_value=(0, tool.encode(bad))):
                with self.assertRaisesRegex(ValueError, 'report is inconsistent'):
                    self.inspect()

    def observation(self, status='REPRODUCED', subject=None):
        run = execution()
        for phase in run['phases']:
            phase['snapshot'] = self.desc['defect_snapshot'] if phase['phase'] == 'defect' else self.desc['repair_snapshot']
        report = {'profile': 'sokol.counterexample-observation.v1', 'subject': subject or self.manifest['subject'],
                  'status': status, 'execution': run}
        report_hash = tool.put(self.pack, tool.encode(report))
        wid = tool.file_record(self.pack, self.binary, self.manifest['subject'], 'demo-recipient', self.key,
                              [report_hash], self.manifest['proposal'], report)
        (self.pack / 'manifest.json').write_bytes(tool.encode({**self.manifest,
                                     'records': sorted([*self.manifest['records'], wid])}))
        return wid

    def test_recipient_reply_is_prior_linked_and_view_does_not_upgrade_execution(self):
        wid = self.observation()
        value = tool.view(self.pack, self.binary, ROOT / '.github/witness-signers')
        self.assertEqual(value['observations'][0]['warrant'], wid)
        self.assertEqual(value['observations'][0]['execution'], 'RECORDED_NOT_REPLAYED')
        self.assertIn('RECORDED_NOT_REPLAYED', tool.markdown(value))

    def test_forged_status_and_wrong_subject_never_become_reproduced(self):
        self.observation('FRESH_LOCAL_RUN')
        with self.assertRaisesRegex(ValueError, 'contradicts transcript'):
            tool.view(self.pack, self.binary, ROOT / '.github/witness-signers')
        shutil.rmtree(self.pack)
        shutil.copytree(self.original, self.pack)
        self.observation(subject='0' * 64)
        with self.assertRaisesRegex(ValueError, 'not bound'):
            tool.view(self.pack, self.binary, ROOT / '.github/witness-signers')


if __name__ == '__main__':
    unittest.main()
