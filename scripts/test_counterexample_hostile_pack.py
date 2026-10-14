"""scripts/counterexample-task.py: hostile evidence packs at the recipient.

Kept apart from test_counterexample_task.py, whose pinned witnesses (EXCHANGE-P1) pin that
module: a new test there would change their closure.

    SOKOL_WARRANT_BIN=/absolute/warrant-rs python3 scripts/test_counterexample_round7.py
"""
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location('counterexample_task', HERE / 'counterexample-task.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
W = tool.worker
SIGNERS = ROOT / '.github/witness-signers'


def green(name):
    return {'witness': name, 'status': 'PASS', 'returncode': 0,
            'output': f'test tests::{name} ... ok\ntest result: ok. 1 passed; 0 failed;'}


def red():
    return {'witness': W.FOCUS, 'status': 'ASSERTION_RED', 'returncode': 101,
            'output': f'assertion `left == right` failed: {W.ASSERTION}\n'
                      f'test tests::{W.FOCUS} ... FAILED\n0 passed; 1 failed;'}


def execution(descriptor=None):
    phases = []
    for label in ('repair', 'defect', 'restored'):
        phase = {'phase': label, 'build': {'status': 'BUILT', 'returncode': 0},
                 'witnesses': [red()] if label == 'defect' else [green(n) for n in W.WITNESSES]}
        if descriptor:
            phase['snapshot'] = descriptor['defect_snapshot' if label == 'defect' else 'repair_snapshot']
        phases.append(phase)
    return {'profile': 'sokol.counterexample-execution.v1', 'phases': phases}


class Interpretation(unittest.TestCase):
    def test_a_later_phase_on_another_source_is_source_mismatch_whatever_an_earlier_phase_says(self):
        # Docs: "each observed phase also carries its measured source snapshot. A different
        # source digest is SOURCE_MISMATCH". An early non-reproduction must not hide it.
        descriptor = {'repair_snapshot': 'a' * 64, 'defect_snapshot': 'b' * 64}
        value = execution(descriptor)
        row = value['phases'][0]['witnesses'][1]
        row.update(status='FAIL', returncode=101, output='test result: FAILED. 0 passed; 1 failed;')
        value['phases'][1]['snapshot'] = 'c' * 64
        self.assertEqual(tool.evaluate(value, descriptor), 'SOURCE_MISMATCH')
        value = execution(descriptor)
        value['phases'][0]['build'] = {'status': 'BUILD_ERROR', 'returncode': 101}
        value['phases'][0]['witnesses'] = []
        value['phases'][2]['snapshot'] = 'c' * 64
        self.assertEqual(tool.evaluate(value, descriptor), 'SOURCE_MISMATCH')


@unittest.skipUnless(os.environ.get('SOKOL_WARRANT_BIN'), 'set SOKOL_WARRANT_BIN for real released-CLI integration')
class HostilePack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='sokol-round7-')
        cls.base = Path(cls.tmp.name).resolve()
        cls.binary = Path(os.environ['SOKOL_WARRANT_BIN']).resolve()
        cls.key = cls.base / 'author.key'
        subprocess.run([str(cls.binary), 'keygen', '--out', str(cls.key)], check=True, stdout=subprocess.DEVNULL)
        cls.original = cls.base / 'exported'
        tool.export(cls.original, cls.binary, 'demo-author-NOT-A-MODEL-IDENTITY', cls.key, SIGNERS)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sokol-round7-attack-')
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name).resolve()
        self.pack = self.dir / 'pack'
        shutil.copytree(self.original, self.pack)
        self.manifest, self.desc, _, _, _ = tool.inspect(self.pack, self.binary, SIGNERS)

    def with_files(self, extra):
        """A producer-consistent descriptor (snapshots and unsigned context recomputed)."""
        descriptor = copy.deepcopy(self.desc)
        files = descriptor['files']
        for name, value in extra.items():
            files[name] = {'sha256': tool.put(self.pack, value), 'executable': False}
        descriptor['repair_snapshot'] = tool.digest(tool.encode(files))
        source = tool.blob(self.pack, files[W.CASE_FILE]['sha256']).decode()
        defect = copy.deepcopy(files)
        defect[W.CASE_FILE]['sha256'] = tool.digest(source.replace(W.BEFORE, W.AFTER).encode())
        descriptor['defect_snapshot'] = tool.digest(tool.encode(defect))
        context = tool.document(tool.blob(self.pack, descriptor['contract_context']))
        context['body']['snapshot'] = 'sha256:' + descriptor['repair_snapshot']
        context['id'] = 'sha256:' + tool.digest(tool.inputs.encode(context['body']))
        descriptor['contract_context'] = tool.put(self.pack, tool.inputs.encode(context))
        return descriptor

    def test_received_python_never_runs_in_the_recipient_owner_gate(self):
        # Code comment: "Never import Python from the received checkout." Docs: `inspect` and
        # `view` do not execute; candidate code runs only inside the isolated worker.
        marker = self.dir / 'received-code-ran-on-recipient-host'
        payload = ('import pathlib, sys\n'
                   f'pathlib.Path({str(marker)!r}).write_text("outside any sandbox")\n'
                   'del sys.modules["json"]\n'
                   'here = sys.path.pop(0)\n'
                   'import json as real\n'
                   'sys.path.insert(0, here)\n'
                   'sys.modules["json"] = real\n').encode()
        descriptor = self.with_files({'scripts/json.py': payload})
        try:
            tool.validate_descriptor(self.pack, descriptor, SIGNERS)
        except ValueError:
            pass
        self.assertFalse(marker.exists(), 'pack-supplied scripts/json.py was imported by the owner gate')

    def test_refused_observation_cannot_carry_a_native_pass_verdict(self):
        # Docs: "A structured resource refusal is recorded as prose plus evidence with no
        # `cmd@v1` pass/fail claim." The view must refuse a record that claims one anyway.
        run = {'profile': 'sokol.counterexample-execution.v1', 'refusal': 'TIME_BUDGET', 'phases': []}
        raw = (W.FRAME + tool.encode(run).decode() + '\n').encode()
        report = {'profile': 'sokol.counterexample-observation.v1', 'subject': self.manifest['subject'],
                  'status': 'REFUSED', 'execution': run, 'native_transcript': tool.put(self.pack, raw),
                  'native_returncode': 3}
        report_hash = tool.put(self.pack, tool.encode(report))
        wid = tool.file_record(self.pack, self.binary, self.manifest['subject'], 'demo-recipient', self.key,
                               [report_hash], self.manifest['proposal'],
                               {'status': 'REPRODUCED', 'native_transcript': report['native_transcript']})
        (self.pack / 'manifest.json').write_bytes(tool.encode({**self.manifest,
                                     'records': sorted([*self.manifest['records'], wid])}))
        envelope = tool.document(tool.read(self.pack / '.warrants/records' / (wid + '.json')))
        self.assertIn('pass', [r.get('verdict') for r in envelope['body']['because']])
        with self.assertRaisesRegex(ValueError, 'cmd@v1'):
            tool.view(self.pack, self.binary, SIGNERS)

    def test_a_record_citing_bytes_outside_the_pack_is_refused_by_inspect(self):
        # CANDIDATE: "An exported pack must be inspectable offline". The released verifier only
        # warns on a missing evidence blob; inspect accepted it and replay would re-sign it.
        report = {'profile': 'sokol.counterexample-observation.v1', 'subject': self.manifest['subject']}
        address = tool.put(self.pack, tool.encode(report))
        wid = tool.file_record(self.pack, self.binary, self.manifest['subject'], 'demo-recipient', self.key,
                               [address], self.manifest['proposal'])
        (self.pack / 'manifest.json').write_bytes(tool.encode({**self.manifest,
                                     'records': sorted([*self.manifest['records'], wid])}))
        (self.pack / '.warrants/blobs' / address).unlink()
        with self.assertRaises(FileNotFoundError):
            tool.inspect(self.pack, self.binary, SIGNERS)

    def test_names_that_collide_after_case_or_unicode_folding_are_refused(self):
        # CANDIDATE: the owner gate runs on the recipient's filesystem. On a case-insensitive or
        # normalising filesystem (macOS default) two descriptor names become one file, so the
        # gate checks a tree other than the snapshot Linux replay builds.
        for extra in ({'orchestrator/BUILD.rs': b'fn main() {}\n'},
                      {'docs/café.md': b'nfc\n', 'docs/café.md': b'nfd\n'}):
            descriptor = self.with_files(extra)
            with self.assertRaisesRegex(ValueError, 'collide'):
                tool.validate_descriptor(self.pack, descriptor, SIGNERS)


if __name__ == '__main__':
    unittest.main()
