"""Candidate completeness, hostile archives and install/remove effects."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('candidate.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
REPO = tool.ROOT


class Candidate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source, self.binaries = self.root / 'source', self.root / 'binaries'
        self.source.mkdir(); self.binaries.mkdir()
        inventory = json.loads((REPO / 'deploy/candidate.json').read_text())
        for row in inventory['files']:
            source = row['source']
            path = self.binaries / source[7:] if source.startswith('binary:') else self.source / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source.encode())
        (self.source / 'deploy/candidate.json').write_text(json.dumps(inventory))
        for path in ('Cargo.lock', 'ebpf/Cargo.lock'):
            (self.source / path).write_text('fixture lock')
        self.commit = '1' * 40
        self.output = self.root / 'candidate.tar.gz'
        def command(argv, **kwargs):
            if argv[:2] == ['git', 'status']: return b''
            if argv[:2] == ['git', 'rev-parse']: return self.commit.encode()
            if argv[-1] == '--version': return ('orchestrator 0.1.0 (build ' + self.commit[:12] + ')').encode()
            return b'fixture tool version'
        for helper in (patch.object(tool, 'ROOT', self.source), patch.object(tool, 'command', side_effect=command),
                       patch.object(tool, 'arch', return_value='aarch64'),
                       patch.object(tool, 'sbom', return_value={'spdxVersion': 'SPDX-2.3'}),
                       patch.object(tool.platform, 'system', return_value='Linux')):
            helper.start(); self.addCleanup(helper.stop)

    def build(self):
        result = tool.build(self.binaries, self.output)
        return result['sha256']

    def repackage(self, mutate):
        with tarfile.open(self.output, 'r:gz') as original:
            entries = [(entry, original.extractfile(entry).read()) for entry in original]
        mutate(entries)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            for item, data in entries:
                archive.addfile(item, io.BytesIO(data))
        self.output.write_bytes(gzip.compress(raw.getvalue()))
        return hashlib.sha256(self.output.read_bytes()).hexdigest()

    def test_all_product_files_roundtrip_including_monitor(self):
        digest = self.build()
        manifest, files = tool.verify(self.output, digest)
        self.assertIn('usr/local/bin/sokol-monitor', files)
        self.assertEqual(manifest['admission'], 'NOT_ADMITTED')
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            tool.build(self.binaries, self.output)

    def test_missing_monitor_cannot_create_a_partial_candidate(self):
        (self.binaries / 'monitor').unlink()
        with self.assertRaises(ValueError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_a_selected_digest_is_required_and_tampering_is_refused(self):
        digest = self.build()
        with self.assertRaises(ValueError):
            tool.verify(self.output, '')
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            tool.verify(self.output, '0' * 64)
        self.output.write_bytes(self.output.read_bytes() + b'tamper')
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            tool.verify(self.output, digest)

    def test_traversal_symlinks_duplicate_and_digest_changes_are_refused(self):
        self.build()
        original = self.output.read_bytes()
        def traversal(entries): entries[0][0].name = '../outside'
        def symlink(entries): entries[0][0].type = tarfile.SYMTYPE; entries[0][0].linkname = '/etc/passwd'
        def duplicate(entries): entries.append(entries[0])
        def change(entries):
            info, data = entries[-1]
            entries[-1] = info, b'x' * len(data)
        for mutation in (traversal, symlink, duplicate, change):
            with self.subTest(mutation=mutation.__name__):
                self.output.write_bytes(original)
                digest = self.repackage(mutation)
                with self.assertRaises((ValueError, UnicodeError, json.JSONDecodeError)):
                    tool.verify(self.output, digest)
                self.assertFalse((self.root / 'outside').exists())

    def test_install_and_remove_do_not_change_state_or_configuration(self):
        digest = self.build()
        prefix = self.root / 'host'; prefix.mkdir()
        state = prefix / 'var/lib/sokol/node.key'; state.parent.mkdir(parents=True)
        state.write_bytes(b'private canary')
        result = tool.install(self.output, digest, prefix)
        self.assertEqual(result['service'], 'NOT_STARTED')
        monitor = prefix / 'usr/local/bin/sokol-monitor'
        self.assertEqual(monitor.read_bytes(), b'binary:monitor')
        self.assertEqual(monitor.stat().st_mode & 0o777, 0o755)
        monitor.write_bytes(b'locally modified')
        with self.assertRaisesRegex(ValueError, 'Modified'):
            tool.install(self.output, digest, prefix, remove=True)
        self.assertTrue((prefix / 'usr/local/bin/sokol-orchestrator').exists())
        monitor.write_bytes(b'binary:monitor')
        tool.install(self.output, digest, prefix, remove=True)
        self.assertFalse(monitor.exists())
        self.assertEqual(state.read_bytes(), b'private canary')

    def test_platform_and_symlink_refusal_precede_file_writes(self):
        digest = self.build()
        prefix = self.root / 'host'; prefix.mkdir()
        with patch.object(tool, 'arch', return_value='x86_64'):
            with self.assertRaisesRegex(ValueError, 'platform'):
                tool.install(self.output, digest, prefix)
        self.assertEqual(list(prefix.iterdir()), [])
        (prefix / 'usr').symlink_to(self.root / 'outside')
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            tool.install(self.output, digest, prefix)

    def test_decompression_is_bounded_before_parsing_tar_headers(self):
        self.build()
        with patch.object(tool, 'MAX_ARCHIVE', 512), patch.object(tool, 'MAX_META', 128):
            data = gzip.compress(b'0' * 1000)
            self.output.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'Decompressed'):
                tool.verify(self.output, hashlib.sha256(data).hexdigest())


if __name__ == '__main__':
    unittest.main()
