import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('support', Path(__file__).with_name('support_bundle.py'))
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)


class Support(unittest.TestCase):
    def test_time_output_and_exit_status_remain_distinct(self):
        done = tool.capture([sys.executable, '-c', 'print("evidence"); raise SystemExit(7)'])
        self.assertEqual((done['status'], done['returncode']), ('COMPLETE', 7))
        huge = tool.capture([sys.executable, '-c', 'print("x"*1000)'], bound=32)
        self.assertEqual(huge['status'], 'OUTPUT_LIMIT'); self.assertTrue(huge['partial'])
        slow = tool.capture([sys.executable, '-c', 'import time; time.sleep(30)'], seconds=.1)
        self.assertEqual(slow['status'], 'TIME_LIMIT'); self.assertTrue(slow['partial'])

    def test_private_archive_records_failures_and_excludes_raw_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'node.key').write_bytes(b'PRIVATE-CANARY')
            with patch.object(tool, 'commands', return_value={'probe.txt': [sys.executable, '-c', 'print("diagnostic"); raise SystemExit(3)']}):
                archive = tool.collect(root)
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
            with tarfile.open(archive) as tar:
                names = tar.getnames()
                manifest = json.loads(tar.extractfile(next(n for n in names if n.endswith('collection.json'))).read())
                self.assertEqual(manifest['commands']['probe.txt']['returncode'], 3)
                self.assertNotIn(b'PRIVATE-CANARY', b''.join(tar.extractfile(n).read() for n in names))


if __name__ == '__main__': unittest.main()
