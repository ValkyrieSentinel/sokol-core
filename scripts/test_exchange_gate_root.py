"""A recipient's verifier must not overwrite the producer's signed checker input."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('exchange', Path(__file__).with_name('counterexample-task.py'))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class RecipientRoot(unittest.TestCase):
    def test_producer_checker_stays_data_and_recipient_checker_runs_outside(self):
        producer = b'# producer bytes, never executed\n'
        files = {'scripts/witness-pin.py': {'sha256': 'fixture', 'executable': False}}
        observed = []
        def run(source, argv, **kwargs):
            if '-I' in argv:
                observed.append(argv)
                self.assertEqual((source / 'scripts/witness-pin.py').read_bytes(), producer)
                self.assertNotEqual(Path(argv[2]).parent, source / 'scripts')
                self.assertEqual(argv[3:7], ['--root', str(source), 'check', '--every-pin'])
            return 0, b''
        with patch.object(tool, 'blob', return_value=producer), patch.object(tool.inputs, 'run_bounded', side_effect=run):
            tool.verify_owner_closure(Path('/unused-pack'), files, b'recipient-selected trust')
        self.assertEqual(len(observed), 1)


if __name__ == '__main__':
    unittest.main()
