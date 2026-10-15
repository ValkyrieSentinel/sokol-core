"""The convenience front cannot turn data into a recipe or a replay result."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('dev', Path(__file__).with_name('sokol-dev.py'))
dev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dev)


class Workbench(unittest.TestCase):
    def test_an_input_cannot_add_shell_or_extra_arguments(self):
        for identity in ('IPC-A1;touch /tmp/not-a-task', '../IPC-A1', '--root', 'ipc-a1'):
            with self.assertRaises(ValueError):
                dev.commands('check', identity)

    def test_context_and_execution_are_separate_fixed_actions(self):
        self.assertEqual(dev.commands('context', 'IPC-A1')[-2:], ['context', 'IPC-A1'])
        self.assertEqual(dev.commands('check', 'IPC-A1')[-2:], ['run', 'IPC-A1'])
        self.assertNotIn('--replay', dev.commands('verify', '/tmp/report.json'))
        self.assertEqual(dev.commands('verify', '/tmp/report.json', replay=True)[-1], '--replay')

    def test_an_unknown_challenge_cannot_select_a_command(self):
        with patch.object(dev, 'module') as load:
            load.return_value.catalog.return_value = ([{'id': 'genesis'}], set())
            with self.assertRaises(ValueError):
                dev.commands('challenge', 'rm -rf anything')
            self.assertEqual(dev.commands('challenge', 'genesis')[-2:], ['--challenge', 'genesis'])

    def test_the_map_preserves_refusal_and_does_not_invent_execution(self):
        value = dev.graph({'snapshot': 'sha256:fixture', 'binding': 'REFUSED',
                           'rows': [{'id': 'T-1', 'files': ['common/src/replay.rs'], 'tier': 'PROVISIONAL'}]})
        self.assertEqual(value['binding'], 'REFUSED')
        self.assertEqual(value['execution'], 'UNKNOWN')
        self.assertEqual(value['edges'], [{'from': 'T-1', 'to': 'common/src/replay.rs', 'kind': 'DECLARES_WITNESS_IN'}])

    def test_an_essential_view_is_refused_instead_of_silently_truncated(self):
        with self.assertRaises(ValueError):
            dev.emit({'essential': 'x' * dev.MAX_VIEW_BYTES})


if __name__ == '__main__':
    unittest.main()
