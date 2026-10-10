"""Bounded task context never runs native code or promotes matching input bytes."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("outbox_task", ROOT / "scripts/outbox-task.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class OutboxTask(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        for name in tool.INPUTS:
            file = self.root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, file)
        self.calls = []
        def git_only(command, **kwargs):
            self.assertEqual(command, ["git", "rev-parse", "HEAD"])
            self.calls.append(command)
            return subprocess.CompletedProcess(command, 0, "a" * 40 + "\n", "")
        self.mock = patch.object(subprocess, "run", side_effect=git_only)
        self.mock.start()

    def tearDown(self):
        self.mock.stop()
        self.temp.cleanup()

    def test_matching_bytes_still_establish_no_native_result(self):
        value = tool.packet(self.root)
        self.assertLessEqual(len(tool.encode(value)), 8192)
        self.assertEqual(value["body"]["current_native_result"], "UNKNOWN")
        self.assertEqual(value["body"]["signature_validity"], "NOT_CHECKED")
        self.assertEqual(value["body"]["contract_id"], "IPC-A1")
        self.assertEqual(len(self.calls), 2)

    def test_source_change_invalidates_cursor(self):
        value = tool.packet(self.root)
        self.assertEqual(tool.packet(self.root, since=value["id"])["status"], "UNCHANGED")
        file = self.root / "orchestrator/src/delivery.rs"
        file.write_bytes(file.read_bytes() + b"\n")
        self.assertNotEqual(tool.packet(self.root, since=value["id"])["id"], value["id"])

    def test_missing_input_refuses_old_cursor(self):
        value = tool.packet(self.root)
        (self.root / "docs/witness-manifest.json.sig").unlink()
        with self.assertRaises(OSError): tool.packet(self.root, since=value["id"])

    def test_small_budget_does_not_trim_scope(self):
        with self.assertRaisesRegex(ValueError, "Essential context"): tool.packet(self.root, budget=2048)

    def test_symlink_is_not_followed(self):
        file = self.root / "orchestrator/src/delivery.rs"
        file.unlink()
        file.symlink_to(ROOT / "orchestrator/src/delivery.rs")
        with self.assertRaisesRegex(ValueError, "Symlink"): tool.packet(self.root)


if __name__ == "__main__":
    unittest.main()
