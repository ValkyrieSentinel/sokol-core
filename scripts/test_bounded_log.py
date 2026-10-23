#!/usr/bin/env python3
"""bench/bounded-log.py keeps a node's log under two files of MAX_BYTES and loses no line of
the last MAX_BYTES written (the campaign's per-file limit killed every node of a 23 h soak)."""
import subprocess
import tempfile
import unittest
from pathlib import Path

WRITER = Path(__file__).resolve().parents[1] / "bench/bounded-log.py"


class BoundedLog(unittest.TestCase):
    def test_rotation_bounds_each_file_and_keeps_the_latest_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "node.log"
            lines = [f"line {i:06d} {'x' * 40}\n".encode() for i in range(5000)]
            limit = 16384
            subprocess.run(["python3", "-I", str(WRITER), str(log), str(limit)],
                           input=b"".join(lines), check=True, timeout=60)
            old = Path(str(log) + ".1")
            self.assertTrue(old.exists(), "the log rotated")
            self.assertLessEqual(log.stat().st_size, limit)
            self.assertLessEqual(old.stat().st_size, limit)
            kept = old.read_bytes() + log.read_bytes()
            self.assertTrue(kept.endswith(b"".join(lines[-200:])), "the newest lines are kept, in order")

    def test_a_short_log_is_written_whole(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "node.log"
            subprocess.run(["python3", "-I", str(WRITER), str(log), "1048576"],
                           input=b"a\nb\n", check=True, timeout=60)
            self.assertEqual(log.read_bytes(), b"a\nb\n")
            self.assertFalse(Path(str(log) + ".1").exists())


if __name__ == "__main__":
    unittest.main()
