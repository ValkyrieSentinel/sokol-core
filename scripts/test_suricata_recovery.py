#!/usr/bin/env python3
"""Exercise the actual adapter's queue/cursor/restart wiring, without XDP or root.

Run after building: python3 scripts/test_suricata_recovery.py target/release/sokol-suricata
The socket peer acknowledges transport only; this does not prove node durability,
exactly-once effects, or recovery of entries in rotated-away files.
"""
import argparse
from contextlib import contextmanager
import datetime
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest


WAIT_SECONDS = 10


def alert(ip):
    return json.dumps({
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": "alert",
        "src_ip": ip,
        "alert": {"severity": 1, "signature_id": 123, "signature": "recovery probe"},
    }) + "\n"


@contextmanager
def running(args):
    # File-backed diagnostics cannot fill a pipe and stall the adapter under test.
    with tempfile.TemporaryFile(mode="w+t") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=log,
                                env={**os.environ, "RUST_LOG": "info"})
        try:
            yield proc
        except BaseException:
            log.seek(0)
            print(log.read(), file=sys.stderr)
            raise
        finally:
            if proc.poll() is None:
                proc.kill()  # process loss: no graceful checkpoint on shutdown
            proc.wait(timeout=3)


def await_cursor(path, expected, proc):
    deadline = time.monotonic() + WAIT_SECONDS
    last = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"adapter exited early: {proc.returncode}")
        try:
            last = json.loads(path.read_text())
            if last == expected:
                return
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    raise AssertionError(f"cursor did not reach {expected}; last observed: {last}")


class RecoveryTests(unittest.TestCase):
    binary = None

    def restart_case(self, rotate):
        # Short path also fits macOS's Unix-socket pathname limit.
        with tempfile.TemporaryDirectory(prefix="sokol-rec-", dir="/tmp") as directory:
            root = Path(directory)
            eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
            prefix = "already read\n"
            eve.write_text(prefix + alert("203.0.113.1"))
            args = [str(self.binary), "--eve", str(eve), "--cursor-file", str(cursor),
                    "--ipc-socket", str(ipc)]
            expected_ips = ["203.0.113.1"]
            # No listener: the old alert must stay pending, pinning the saved offset.
            with running(args + ["--from-start"]) as proc:
                old_inode = eve.stat().st_ino
                await_cursor(cursor, {"inode": old_inode, "position": len(prefix)}, proc)
                if rotate:
                    eve.rename(root / "eve.json.1")
                    expected_ips = ["203.0.113.2", "203.0.113.3"]
                    eve.write_text("".join(alert(ip) for ip in expected_ips))
                    self.assertNotEqual(eve.stat().st_ino, old_inode)
                    await_cursor(cursor, {"inode": eve.stat().st_ino, "position": 0}, proc)

            # Restart without --from-start: the persisted cursor must drive recovery.
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(ipc))
                server.listen(1)
                server.settimeout(WAIT_SECONDS)
                with running(args) as proc:
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(WAIT_SECONDS)
                        with conn.makefile("rb") as reader:
                            self.assertEqual(reader.readline(4097), b"ACK\n")
                            conn.sendall(b"OK ack\n")
                            for ip in expected_ips:
                                line = reader.readline(4097).decode()
                                event, separator, payload = line.partition(":")
                                self.assertTrue(event.startswith("SIGNAL#"), line)
                                self.assertEqual(separator, ":", line)
                                self.assertEqual(payload, f"suricata|{ip}|-|sid:123 recovery probe\n")
                                conn.sendall(b"OK applied\n")
                            # Acknowledged work must release the pinned cursor as well.
                            await_cursor(cursor, {"inode": eve.stat().st_ino,
                                                  "position": eve.stat().st_size}, proc)
                            # No extra command may follow after all expected replies.
                            conn.settimeout(0.2)
                            with self.assertRaises(socket.timeout):
                                reader.readline(4097)

    def test_invalid_utf8_does_not_drop_neighbouring_alerts(self):
        with tempfile.TemporaryDirectory(prefix="sokol-utf8-", dir="/tmp") as directory:
            root = Path(directory)
            eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
            ips = ["203.0.113.4", "203.0.113.5"]
            eve.write_bytes(alert(ips[0]).encode() + b"\xff\n" + alert(ips[1]).encode())
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(ipc))
                server.listen(1)
                server.settimeout(WAIT_SECONDS)
                args = [str(self.binary), "--eve", str(eve), "--cursor-file", str(cursor),
                        "--ipc-socket", str(ipc), "--from-start"]
                with running(args) as proc:
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(WAIT_SECONDS)
                        with conn.makefile("rb") as reader:
                            self.assertEqual(reader.readline(4097), b"ACK\n")
                            conn.sendall(b"OK ack\n")
                            for ip in ips:
                                line = reader.readline(4097).decode()
                                self.assertTrue(line.startswith("SIGNAL#"), line)
                                self.assertEqual(line.partition(":")[2],
                                                 f"suricata|{ip}|-|sid:123 recovery probe\n")
                                conn.sendall(b"OK applied\n")
                            await_cursor(cursor, {"inode": eve.stat().st_ino,
                                                  "position": eve.stat().st_size}, proc)

    def test_pending_same_file_survives_process_loss(self):
        self.restart_case(rotate=False)

    def test_pending_old_file_cannot_skip_new_file_after_rotation(self):
        self.restart_case(rotate=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    RecoveryTests.binary = args.binary.resolve()
    if not RecoveryTests.binary.is_file():
        parser.error(f"adapter binary not found: {RecoveryTests.binary}")
    unittest.main(argv=[sys.argv[0]], verbosity=2)
