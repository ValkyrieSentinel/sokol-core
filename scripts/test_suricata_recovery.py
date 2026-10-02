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
import re
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
def running(args, capture=None):
    # File-backed diagnostics cannot fill a pipe and stall the adapter under test.
    with tempfile.TemporaryFile(mode="w+t") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=log,
                                env={**os.environ, "RUST_LOG": "info"})
        try:
            if capture is not None:
                capture.append(log)
            yield proc
        except BaseException:
            print(read_log(log), file=sys.stderr)
            raise
        finally:
            if proc.poll() is None:
                proc.kill()  # process loss: no graceful checkpoint on shutdown
            proc.wait(timeout=3)


def read_log(log):
    # Unlike seek/read, pread does not move the child's shared output offset.
    return os.pread(log.fileno(), os.fstat(log.fileno()).st_size, 0).decode(errors="replace")


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

    def test_invalid_forwarding_age_leaves_cursor_and_ipc_untouched(self):
        with tempfile.TemporaryDirectory(prefix="sokol-rec-", dir="/tmp") as directory:
            root = Path(directory)
            eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
            eve.write_text(alert("203.0.113.17"))
            original = json.dumps({"inode": eve.stat().st_ino, "position": 0}).encode()
            cursor.write_bytes(original)
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(ipc))
                server.listen(1)
                with running([str(self.binary), "--eve", str(eve),
                              "--cursor-file", str(cursor), "--ipc-socket", str(ipc),
                              "--max-alert-age-secs", "18446744073709551615"]) as proc:
                    try:
                        code = proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.fail("invalid forwarding age started a long-running adapter")
                    self.assertEqual(code, 2, "Clap must reject the configuration")
                    self.assertEqual(cursor.read_bytes(), original)
                    server.settimeout(0.1)
                    with self.assertRaises(socket.timeout):
                        server.accept()

    def test_cooldown_diagnostics_aggregate_across_batches_without_losing_counts(self):
        with tempfile.TemporaryDirectory(prefix="sokol-rec-", dir="/tmp") as directory:
            root = Path(directory)
            eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
            repeats = 4096
            eve.write_text(alert("203.0.113.17") * (repeats + 1))
            logs = []
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(ipc))
                server.listen(1)
                server.settimeout(WAIT_SECONDS)
                started = time.monotonic()
                with running([str(self.binary), "--eve", str(eve), "--from-start",
                              "--cursor-file", str(cursor), "--ipc-socket", str(ipc),
                              "--cooldown-secs", "86400"], capture=logs) as proc:
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(WAIT_SECONDS)
                        with conn.makefile("rb") as reader:
                            self.assertEqual(reader.readline(4097), b"ACK\n")
                            conn.sendall(b"OK ack\n")
                            self.assertIn(b"suricata|203.0.113.17|", reader.readline(4097))
                            conn.sendall(b"OK applied\n")
                            await_cursor(cursor, {"inode": eve.stat().st_ino,
                                                  "position": eve.stat().st_size}, proc)
                            deadline = time.monotonic() + WAIT_SECONDS
                            while True:
                                # pread leaves the child's shared output offset alone.
                                text = read_log(logs[0])
                                counts = [int(n) for n in re.findall(
                                    r"(\d+) alerts skipped: source cooldown active", text)]
                                if sum(counts) >= repeats:
                                    break
                                if time.monotonic() >= deadline:
                                    self.fail(f"pending diagnostics never flushed at EOF: {counts}")
                                time.sleep(0.05)
                            self.assertEqual(sum(counts), repeats)
                            elapsed = time.monotonic() - started
                            self.assertLessEqual(len(counts), int(elapsed) + 1,
                                                 "refusal report decisions must be spaced by a second")
                            conn.settimeout(0.2)
                            with self.assertRaises(socket.timeout):
                                reader.readline(4097)

    def test_zero_rate_counts_skipped_alerts_without_ipc_or_pending_cursor(self):
        with tempfile.TemporaryDirectory(prefix="sokol-rec-", dir="/tmp") as directory:
            root = Path(directory)
            eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
            refused = 513  # crosses three bounded reader batches
            eve.write_text(alert("203.0.113.17") * refused)
            logs = []
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(ipc))
                server.listen(1)
                started = time.monotonic()
                with running([str(self.binary), "--eve", str(eve), "--from-start",
                              "--cursor-file", str(cursor), "--ipc-socket", str(ipc),
                              "--max-signals-per-sec", "0"], capture=logs) as proc:
                    await_cursor(cursor, {"inode": eve.stat().st_ino,
                                          "position": eve.stat().st_size}, proc)
                    deadline = time.monotonic() + WAIT_SECONDS
                    while True:
                        text = read_log(logs[0])
                        counts = [int(n) for n in re.findall(
                            r"(\d+) alerts skipped: policy rate limit reached", text)]
                        if sum(counts) >= refused:
                            break
                        if time.monotonic() >= deadline:
                            self.fail(f"rate-refused alerts are invisible in diagnostics: {counts}")
                        self.assertIsNone(proc.poll(), "adapter must stay alive at zero rate")
                        time.sleep(0.05)
                    self.assertEqual(sum(counts), refused)
                    self.assertLessEqual(len(counts), int(time.monotonic() - started) + 1)
                    self.assertNotIn("alerts skipped: source cooldown active", text)
                    self.assertNotIn("alerts skipped: cooldown memory full", text)
                    self.assertNotIn("alerts queued, retrying", text)
                    server.settimeout(0.1)
                    with self.assertRaises(socket.timeout):
                        server.accept()

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

    def test_pending_pretruncate_offset_cannot_skip_regrown_file_after_restart(self):
        with tempfile.TemporaryDirectory(prefix="sokol-truncate-", dir="/tmp") as directory:
            root = Path(directory)
            eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
            prefix = "{}\n" * 100
            eve.write_text(prefix + alert("203.0.113.10"))
            inode = eve.stat().st_ino
            args = [str(self.binary), "--eve", str(eve), "--cursor-file", str(cursor),
                    "--ipc-socket", str(ipc)]
            expected_ips = ["203.0.113.11", "203.0.113.12"]
            with running(args + ["--from-start"]) as proc:
                await_cursor(cursor, {"inode": inode, "position": len(prefix)}, proc)
                # Detectable copytruncate keeps the inode but replaces its contents.
                first = alert(expected_ips[0])
                self.assertLess(len(first), len(prefix))
                eve.write_text(first)
                self.assertEqual(eve.stat().st_ino, inode)
                # Observe the reset before regrowth, rather than racing the reader.
                # An empty or short intermediate file is acceptable; both reset it.
                await_cursor(cursor, {"inode": inode, "position": 0}, proc)
                with eve.open("a") as file:
                    file.write(alert(expected_ips[1]))
                self.assertGreater(eve.stat().st_size, len(prefix))
                await_cursor(cursor, {"inode": inode, "position": 0}, proc)

            # Old-file queued data is gone; every alert in current contents must replay.
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
                                self.assertTrue(line.startswith("SIGNAL#"), line)
                                self.assertEqual(line.partition(":")[2],
                                                 f"suricata|{ip}|-|sid:123 recovery probe\n")
                                conn.sendall(b"OK applied\n")
                            await_cursor(cursor, {"inode": inode, "position": eve.stat().st_size}, proc)

    def test_missing_source_keeps_resume_anchor_across_wait_and_process_loss(self):
        for restart in [False, True]:
            with self.subTest(restart=restart):
                with tempfile.TemporaryDirectory(prefix="sokol-defer-", dir="/tmp") as directory:
                    root = Path(directory)
                    eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
                    parked = root / "eve.parked"
                    prefix = alert("203.0.113.13")
                    eve.write_text(prefix + alert("203.0.113.14"))
                    expected = {"inode": eve.stat().st_ino, "position": len(prefix)}
                    cursor.write_text(json.dumps(expected))
                    written = cursor.stat().st_mtime_ns
                    eve.rename(parked)
                    args = [str(self.binary), "--eve", str(eve), "--cursor-file", str(cursor),
                            "--ipc-socket", str(ipc)]
                    with socket.socket(socket.AF_UNIX) as server:
                        server.bind(str(ipc))
                        server.listen(1)
                        server.settimeout(WAIT_SECONDS)

                        def receive(proc):
                            conn, _ = server.accept()
                            with conn:
                                conn.settimeout(WAIT_SECONDS)
                                with conn.makefile("rb") as reader:
                                    self.assertEqual(reader.readline(4097), b"ACK\n")
                                    conn.sendall(b"OK ack\n")
                                    line = reader.readline(4097).decode()
                                    self.assertTrue(line.startswith("SIGNAL#"), line)
                                    self.assertEqual(line.partition(":")[2],
                                                     "suricata|203.0.113.14|-|sid:123 recovery probe\n")
                                    conn.sendall(b"OK applied\n")
                                    await_cursor(cursor, {"inode": eve.stat().st_ino,
                                                          "position": eve.stat().st_size}, proc)
                                    conn.settimeout(0.2)
                                    with self.assertRaises(socket.timeout):
                                        reader.readline(4097)

                        with running(args + ([] if restart else ["--from-start"])) as proc:
                            # Wait for an actual periodic checkpoint while the path is absent.
                            # Reading the pre-existing cursor alone would race startup.
                            deadline = time.monotonic() + WAIT_SECONDS
                            while cursor.stat().st_mtime_ns == written:
                                self.assertIsNone(proc.poll(), "adapter exited while awaiting source")
                                if time.monotonic() >= deadline:
                                    self.fail("no checkpoint while source was missing")
                                time.sleep(0.05)
                            self.assertEqual(json.loads(cursor.read_text()), expected,
                                             "absence must not erase the selected resume anchor")
                            if not restart:
                                parked.rename(eve)
                                receive(proc)
                        if restart:
                            parked.rename(eve)
                            with running(args + ["--from-start"]) as proc:
                                receive(proc)

    def test_alert_expiring_during_handshake_is_not_forwarded(self):
        for lost_ack in (False, True):
            with self.subTest(lost_ack=lost_ack):
                self.check_forwarding_freshness(lost_ack)

    def check_forwarding_freshness(self, lost_ack):
        with tempfile.TemporaryDirectory(prefix="sokol-age-", dir="/tmp") as directory:
            root = Path(directory)
            eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
            eve.write_text("")
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(ipc))
                server.listen(1)
                server.settimeout(WAIT_SECONDS)
                args = [str(self.binary), "--eve", str(eve), "--cursor-file", str(cursor),
                        "--ipc-socket", str(ipc), "--from-start", "--max-alert-age-secs", "3" if lost_ack else "1"]
                diagnostics = []
                with running(args, capture=diagnostics) as proc:
                    # Observe actual loop/checkpoint progress before creating the timed alert.
                    await_cursor(cursor, {"inode": eve.stat().st_ino, "position": 0}, proc)
                    with eve.open("a") as writer:
                        writer.write(alert("203.0.113.17"))
                    if lost_ack:
                        first, _ = server.accept()
                        with first:
                            first.settimeout(WAIT_SECONDS)
                            with first.makefile("rb") as reader:
                                self.assertEqual(reader.readline(4097), b"ACK\n")
                                first.sendall(b"OK ack\n")
                                self.assertIn(b"suricata|203.0.113.17|-|", reader.readline(4097))
                                time.sleep(1.5)  # consume age budget while still below answer timeout
                                # The signal may have applied. Close without its final ACK.
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(WAIT_SECONDS)
                        with conn.makefile("rb") as reader:
                            self.assertEqual(reader.readline(4097), b"ACK\n")
                            time.sleep(1.2)  # past freshness budget, below the 2s ACK timeout
                            conn.sendall(b"OK ack\n")
                            with eve.open("a") as writer:
                                writer.write(alert("203.0.113.17"))  # same-source policy cooldown remains
                                writer.write(alert("203.0.113.18"))
                            # Expiry must not send/retry old 17, invent RETRACT, or stop fresh work.
                            line = reader.readline(4097)
                            self.assertTrue(line.startswith(b"SIGNAL#"), line)
                            self.assertEqual(line.partition(b":")[2],
                                             b"suricata|203.0.113.18|-|sid:123 recovery probe\n")
                            conn.sendall(b"OK applied\n")
                            await_cursor(cursor, {"inode": eve.stat().st_ino,
                                                  "position": eve.stat().st_size}, proc)
                            conn.settimeout(0.2)
                            with self.assertRaises(socket.timeout):
                                reader.readline(4097)
                            logs = read_log(diagnostics[0])
                            self.assertIn("1 queued alerts expired before forwarding", logs)
                            self.assertIn("1 alerts skipped: source cooldown active", logs)

    def test_bad_records_do_not_drop_neighbouring_alerts(self):
        oversized = json.loads(alert("203.0.113.99"))
        oversized["padding"] = "x" * (1024 * 1024)
        for name, bad_record in [
            ("invalid UTF-8", b"\xff\n"),
            ("oversized valid JSON alert", (json.dumps(oversized) + "\n").encode()),
        ]:
            with self.subTest(record=name):
                with tempfile.TemporaryDirectory(prefix="sokol-utf8-", dir="/tmp") as directory:
                    root = Path(directory)
                    eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
                    ips = ["203.0.113.4", "203.0.113.5"]
                    eve.write_bytes(alert(ips[0]).encode() + bad_record + alert(ips[1]).encode())
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

    def test_backlog_does_not_sleep_between_every_batch(self):
        # 100,000 records / 256 per batch * 50 ms would delay this alert by >19 s.
        # The existing 10 s socket deadline detects that artificial delay.
        with tempfile.TemporaryDirectory(prefix="sokol-backlog-", dir="/tmp") as directory:
            root = Path(directory)
            eve, cursor, ipc = root / "eve.json", root / "cursor", root / "ipc.sock"
            eve.write_text("{}\n" * 100_000 + alert("203.0.113.6"))
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
                            line = reader.readline(4097).decode()
                            self.assertTrue(line.startswith("SIGNAL#"), line)
                            self.assertEqual(line.partition(":")[2],
                                             "suricata|203.0.113.6|-|sid:123 recovery probe\n")
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
