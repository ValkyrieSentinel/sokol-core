#!/usr/bin/env python3
"""Check LAPI startup, expiry and failed-delta recovery through the actual adapter.

Usage: python3 scripts/test_crowdsec_stream.py target/release/sokol-crowdsec
Local fake HTTP/IPC peers check requests and commands, not production-node effects.
"""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from test_suricata_recovery import running


WAIT_SECONDS = 10
DECISION = {"id": 71, "origin": "cscli", "type": "ban", "scope": "Ip",
            "value": "203.0.113.71", "duration": "60s", "scenario": "stream probe"}


class LocalAPI(HTTPServer):
    def get_request(self):
        conn, address = super().get_request()
        conn.settimeout(3)
        return conn, address


class StreamTests(unittest.TestCase):
    binary = None

    def check_stream(self, expire_during_handshake=False):
        requests = []
        replies = [
            # Even the valid deletion must not escape this malformed envelope.
            {"new": "not an array", "deleted": [DECISION]},
            {"new": [{**DECISION, "duration": "1s" if expire_during_handshake else "60s"}], "deleted": None},
            {"new": [], "deleted": [DECISION]},
        ]

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                index = len(requests) - 1
                body = json.dumps(replies[index] if index < len(replies) else {}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory(prefix="sokol-cs-", dir="/tmp") as directory:
            ipc = Path(directory) / "ipc.sock"
            with LocalAPI(("127.0.0.1", 0), Handler) as api, socket.socket(socket.AF_UNIX) as server:
                server.bind(str(ipc))
                server.listen(1)
                server.settimeout(WAIT_SECONDS)
                thread = threading.Thread(target=api.serve_forever,
                                          kwargs={"poll_interval": 0.05}, daemon=True)
                thread.start()
                try:
                    args = [str(self.binary), "--lapi-url", f"http://127.0.0.1:{api.server_port}",
                            "--api-key", "dummy-regression-key", "--ipc-socket", str(ipc),
                            "--poll-secs", "1"]
                    # Keep the synthetic API key and requests on the local fixture.
                    with patch.dict(os.environ, {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}), running(args):
                        conn, _ = server.accept()
                        with conn:
                            conn.settimeout(WAIT_SECONDS)
                            with conn.makefile("rb") as reader:
                                self.assertEqual(reader.readline(4097), b"ACK\n")
                                if expire_during_handshake:
                                    time.sleep(1.2)  # longer than the source TTL, shorter than ACK timeout
                                conn.sendall(b"OK ack\n")
                                if expire_during_handshake:
                                    self.assertEqual(reader.readline(4097), b"RETRACT#71:crowdsec|203.0.113.71\n")
                                    conn.sendall(b"OK lifted\n")
                                else:
                                    self.assertEqual(reader.readline(4097).decode(),
                                                     "SIGNAL#71;ttl=60:crowdsec|203.0.113.71|-|stream probe "
                                                     "(origin cscli, crowdsec duration 60s)\n")
                                    conn.sendall(b"OK applied\n")
                                    self.assertEqual(reader.readline(4097),
                                                     b"RETRACT#71:crowdsec|203.0.113.71\n")
                                    conn.sendall(b"OK lifted\n")
                                    self.assertEqual(requests[:3], [
                                        "/v1/decisions/stream?startup=true",
                                        "/v1/decisions/stream?startup=true",
                                        "/v1/decisions/stream?startup=false",
                                    ])
                finally:
                    api.shutdown()
                    thread.join(timeout=5)
                self.assertFalse(thread.is_alive(), "HTTP fixture did not stop")

    def test_malformed_batch_does_not_finish_startup_or_send_partial_retractions(self):
        self.check_stream()

    def test_decision_expiring_during_handshake_is_retracted(self):
        self.check_stream(expire_during_handshake=True)

    def test_failed_delta_requests_full_stream_and_recovers_commands(self):
        for failure in ("bad-json", "bad-shape", "http-error", "truncated-body"):
            with self.subTest(failure=failure):
                self.check_resync(failure)

    def check_resync(self, failure):
        requests = []
        third_requested = threading.Event()
        fourth_requested = threading.Event()
        replacement = {**DECISION, "id": 72, "value": "203.0.113.72"}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                index = len(requests) - 1
                status = 200
                if index == 0:
                    body = json.dumps({"new": [DECISION], "deleted": []}).encode()
                elif index == 1:
                    if failure == "bad-json":
                        body = b"{"
                    elif failure == "bad-shape":
                        body = b'{"new":{},"deleted":[]}'
                    elif failure == "http-error":
                        status, body = 503, b"temporary error"
                    else:
                        body = b"{}"  # valid JSON; only the HTTP body is truncated
                elif index == 2 and self.path.endswith("startup=true"):
                    # The lost delta was consumed at the server. Its current retained
                    # state recovers both an active decision and the prior deletion.
                    body = json.dumps({"new": [replacement], "deleted": [DECISION]}).encode()
                else:
                    body = b"{}"
                self.send_response(status)
                self.send_header("Content-Length", str(len(body) + (20 if index == 1 and failure == "truncated-body" else 0)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                self.close_connection = True
                if index == 2:
                    third_requested.set()
                elif index == 3:
                    fourth_requested.set()

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory(prefix="sokol-cs-resync-", dir="/tmp") as directory:
            ipc = Path(directory) / "ipc.sock"
            with LocalAPI(("127.0.0.1", 0), Handler) as api, socket.socket(socket.AF_UNIX) as server:
                server.bind(str(ipc))
                server.listen(1)
                server.settimeout(WAIT_SECONDS)
                thread = threading.Thread(target=api.serve_forever,
                                          kwargs={"poll_interval": 0.05}, daemon=True)
                thread.start()
                try:
                    args = [str(self.binary), "--lapi-url", f"http://127.0.0.1:{api.server_port}",
                            "--api-key", "dummy-regression-key", "--ipc-socket", str(ipc), "--poll-secs", "1"]
                    with patch.dict(os.environ, {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}), running(args):
                        conn, _ = server.accept()
                        with conn:
                            conn.settimeout(WAIT_SECONDS)
                            with conn.makefile("rb") as reader:
                                self.assertEqual(reader.readline(4097), b"ACK\n")
                                conn.sendall(b"OK ack\n")
                                self.assertTrue(reader.readline(4097).startswith(b"SIGNAL#71;ttl="))
                                conn.sendall(b"OK applied\n")
                                self.assertTrue(third_requested.wait(WAIT_SECONDS), "missing recovery poll")
                                self.assertEqual(requests[:3], [
                                    "/v1/decisions/stream?startup=true",
                                    "/v1/decisions/stream?startup=false",
                                    "/v1/decisions/stream?startup=true",
                                ])
                                self.assertEqual(reader.readline(4097), b"RETRACT#71:crowdsec|203.0.113.71\n")
                                conn.sendall(b"OK lifted\n")
                                verb, payload = reader.readline(4097).split(b":", 1)
                                self.assertTrue(verb.startswith(b"SIGNAL#72;ttl="))
                                self.assertTrue(1 <= int(verb.split(b"=", 1)[1]) <= 60)
                                self.assertEqual(payload, b"crowdsec|203.0.113.72|-|stream probe (origin cscli, crowdsec duration 60s)\n")
                                conn.sendall(b"OK applied\n")
                                self.assertTrue(fourth_requested.wait(WAIT_SECONDS), "missing post-recovery poll")
                                self.assertEqual(requests[3], "/v1/decisions/stream?startup=false")
                finally:
                    api.shutdown()
                    thread.join(timeout=5)
                self.assertFalse(thread.is_alive(), "HTTP fixture did not stop")

    def test_polling_continues_before_a_healthy_backlog_is_drained(self):
        self.check_backlog("1")

    def test_zero_poll_interval_does_not_starve_delivery(self):
        self.check_backlog("0")

    def check_backlog(self, poll_secs):
        total = 20
        commands = []
        errors = []
        second_poll = threading.Event()
        complete = threading.Event()
        at_second_poll = []
        count = 0
        decisions = [{**DECISION, "id": 100 + i} for i in range(total)]

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal count
                count += 1
                if count == 1:
                    response = {"new": decisions, "deleted": []}
                elif count == 2:
                    at_second_poll.append(len(commands))
                    response = {"new": [], "deleted": [decisions[0]]}
                else:
                    response = {}
                body = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                if count == 2:
                    second_poll.set()

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory(prefix="sokol-cs-sched-", dir="/tmp") as directory:
            ipc = Path(directory) / "ipc.sock"
            with LocalAPI(("127.0.0.1", 0), Handler) as api, socket.socket(socket.AF_UNIX) as server:
                server.bind(str(ipc))
                server.listen(1)
                server.settimeout(WAIT_SECONDS)

                def node():
                    try:
                        conn, _ = server.accept()
                        with conn:
                            conn.settimeout(WAIT_SECONDS)
                            with conn.makefile("rb") as reader:
                                if reader.readline(4097) != b"ACK\n":
                                    raise AssertionError("missing ACK handshake")
                                conn.sendall(b"OK ack\n")
                                while len(commands) <= total:
                                    line = reader.readline(4097)
                                    if not line:
                                        break
                                    commands.append(line)
                                    conn.sendall(b"OK lifted\n" if line.startswith(b"RETRACT") else b"OK applied\n")
                                complete.set()
                    except Exception as error:
                        errors.append(error)
                        second_poll.set()
                        complete.set()

                http_thread = threading.Thread(target=api.serve_forever,
                    kwargs={"poll_interval": 0.05}, daemon=True)
                node_thread = threading.Thread(target=node, daemon=True)
                http_thread.start()
                node_thread.start()
                try:
                    args = [str(self.binary), "--lapi-url", f"http://127.0.0.1:{api.server_port}",
                            "--api-key", "dummy-regression-key", "--ipc-socket", str(ipc),
                            "--poll-secs", poll_secs, "--max-signals-per-sec", "5"]
                    with patch.dict(os.environ, {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}), running(args):
                        self.assertTrue(second_poll.wait(WAIT_SECONDS), "API polling stalled")
                        self.assertFalse(errors, str(errors))
                        self.assertTrue(at_second_poll)
                        self.assertLess(at_second_poll[0], total,
                                        "the next poll must precede draining the initial backlog")
                        self.assertTrue(complete.wait(WAIT_SECONDS), "queued commands did not finish")
                        self.assertFalse(errors, str(errors))
                        self.assertEqual(len(commands), total + 1)
                        self.assertEqual([line.split(b";", 1)[0] for line in commands[:total]],
                                         [f"SIGNAL#{100 + i}".encode() for i in range(total)])
                        self.assertEqual(commands[-1], b"RETRACT#100:crowdsec|203.0.113.71\n")
                finally:
                    api.shutdown()
                    http_thread.join(timeout=5)
                    node_thread.join(timeout=5)
                self.assertFalse(http_thread.is_alive() or node_thread.is_alive(), "fixture did not stop")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    StreamTests.binary = args.binary.resolve()
    if not StreamTests.binary.is_file():
        parser.error(f"adapter binary not found: {StreamTests.binary}")
    unittest.main(argv=[sys.argv[0]], verbosity=2)
