#!/usr/bin/env python3
"""Check malformed LAPI startup recovery through the actual CrowdSec adapter.

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
import unittest
from unittest.mock import patch

from test_suricata_recovery import running


WAIT_SECONDS = 10
DECISION = {"id": 71, "origin": "cscli", "type": "ban", "scope": "Ip",
            "value": "203.0.113.71", "duration": "60s", "scenario": "stream probe"}


class StreamTests(unittest.TestCase):
    binary = None

    def test_malformed_batch_does_not_finish_startup_or_send_partial_retractions(self):
        requests = []
        replies = [
            # Even the valid deletion must not escape this malformed envelope.
            {"new": "not an array", "deleted": [DECISION]},
            {"new": [DECISION], "deleted": None},
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

        class LocalAPI(HTTPServer):
            def get_request(self):
                conn, address = super().get_request()
                conn.settimeout(3)
                return conn, address

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
                                conn.sendall(b"OK ack\n")
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    StreamTests.binary = args.binary.resolve()
    if not StreamTests.binary.is_file():
        parser.error(f"adapter binary not found: {StreamTests.binary}")
    unittest.main(argv=[sys.argv[0]], verbosity=2)
