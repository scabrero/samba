# Unix SMB/CIFS implementation.
#
# Tests for samba.http.
#
# Copyright (C) 2026
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

import unittest
import multiprocessing
from http.server import BaseHTTPRequestHandler, HTTPServer

from samba import http as samba_http


def _serve_http_request(queue):
    class _HTTPRequestHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)

            queue.put({
                "path": self.path,
                "body": body,
                "headers": dict(self.headers.items()),
            })

            response = body + b":" + self.path.encode("utf-8")
            self.send_response(200, "OK")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("X-Test-Header", "python-http-binding")
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _HTTPRequestHandler)
    queue.put(server.server_port)
    server.handle_request()
    server.server_close()


class HttpBindingTests(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.context = multiprocessing.get_context("fork")
        self.queue = self.context.Queue()
        self.server = self.context.Process(target=_serve_http_request,
                                           args=(self.queue,))
        self.server.start()
        self.server_port = self.queue.get(timeout=5)

    def tearDown(self):
        self.server.join(timeout=5)
        if self.server.is_alive():
            self.server.terminate()
            self.server.join(timeout=5)
        super().tearDown()

    def test_connection_methods(self):
        conn = samba_http.Connection()
        payload = b"ping"

        conn.connect("127.0.0.1", self.server_port)
        conn.send_request(
            "POST",
            "/python-http-test",
            {"Content-Type": "application/octet-stream"},
            payload,
        )
        status, reason, headers, body = conn.read_response()
        conn.disconnect()

        self.assertEqual(200, status)
        self.assertEqual("OK", reason)
        self.assertEqual("python-http-binding", headers["X-Test-Header"])
        self.assertEqual(payload + b":/python-http-test", body)

        request = self.queue.get(timeout=5)
        self.assertEqual("/python-http-test", request["path"])
        self.assertEqual(payload, request["body"])
        self.assertEqual("4", request["headers"]["Content-Length"])
        self.assertIn("Host", request["headers"])
        self.server.join(timeout=5)
        self.assertEqual(0, self.server.exitcode)
