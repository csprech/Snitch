import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from snitch.server import App, make_handler


class Upstream(BaseHTTPRequestHandler):
    count = 0
    def do_POST(self):
        Upstream.count += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def log_message(self, *args):
        pass


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.up_thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.up_thread.start()
        Upstream.count = 0
        self.env = patch.dict(os.environ, {"SNITCH_ADMIN_KEY": "admin-" + "a"*30,
                                        "SNITCH_AGENT_KEY": "agent-" + "b"*30,
                                        "SNITCH_ALLOW_HTTP_LOCAL": "1"})
        self.env.start()
        config = {"agents": {"a": "SNITCH_AGENT_KEY"}, "tools": {"read": {"agents": ["a"], "risk": "low", "url": f"http://127.0.0.1:{self.upstream.server_port}/"}}}
        self.app = App(config, str(Path(self.temp.name) / "db"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown(); self.server.server_close()
        self.upstream.shutdown(); self.upstream.server_close()
        self.env.stop(); self.temp.cleanup()

    def call(self, path, body, token="agent-" + "b"*30, idem=None):
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        if idem:
            headers["Idempotency-Key"] = idem
        req = urllib.request.Request(self.url + path, json.dumps(body).encode(), headers)
        try:
            with urllib.request.urlopen(req, timeout=2) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def test_enforced_execution_and_replay(self):
        payload = {"tool": "read", "arguments": {"q": "public"}}
        self.assertEqual(self.call("/v1/execute", payload)[0], 400)
        first = self.call("/v1/execute", payload, idem="action-0001")
        second = self.call("/v1/execute", payload, idem="action-0001")
        self.assertEqual(first, second)
        self.assertEqual(Upstream.count, 1)
        self.assertEqual(self.call("/v1/execute", {"tool": "read", "arguments": {"q": "other"}}, idem="action-0001")[0], 409)
        self.assertEqual(self.call("/v1/hold", {"agent": "a"})[0], 403)
        self.assertEqual(self.call("/v1/hold", {"agent": "a"}, token="admin-" + "a"*30)[0], 200)
        self.assertEqual(self.call("/v1/execute", payload, idem="action-0002")[1]["decision"], "block")
        self.assertEqual(Upstream.count, 1)


if __name__ == "__main__":
    unittest.main()
