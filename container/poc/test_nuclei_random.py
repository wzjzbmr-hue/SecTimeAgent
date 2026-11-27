"""Benign runtime regression for a validator-only randstr diagnostic. No exploit."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

TEMPLATE = '''id: cairn-random-regression
info:
  name: Safe random variable expansion fixture
  author: cairn
  severity: info
variables:
  rand: "{{randstr}}"
  filename: "proof_{{rand}}.txt"
  bound: "{{to_lower(rand_text_alpha(8))}}"
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{filename}}?value={{rand}}&bound={{bound}}"
    matchers:
      - type: word
        words: ["cairn fixture ok"]
'''
WARNING = "Failed to evaluate expression 'randstr'"


@unittest.skipUnless(shutil.which('nuclei'), 'requires tested Worker Nuclei engine')
class RandomContextTest(unittest.TestCase):
    def test_runtime_expands_alias_consistently_across_fields(self):
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                observed.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'cairn fixture ok')

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'random.yaml'
            path.write_text(TEMPLATE)
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                values = []
                for _ in range(2):
                    run = subprocess.run(['nuclei', '-t', str(path), '-u', 'http://127.0.0.1:' + str(server.server_port),
                                          '-duc', '-ni', '-nc', '-timeout', '3', '-retries', '0'],
                                         capture_output=True, text=True, timeout=30)
                    self.assertEqual(0, run.returncode)
                    self.assertNotIn(WARNING, run.stdout + run.stderr)
                    self.assertIn('[cairn-random-regression]', run.stdout)
                    parts = urlsplit(observed[-1]); query = parse_qs(parts.query)
                    value = query['value'][0]
                    self.assertRegex(value, r'^[A-Za-z0-9]{16,}$')
                    self.assertEqual('/proof_' + value + '.txt', parts.path)
                    self.assertRegex(query['bound'][0], r'^[a-z]{8}$')
                    values.append(value)
                self.assertNotEqual(values[0], values[1])
            finally:
                server.shutdown(); server.server_close()


if __name__ == '__main__':
    unittest.main()
