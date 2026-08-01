#!/usr/bin/env python3
"""Mock HTTP server for testing
skills/web-vulnerability-testing/scripts/security-headers-check.sh against
real HTTP responses. Stdlib only, no dependencies.

Routes:
  GET /vulnerable - no X-Frame-Options/CSP, a Set-Cookie with no SameSite,
    and a <form> with no anti-CSRF token field. Should be flagged
    clickjacking-vulnerable with a nonzero forms_without_token_field.
  GET /safe - X-Frame-Options + CSP frame-ancestors set, a Set-Cookie with
    SameSite=Strict, HSTS + X-Content-Type-Options set, and a <form>
    containing a csrf_token field. Should be flagged not vulnerable.

Usage: mock_server.py <port>
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

VULNERABLE_BODY = b"""<html><body>
<form method="post" action="/transfer">
  <input type="text" name="amount">
  <input type="submit" value="Transfer">
</form>
</body></html>"""

SAFE_BODY = b"""<html><body>
<form method="post" action="/transfer">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="text" name="amount">
  <input type="submit" value="Transfer">
</form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # keep test output quiet

    def do_GET(self):
        if self.path == "/vulnerable":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=abc123; Path=/")
            self.send_header("Content-Length", str(len(VULNERABLE_BODY)))
            self.end_headers()
            self.wfile.write(VULNERABLE_BODY)
        elif self.path == "/safe":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "frame-ancestors 'self'")
            self.send_header("Set-Cookie", "session=abc123; Path=/; SameSite=Strict")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(SAFE_BODY)))
            self.end_headers()
            self.wfile.write(SAFE_BODY)
        else:
            self.send_response(404)
            self.end_headers()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8997
    server = HTTPServer(("127.0.0.1", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
