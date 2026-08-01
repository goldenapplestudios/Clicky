#!/usr/bin/env python3
"""Minimal self-signed HTTPS server for testing
skills/web-vulnerability-testing/scripts/tls-scan.sh's openssl_fallback
path against real TLS handshake behavior instead of trusting the script's
own "verified against real local TLS servers" header comment as unbacked
prose. Stdlib only, no dependencies.

Explicitly pinned to TLS1.2-TLS1.3 so the test has a deterministic
expectation for weak_protocols_detected (empty) regardless of what the
local OpenSSL build's default policy would otherwise allow.

Usage: mock_tls_server.py <port> <certfile> <keyfile>
"""
import ssl
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # keep test output quiet

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")


def main():
    port, certfile, keyfile = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    server = HTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
