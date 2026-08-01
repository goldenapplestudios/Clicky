#!/usr/bin/env python3
"""Mock LLM-app endpoint for testing skills/ai-llm-security-testing/scripts/
prompt-injection-probe.sh against real HTTP behavior instead of trusting
the "verified live against two mock endpoints" claim in that skill's
SKILL.md as unbacked prose (which is exactly what an earlier audit found
it was - see tests/README.md). Stdlib only, no dependencies.

Routes:
  POST /reflect - echoes the request's "content" field back verbatim in an
    OpenAI-compatible {"choices":[{"message":{"content": ...}}]} shape, so
    injected {{CANARY}} substitutions round-trip and the probe's
    "possible_injection" detection should fire on every canary payload.
  POST /safe - always returns a fixed, generic refusal-style reply
    regardless of input, so the probe should report zero
    "possible_injection" verdicts against it.

Usage: mock_server.py <port>
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # keep test output quiet

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            body = {}

        content = ""
        messages = body.get("messages")
        if isinstance(messages, list) and messages:
            content = messages[-1].get("content", "")

        if self.path == "/reflect":
            reply = f"Sure! Here you go: {content}"
        elif self.path == "/safe":
            reply = "I can't help with that request."
        else:
            self.send_response(404)
            self.end_headers()
            return

        response = json.dumps({"choices": [{"message": {"content": reply}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8998
    server = HTTPServer(("127.0.0.1", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
