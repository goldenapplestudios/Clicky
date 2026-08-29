#!/usr/bin/env python3
"""Real end-to-end check that fetch_url enforces scope, including redirects.

Backs a specific gap found by auditing the gateway against OWASP APTS:
`scope_gate` was consulted ONLY in register_target, so fetch_url resolved
its URL and called httpx with follow_redirects=True - it would chase a
`Location:` header to any host on the internet without ever consulting
scope.json. APTS-SE-006 requires validation immediately before every
network action, naming redirects explicitly ("Before following any
redirect, validate destination is in scope") and requiring it to be
atomic ("if validation fails, the action is not taken").

Drives the real server over real MCP stdio against a real local HTTP
server and asserts:
  1. An in-scope host is fetched normally.
  2. An out-of-scope host is refused outright.
  3. A redirect from an in-scope host to an out-of-scope host is NOT
     followed - the decisive case, since the agent never named the
     destination; the target did.
  4. An in-scope -> in-scope redirect IS followed.
  5. A hostname alias learned from the engagement is allowed (the same
     alias rule register_target uses).

Usage: test_fetch_url_scope.py /path/to/server.py
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

SERVER_PATH = sys.argv[1]
FAILED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global FAILED
    if condition:
        print(f"PASS: {label}")
    else:
        FAILED = 1
        print(f"FAIL: {label}" + (f" - {detail}" if detail else ""))


def tool_text(result) -> str:
    return "\n".join(
        t for t in (getattr(b, "text", None) for b in result.content) if t is not None
    )


class Handler(BaseHTTPRequestHandler):
    """Serves a plain page, plus redirects used by the checks below."""

    off_port = 0
    on_port = 0

    def do_GET(self):  # noqa: N802
        if self.path == "/redirect-offsite":
            # 127.0.0.2 is a distinct host from 127.0.0.1 for scope purposes.
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.2:{self.off_port}/landed")
            self.end_headers()
        elif self.path == "/redirect-onsite":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.on_port}/ok")
            self.end_headers()
        else:
            body = b"CLICKY_PAGE_BODY"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


def serve(host: str) -> HTTPServer:
    httpd = HTTPServer((host, 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


async def main() -> int:
    tmp_dir = tempfile.mkdtemp(prefix="clicky-fetch-scope-")
    on = serve("127.0.0.1")
    off = serve("127.0.0.2")
    Handler.on_port = on.server_port
    Handler.off_port = off.server_port
    try:
        session_dir = Path(tmp_dir) / "session"
        session_dir.mkdir()
        (session_dir / "session.json").write_text(
            json.dumps({"session_id": "fetch-fixture", "target": "127.0.0.1"})
        )
        (session_dir / "scope.json").write_text(
            json.dumps(
                {"targets": {"in_scope": ["127.0.0.1"], "out_of_scope": ["127.0.0.2"]}}
            )
        )

        import os

        params = StdioServerParameters(
            command=sys.executable,
            args=[SERVER_PATH],
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", ""),
                "CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT": "enforce",
            },
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                async def fetch(url):
                    return tool_text(
                        await session.call_tool(
                            "fetch_url",
                            {"url": url, "session_dir": str(session_dir)},
                        )
                    )

                base_on = f"http://127.0.0.1:{on.server_port}"
                base_off = f"http://127.0.0.2:{off.server_port}"

                ok = await fetch(f"{base_on}/ok")
                check(
                    "in-scope host is fetched normally",
                    "CLICKY_PAGE_BODY" in ok,
                    f"got: {ok[:200]!r}",
                )

                denied = await fetch(f"{base_off}/landed")
                check(
                    "explicitly out-of-scope host is refused, not fetched",
                    "[SCOPE]" in denied and "CLICKY_PAGE_BODY" not in denied,
                    f"got: {denied[:200]!r}",
                )

                # The decisive one: the agent named only an in-scope URL.
                hop = await fetch(f"{base_on}/redirect-offsite")
                check(
                    "redirect to an out-of-scope host is NOT followed "
                    "(APTS-SE-006: validate before following any redirect)",
                    "redirect NOT followed" in hop and "CLICKY_PAGE_BODY" not in hop,
                    f"got: {hop[:250]!r}",
                )

                good_hop = await fetch(f"{base_on}/redirect-onsite")
                check(
                    "redirect to an in-scope host IS followed",
                    "CLICKY_PAGE_BODY" in good_hop,
                    f"got: {good_hop[:200]!r}",
                )

                # Teach the session a hostname the way real output would,
                # then confirm the shared alias rule admits it.
                await session.call_tool(
                    "execute_command",
                    {
                        "command": "echo 'Host: connected.htb'",
                        "session_dir": str(session_dir),
                    },
                )
                alias = await fetch("http://connected.htb/")
                check(
                    "a hostname alias learned from the engagement is allowed "
                    "past the scope check (fails on connection, not on scope)",
                    "[SCOPE]" not in alias,
                    f"got: {alias[:200]!r}",
                )
        return FAILED
    finally:
        on.shutdown()
        off.shutdown()
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
