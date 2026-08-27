#!/usr/bin/env python3
"""Live check that the Kalilix toolchain is resolved LAZILY, not at startup.

This is the regression test for a real outage. Resolving the toolchain used to
happen in launch.sh before the MCP server was exec'd, which put a ~44s cold
operation inside the client's server-startup timeout (MCP_TIMEOUT). A stdio
server that misses that deadline is reported "failed to connect" and is never
retried for the session - and because every Clicky agent holds only gateway
tools, that left whole engagements running against agents with no tools at all,
degrading silently instead of stopping.

Nothing at startup needs that PATH: execute_command's subprocess is its only
consumer, and a tool call has a far larger budget (MCP_TOOL_TIMEOUT defaults to
~28 hours unset; stdio servers have no per-request timer).

Asserts, over real MCP stdio:
  1. initialize and tools/list complete without the toolchain being resolved.
  2. create_session kicks off the background warm (after the handshake, so it
     cannot affect the startup timeout).
  3. execute_command's subprocess actually receives the resolved PATH.
  4. Resolution is memoized - not re-run per command.
  5. A FAILING resolve degrades loudly: banner in the output, error in the
     trace, and still only invoked once.
  6. With tool_provisioning unset, the resolver is never invoked at all.

The resolver is stubbed by building a MIRRORED gateway tree in a temp dir -
server.py and its sibling modules copied in, a stub `scripts/toolchain-path.sh`
beside them, and the other skill directories symlinked back to the real ones.
server.py resolves every helper relative to its own location, so this redirects
the resolver without the production code needing a test-only environment hook.

Usage: test_toolchain_lazy.py /path/to/server.py
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

SERVER_PATH = sys.argv[1]
FAILED = 0


def check(label, condition, detail=""):
    global FAILED
    if condition:
        print(f"PASS: {label}")
    else:
        FAILED = 1
        print(f"FAIL: {label}" + (f" - {detail}" if detail else ""))


def tool_text(result):
    return "\n".join(
        t for t in (getattr(b, "text", None) for b in result.content) if t is not None
    )


def make_session(tmp: Path, name: str) -> Path:
    d = tmp / name
    d.mkdir(parents=True)
    (d / "session.json").write_text(json.dumps({"session_id": name, "target": "fixture"}))
    (d / "scope.json").write_text(
        json.dumps({"targets": {"in_scope": ["203.0.113.10"], "out_of_scope": []}})
    )
    return d


def build_gateway_mirror(tmp: Path, stub_body: str) -> Path:
    """Mirror the gateway's directory layout with a stubbed toolchain resolver.

    server.py derives every helper path from its own location (`_HERE`), so
    copying it into a parallel tree next to a stub `scripts/toolchain-path.sh`
    redirects the resolver without production code carrying a test hook. The
    other skill directories are symlinked to the real ones, because
    create_session genuinely shells out to them.
    """
    real = Path(SERVER_PATH).resolve().parent
    mirror = tmp / "mirror" / "skills" / "mcp-gateway"
    (mirror / "scripts").mkdir(parents=True)

    for name in ("server.py", "token_store.py", "scope_gate.py", "requirements.txt"):
        src = real / name
        if src.is_file():
            shutil.copy2(src, mirror / name)

    stub = mirror / "scripts" / "toolchain-path.sh"
    stub.write_text(stub_body)
    stub.chmod(0o755)

    for sibling in ("session-management", "target-validation", "engagement-state"):
        src = real.parent / sibling
        if src.is_dir():
            (mirror.parent / sibling).symlink_to(src, target_is_directory=True)

    return mirror / "server.py"


async def drive(tmp, server_py, provisioning, body):
    """Run `body` against a fresh server process from a mirrored tree."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
    }
    if provisioning is not None:
        env["CLAUDE_PLUGIN_OPTION_TOOL_PROVISIONING"] = provisioning
    params = StdioServerParameters(command=sys.executable, args=[str(server_py)], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await body(session)


async def main():
    tmp = Path(tempfile.mkdtemp(prefix="clicky-toolchain-lazy-"))
    try:
        marker = tmp / "resolver-invocations"
        toolbin = tmp / "toolchain-bin"
        toolbin.mkdir()
        (toolbin / "clicky-fake-tool").write_text("#!/bin/bash\necho FAKE_TOOL_RAN\n")
        (toolbin / "clicky-fake-tool").chmod(0o755)

        GOOD_STUB = f"#!/bin/bash\necho x >> {marker}\nprintf '%s' '{toolbin}'\n"
        BAD_STUB = (f"#!/bin/bash\necho x >> {marker}\n"
                    "echo 'nix is broken in this fixture' >&2\nexit 1\n")
        good = build_gateway_mirror(tmp / "ok", GOOD_STUB)
        bad = build_gateway_mirror(tmp / "fail", BAD_STUB)
        plain = build_gateway_mirror(tmp / "plain", GOOD_STUB)

        def invocations():
            return len(marker.read_text().splitlines()) if marker.exists() else 0

        # --- 1 & 2: startup path is clean, create_session warms -------------
        sd = make_session(tmp, "s1")

        async def body(session):
            await session.list_tools()
            check("initialize + tools/list resolve NOTHING (startup path clean)",
                  invocations() == 0, f"resolver ran {invocations()}x before any tool call")

            # create_session is the documented warm trigger; it runs only after
            # the handshake, so it cannot affect MCP_TIMEOUT.
            await session.call_tool("create_session", {
                "target": "203.0.113.10", "objective": "fixture", "caller": "t"})
            for _ in range(40):
                if invocations() >= 1:
                    break
                await asyncio.sleep(0.25)
            check("create_session starts the background warm", invocations() >= 1,
                  "resolver never ran after create_session")

        await drive(tmp, good, "kalilix", body)

        # --- 3 & 4: PATH reaches the subprocess, and is memoized ------------
        marker.write_text("")
        sd2 = make_session(tmp, "s2")

        async def body2(session):
            out = tool_text(await session.call_tool("execute_command", {
                "command": "clicky-fake-tool", "session_dir": str(sd2),
                "timeout_s": 30, "caller": "t"}))
            check("resolved PATH reaches execute_command's subprocess",
                  "FAKE_TOOL_RAN" in out, out[:200])
            n = invocations()
            for _ in range(3):
                await session.call_tool("execute_command", {
                    "command": "true", "session_dir": str(sd2),
                    "timeout_s": 30, "caller": "t"})
            check("resolution is memoized, not repeated per command",
                  invocations() == n, f"{n} -> {invocations()}")

        await drive(tmp, build_gateway_mirror(tmp / "ok2", GOOD_STUB), "kalilix", body2)

        # --- 5: a failing resolve degrades LOUDLY ---------------------------
        marker.write_text("")
        sd3 = make_session(tmp, "s3")

        async def body3(session):
            out = tool_text(await session.call_tool("execute_command", {
                "command": "echo hello", "session_dir": str(sd3),
                "timeout_s": 30, "caller": "t"}))
            check("failed resolve prepends the TOOLCHAIN UNAVAILABLE banner",
                  "[TOOLCHAIN UNAVAILABLE" in out, out[:250])
            check("banner warns 'command not found' is not a negative finding",
                  "NOT be recorded as a negative finding" in out, out[:400])
            check("the command still ran despite degradation", "hello" in out, out[:250])

            out2 = tool_text(await session.call_tool("execute_command", {
                "command": "echo second", "session_dir": str(sd3),
                "timeout_s": 30, "caller": "t"}))
            check("banner is repeated on EVERY degraded call",
                  "[TOOLCHAIN UNAVAILABLE" in out2, out2[:200])
            check("a failed resolve is memoized too (not retried per command)",
                  invocations() == 1, f"resolver ran {invocations()}x")

            trace = sd3 / "logs" / "trace.jsonl"
            recs = [json.loads(l) for l in trace.read_text().splitlines() if l.strip()]
            errs = [r for r in recs if r.get("error")]
            check("degradation is recorded in trace.jsonl for the report agents",
                  len(errs) >= 1, "no trace record carried an error")

        await drive(tmp, bad, "kalilix", body3)

        # --- 6: default configuration pays nothing --------------------------
        marker.write_text("")
        sd4 = make_session(tmp, "s4")

        async def body4(session):
            out = tool_text(await session.call_tool("execute_command", {
                "command": "echo plain", "session_dir": str(sd4),
                "timeout_s": 30, "caller": "t"}))
            check("tool_provisioning unset never invokes the resolver",
                  invocations() == 0, f"resolver ran {invocations()}x")
            check("unset provisioning shows no degradation banner",
                  "[TOOLCHAIN UNAVAILABLE" not in out and "plain" in out, out[:200])

        await drive(tmp, plain, None, body4)

        return FAILED
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
