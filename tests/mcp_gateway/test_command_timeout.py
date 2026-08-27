#!/usr/bin/env python3
"""Live check for execute_command's timeout handling in server.py.

Backs a specific, previously-real failure mode: a long-running command that
exceeded `timeout_s` returned ONLY the string `[TIMEOUT after Ns]`. Every byte
the command had already produced was discarded, and because `shell=True` kills
only the shell, the real work (nmap, hydra, a spray script) was orphaned and
kept running against the target after the agent believed it had stopped.

The practical consequence was that "the scan did not finish" and "the scan
found nothing" were indistinguishable to the calling agent, so a timed-out
check could be written up as a clean negative.

This drives the real server over real MCP stdio and asserts:
  1. Partial output produced before the timeout is RETURNED, not discarded.
  2. The result is banner-marked as INCOMPLETE / not a negative result.
  3. The whole process group is killed - no orphan survives the timeout.
  4. Normal (non-timeout) commands still report their real exit status.

Usage: test_command_timeout.py /path/to/server.py
"""
import asyncio
import json
import shutil
import sys
import tempfile
import time
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


async def main() -> int:
    tmp_dir = tempfile.mkdtemp(prefix="clicky-gateway-timeout-check-")
    try:
        session_dir = Path(tmp_dir) / "session"
        session_dir.mkdir()
        (session_dir / "session.json").write_text(
            json.dumps({"session_id": "timeout-fixture", "target": "fixture"})
        )
        (session_dir / "scope.json").write_text(
            json.dumps({"targets": {"in_scope": ["203.0.113.10"], "out_of_scope": []}})
        )

        orphan_marker = Path(tmp_dir) / "orphan-survived.txt"

        params = StdioServerParameters(
            command=sys.executable,
            args=[SERVER_PATH],
            env={
                "PATH": __import__("os").environ.get("PATH", ""),
                "HOME": __import__("os").environ.get("HOME", ""),
                "CLICKY_SESSION_BASE": str(Path(tmp_dir) / "session-base"),
            },
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                async def run(cmd, timeout_s):
                    return tool_text(
                        await session.call_tool(
                            "execute_command",
                            {
                                "command": cmd,
                                "session_dir": str(session_dir),
                                "timeout_s": timeout_s,
                                "caller": "timeout-test",
                            },
                        )
                    )

                # --- 1/2: partial output survives a timeout ---------------
                out = await run(
                    "echo CLICKY_PARTIAL_MARKER; echo ON_STDERR >&2; sleep 45", 3
                )
                check(
                    "partial stdout produced before the timeout is preserved",
                    "CLICKY_PARTIAL_MARKER" in out,
                    f"got: {out[:300]!r}",
                )
                check(
                    "partial stderr is preserved too",
                    "ON_STDERR" in out,
                    f"got: {out[:300]!r}",
                )
                check(
                    "timeout result is banner-marked INCOMPLETE",
                    "RESULT INCOMPLETE" in out,
                    f"got: {out[:300]!r}",
                )
                check(
                    "timeout result explicitly warns it is NOT a negative result",
                    "NOT a negative result" in out,
                    f"got: {out[:300]!r}",
                )
                check(
                    "timeout result names UNTESTED work",
                    "UNTESTED" in out,
                    f"got: {out[:300]!r}",
                )

                # --- 3: no orphan survives -------------------------------
                # The backgrounded subshell would write the marker 6s from
                # now. A process-group kill takes it out; killing only the
                # shell leaves it running and the marker appears.
                await run(
                    f"( sleep 6; echo alive > {orphan_marker} ) & echo LAUNCHED; sleep 45",
                    2,
                )
                await asyncio.sleep(9)
                check(
                    "backgrounded grandchild is killed with the process group "
                    "(no orphan left hammering the target)",
                    not orphan_marker.exists(),
                    f"orphan marker was created at {orphan_marker}",
                )

                # --- 4: normal commands unaffected -----------------------
                ok = await run("echo HEALTHY; exit 0", 30)
                check("successful command reports [exit 0]", "[exit 0]" in ok, ok[:200])
                check("successful command returns its output", "HEALTHY" in ok, ok[:200])

                bad = await run("echo NOPE >&2; exit 7", 30)
                check("failing command reports its real exit code", "[exit 7]" in bad, bad[:200])
                check(
                    "non-timeout result carries no INCOMPLETE banner",
                    "RESULT INCOMPLETE" not in bad,
                    bad[:200],
                )

                # --- 5: non-UTF-8 output must not crash the tool ----------
                # Command output is frequently non-UTF-8 (hexdump, tcpdump -X,
                # a compiled artifact). A strict decode raised UnicodeDecodeError
                # inside the tool and killed the whole call; errors="replace"
                # returns the output with replacement chars instead.
                binout = await run(r"printf '\xff\xfe\xaf'; echo; echo TAIL_OK", 30)
                check(
                    "non-UTF-8 command output is returned, not a crash",
                    "TAIL_OK" in binout and "[exit 0]" in binout,
                    f"got: {binout[:200]!r}",
                )

                # --- 6: bashisms work (bash executable, not dash) --------
                bashout = await run("arr=(a b c); echo GOT_${arr[1]}", 30)
                check(
                    "bash arrays work (execute_command runs bash, not dash)",
                    "GOT_b" in bashout,
                    f"got: {bashout[:200]!r}",
                )
        return FAILED
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
