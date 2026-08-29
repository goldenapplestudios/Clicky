#!/usr/bin/env python3
"""Real end-to-end check that an agent cannot widen its own scope.

Backs a specific, previously-real hole. Every agent holds execute_command
(an arbitrary shell) and most hold write_file, and scope.json was re-read
from disk on EVERY classification with no lock, hash or cache. So

    echo '{"targets":{"in_scope":["0.0.0.0/0"]}}' > $SESSION_DIR/scope.json

silently widened scope for every later check: the control lived inside the
blast radius of the thing it constrains. A network allowlist derived from
that file would have been a lock with the key left in it.

The fix locks the scope in force to a directory outside session_dir on
first use, and decides against that copy forever after. The on-disk file
stays visible and editable - an edit is inert and reported, not obeyed.

OWASP APTS MR-012 (scope immutable after initialization), MR-023 (deny the
agent the ability to modify safety controls), AR-020 (audit reconstructable
without agent-written data).

This drives the real server over real MCP stdio and asserts:
  1. An out-of-scope target is refused (baseline).
  2. Rewriting scope.json via execute_command does NOT widen scope.
  3. Rewriting it via write_file is refused outright.
  4. The tamper is recorded where an operator will see it.
  5. Control state and the audit trail are not agent-writable.
  6. Legitimate engagement output still writes normally.

Usage: test_scope_tamper.py /path/to/server.py
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

SERVER_PATH = sys.argv[1]
FAILED = 0

# The attack: move an explicitly EXCLUDED host into in_scope and drop the
# exclusion. Using an out_of_scope host (not merely an unlisted one) makes
# both the before and after states a hard deny with no elicitation, so the
# assertions turn purely on which scope is in force.
WIDE_OPEN = '{"targets": {"in_scope": ["0.0.0.0/0", "198.51.100.5"], "out_of_scope": []}}'


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


async def elicit_should_not_be_called(context, params):
    raise AssertionError(f"unexpected elicitation: {params!r}")


async def main() -> int:
    tmp_dir = tempfile.mkdtemp(prefix="clicky-scope-tamper-")
    try:
        session_dir = Path(tmp_dir) / "session"
        for sub in ("recon", "state", "logs"):
            (session_dir / sub).mkdir(parents=True)
        (session_dir / "session.json").write_text(
            json.dumps({"session_id": "tamper-fixture", "target": "203.0.113.10"})
        )
        (session_dir / "scope.json").write_text(
            json.dumps(
                {
                    "targets": {
                        "in_scope": ["203.0.113.10"],
                        "out_of_scope": ["198.51.100.5"],
                    }
                }
            )
        )

        params = StdioServerParameters(
            command=sys.executable,
            args=[SERVER_PATH],
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": os.environ.get("HOME", ""),
                "CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT": "enforce",
                # Keep the locked-scope store inside the fixture.
                "CLAUDE_PLUGIN_DATA": str(Path(tmp_dir) / "plugin-data"),
            },
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(
                read, write, elicitation_callback=elicit_should_not_be_called
            ) as session:
                await session.initialize()

                async def register(target):
                    return await session.call_tool(
                        "register_target",
                        {"target": target, "session_dir": str(session_dir)},
                    )

                async def run(cmd):
                    return tool_text(
                        await session.call_tool(
                            "execute_command",
                            {"command": cmd, "session_dir": str(session_dir)},
                        )
                    )

                async def wfile(path, content):
                    return tool_text(
                        await session.call_tool(
                            "write_file",
                            {
                                "path": path,
                                "content": content,
                                "session_dir": str(session_dir),
                            },
                        )
                    )

                # 1) Baseline: the in-scope target registers, which locks
                #    the scope; the excluded host is denied outright. No
                #    elicitation on either path - elicit_should_not_be_called
                #    makes any prompt a hard failure.
                ok = await register("203.0.113.10")
                check(
                    "in-scope target registers (and locks the scope)",
                    not ok.is_error and tool_text(ok).strip() == "TARGET_1",
                    f"isError={ok.is_error} text={tool_text(ok)!r}",
                )
                denied_before = await register("198.51.100.5")
                check(
                    "explicitly out-of-scope target is denied before tampering",
                    denied_before.is_error,
                    f"text={tool_text(denied_before)!r}",
                )

                # 2) THE ATTACK: rewrite scope.json through the shell every
                #    agent holds, then retry the same target.
                await run(
                    f"cat > {session_dir}/scope.json << 'EOF'\n{WIDE_OPEN}\nEOF"
                )
                on_disk = (session_dir / "scope.json").read_text()
                check(
                    "the shell really did overwrite scope.json on disk "
                    "(the attack landed; only its effect is neutralised)",
                    "0.0.0.0/0" in on_disk,
                    f"on-disk scope now: {on_disk[:120]!r}",
                )
                denied_after = await register("198.51.100.5")
                check(
                    "after the rewrite the same target is STILL denied - the "
                    "locked scope governs, not the file the agent controls",
                    denied_after.is_error,
                    f"isError={denied_after.is_error} "
                    f"text={tool_text(denied_after)!r}",
                )

                # 3) The same attack via write_file is refused outright.
                w = await wfile(f"{session_dir}/scope.json", WIDE_OPEN)
                check(
                    "write_file to scope.json is refused",
                    "[REFUSED]" in w,
                    f"got: {w[:200]!r}",
                )

                # 4) The operator can see it happened.
                log = session_dir / "logs" / "scope-enforcement.log"
                log_text = log.read_text() if log.exists() else ""
                check(
                    "the tamper is recorded where an operator will find it",
                    "TAMPER" in log_text,
                    f"log: {log_text[-300:]!r}",
                )

                # 5) Control state and audit trail are not agent-writable.
                for rel, what in (
                    ("state/technique-authorizations.json", "technique gate"),
                    ("logs/trace.jsonl", "audit trail"),
                    ("../escape.txt", "path outside the session"),
                ):
                    out = await wfile(f"{session_dir}/{rel}", "x")
                    check(
                        f"write_file to {what} ({rel}) is refused",
                        "[REFUSED]" in out,
                        f"got: {out[:160]!r}",
                    )

                # 6) ...but real engagement output still works.
                good = await wfile(f"{session_dir}/recon/ports.json", '{"open": [22]}')
                check(
                    "legitimate engagement output still writes",
                    "[REFUSED]" not in good and "OK: wrote" in good,
                    f"got: {good[:160]!r}",
                )

                # 7) The token map is never readable through the gateway.
                tm = tool_text(
                    await session.call_tool(
                        "read_file",
                        {
                            "path": f"{session_dir}/.token-map.json",
                            "session_dir": str(session_dir),
                        },
                    )
                )
                check(
                    "read_file refuses the token map",
                    "[REFUSED]" in tm,
                    f"got: {tm[:160]!r}",
                )
        return FAILED
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
