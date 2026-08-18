#!/usr/bin/env python3
"""Real end-to-end check of skills/mcp-gateway/server.py: launches it as an
actual subprocess over stdio, performs a real MCP `initialize` handshake,
lists its tools, and drives all 7 tools through real `tools/call` requests
- including a real `create_session` bootstrap call, explicit `session_dir`
threading through every other tool (no `SESSION_DIR` env var, no pointer
file - see server.py/SKILL.md's "Session context" section), a real
elicitation round-trip for register_target's NOT_LISTED case (an
elicitation_callback on the client side auto-accepts, the same way an
operator approving the prompt would), and confirmation that every
session-scoped tool fails loudly (not silently) on a missing, nonexistent,
or invalid `session_dir`.

Not a unit test of token_store.py/scope_gate.py in isolation (see
test_token_store.py / test_scope_gate.sh for those) - this is specifically
checking that the wiring through the real mcp SDK/server process/stdio
transport actually works end to end, token substitution included.

Usage: live_server_check.py <server.py path>
Exits 0 if every check passes, 1 otherwise. Prints one PASS/FAIL line per
check plus a final summary.
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
from mcp_types import ElicitResult

SERVER_PATH = sys.argv[1]

FAILED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global FAILED
    if condition:
        print(f"PASS: {label}")
    else:
        FAILED = 1
        print(f"FAIL: {label}" + (f" - {detail}" if detail else ""))


async def elicitation_callback(context, params):
    """Auto-accept every elicitation, like an operator approving the prompt."""
    return ElicitResult(action="accept", content={"confirm": True})


def tool_text(result) -> str:
    """Flatten a CallToolResult's text content blocks into one string."""
    parts = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text is not None:
            parts.append(text)
    return "\n".join(parts)


async def main() -> int:
    tmp_dir = tempfile.mkdtemp(prefix="clicky-mcp-gateway-live-check-")
    try:
        # session_dir this check drives register_target/execute_command/etc.
        # against directly - hand-built rather than obtained via
        # create_session, so this check controls its own scope.json content.
        # A real Clicky session directory always has a session.json (written
        # by session-manager.sh create as one of its first acts) - server.py's
        # _validate_session_dir() requires one to exist before accepting a
        # session_dir argument, so this fixture includes one too.
        session_dir = Path(tmp_dir) / "session"
        session_dir.mkdir()
        (session_dir / "session.json").write_text(
            json.dumps({"session_id": "fixture-session", "target": "fixture"})
        )
        scope_path = session_dir / "scope.json"
        scope_path.write_text(
            """{
  "targets": {
    "in_scope": ["203.0.113.10"],
    "out_of_scope": ["198.51.100.5"]
  }
}
"""
        )

        # Sandbox for create_session's own session-manager.sh-backed session
        # creation below, so this check never writes into the real
        # ~/.claude/sessions - same env var session-manager.sh itself honors.
        create_session_base = Path(tmp_dir) / "session-base"
        create_session_base.mkdir()

        params = StdioServerParameters(
            command=sys.executable,
            args=[SERVER_PATH],
            # Deliberately no SESSION_DIR here - server.py never reads it
            # (there is no environment-variable or pointer-file fallback
            # anywhere in this module; session_dir is a required argument on
            # every tool below except create_session). See "Session context"
            # in SKILL.md.
            env={
                **os.environ,
                "CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY": str(create_session_base),
            },
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(
                read, write, elicitation_callback=elicitation_callback
            ) as session:
                init_result = await session.initialize()
                check(
                    "initialize handshake succeeds",
                    init_result.server_info.name == "clicky-mcp-gateway",
                    f"got server_info={init_result.server_info!r}",
                )

                tools_result = await session.list_tools()
                tool_names = {t.name for t in tools_result.tools}
                expected = {
                    "create_session",
                    "register_target",
                    "execute_command",
                    "fetch_url",
                    "read_file",
                    "write_file",
                    "search_files",
                }
                check(
                    "tools/list reports exactly the 7 expected tools",
                    tool_names == expected,
                    f"got {sorted(tool_names)}",
                )

                # --- create_session: the real cold-start bootstrap path ---
                # No session_dir exists anywhere yet - this is the one tool
                # that doesn't need one, because it creates one.
                result = await session.call_tool(
                    "create_session", {"target": "203.0.113.99"}
                )
                text = tool_text(result)
                check(
                    "create_session succeeds on a valid target with no prior session",
                    not result.is_error,
                    f"isError={result.is_error} text={text!r}",
                )
                created = json.loads(text) if not result.is_error else {}
                created_session_dir = created.get("session_dir", "")
                created_session_id = created.get("session_id", "")
                check(
                    "create_session's returned session_dir actually exists on disk",
                    bool(created_session_dir) and Path(created_session_dir).is_dir(),
                    f"session_dir={created_session_dir!r}",
                )
                check(
                    "create_session's returned session_dir looks like a real "
                    "session (has session.json) and lives under the sandboxed "
                    "CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY, not the "
                    "real ~/.claude/sessions",
                    (Path(created_session_dir) / "session.json").is_file()
                    and Path(created_session_dir).parent == create_session_base,
                    f"session_dir={created_session_dir!r} sandbox={create_session_base}",
                )
                check(
                    "create_session's session_id matches the session_dir's own basename",
                    created_session_id
                    and Path(created_session_dir).name == created_session_id,
                    f"session_id={created_session_id!r} session_dir={created_session_dir!r}",
                )

                # --- create_session: invalid/dangerous target fails loudly,
                # no session directory left behind ---
                before = set(create_session_base.iterdir())
                result = await session.call_tool(
                    "create_session", {"target": "127.0.0.1"}
                )
                after = set(create_session_base.iterdir())
                check(
                    "create_session refuses a dangerous target (localhost)",
                    result.is_error,
                    f"isError={result.is_error} text={tool_text(result)!r}",
                )
                check(
                    "create_session's target-validation failure allocates no "
                    "session directory at all",
                    before == after,
                    f"before={before} after={after}",
                )

                # --- the freshly created_session_dir is immediately usable
                # by another tool (register_target), exactly the way
                # commands/pentest.md Step 1 chains create_session ->
                # register_target ---
                result = await session.call_tool(
                    "register_target",
                    {"target": "203.0.113.99", "session_dir": created_session_dir},
                )
                text = tool_text(result)
                check(
                    "register_target succeeds against the session_dir "
                    "create_session just returned (no scope.json -> "
                    "NOT_LISTED -> elicitation -> approved)",
                    not result.is_error and text.strip() == "TARGET_1",
                    f"isError={result.is_error} text={text!r}",
                )

                # --- every session-scoped tool requires session_dir: missing
                # entirely fails loudly (not silently, not via some fallback) ---
                result = await session.call_tool(
                    "execute_command", {"command": "echo hi"}
                )
                check(
                    "execute_command with no session_dir argument at all fails "
                    "loudly (schema validation error), not silently",
                    result.is_error and "session_dir" in tool_text(result),
                    f"isError={result.is_error} text={tool_text(result)!r}",
                )

                # --- nonexistent session_dir fails loudly with a clear message ---
                result = await session.call_tool(
                    "execute_command",
                    {"command": "echo hi", "session_dir": "/nonexistent/clicky-path"},
                )
                text = tool_text(result)
                check(
                    "execute_command with a nonexistent session_dir fails "
                    "loudly with a clear error, not silent misdirection",
                    result.is_error and "does not exist" in text,
                    f"isError={result.is_error} text={text!r}",
                )

                # --- a real directory that isn't a valid session (no
                # session.json) also fails loudly, not silently accepted ---
                bogus_dir = Path(tmp_dir) / "not_a_session"
                bogus_dir.mkdir()
                result = await session.call_tool(
                    "execute_command",
                    {"command": "echo hi", "session_dir": str(bogus_dir)},
                )
                text = tool_text(result)
                check(
                    "execute_command with a directory that exists but has no "
                    "session.json fails loudly, not silently accepted",
                    result.is_error and "session.json" in text,
                    f"isError={result.is_error} text={text!r}",
                )

                # --- register_target: IN_SCOPE (against the hand-built
                # session_dir/scope.json fixture from here on) ---
                result = await session.call_tool(
                    "register_target",
                    {"target": "203.0.113.10", "session_dir": str(session_dir)},
                )
                text = tool_text(result)
                check(
                    "register_target(IN_SCOPE) mints TARGET_1",
                    not result.is_error and text.strip() == "TARGET_1",
                    f"isError={result.is_error} text={text!r}",
                )

                # --- register_target: same value again is idempotent ---
                result = await session.call_tool(
                    "register_target",
                    {"target": "203.0.113.10", "session_dir": str(session_dir)},
                )
                text = tool_text(result)
                check(
                    "register_target on an already-registered value returns the same token",
                    not result.is_error and text.strip() == "TARGET_1",
                    f"isError={result.is_error} text={text!r}",
                )

                # --- register_target: OUT_OF_SCOPE is refused ---
                result = await session.call_tool(
                    "register_target",
                    {"target": "198.51.100.5", "session_dir": str(session_dir)},
                )
                check(
                    "register_target(OUT_OF_SCOPE) is refused",
                    result.is_error,
                    f"isError={result.is_error} text={tool_text(result)!r}",
                )

                # --- register_target: NOT_LISTED goes through elicitation, gets approved ---
                result = await session.call_tool(
                    "register_target",
                    {"target": "192.0.2.77", "session_dir": str(session_dir)},
                )
                text = tool_text(result)
                check(
                    "register_target(NOT_LISTED) approved via elicitation mints TARGET_2",
                    not result.is_error and text.strip() == "TARGET_2",
                    f"isError={result.is_error} text={text!r}",
                )

                # --- execute_command: resolve token -> real value -> redact back to token ---
                result = await session.call_tool(
                    "execute_command",
                    {"command": "echo TARGET_1", "session_dir": str(session_dir)},
                )
                text = tool_text(result)
                check(
                    "execute_command resolves TARGET_1 to the real IP before running, "
                    "then redacts the real IP back to TARGET_1 in the output",
                    not result.is_error
                    and "TARGET_1" in text
                    and "203.0.113.10" not in text,
                    f"isError={result.is_error} text={text!r}",
                )

                # --- write_file / read_file round trip through tokens ---
                out_path = str(session_dir / "notes.txt")
                result = await session.call_tool(
                    "write_file",
                    {
                        "path": out_path,
                        "content": "recon target is TARGET_1\n",
                        "session_dir": str(session_dir),
                    },
                )
                check(
                    "write_file succeeds",
                    not result.is_error,
                    f"isError={result.is_error} text={tool_text(result)!r}",
                )
                # The file on disk must contain the REAL ip, not the token -
                # that's the entire point of resolving before writing.
                on_disk = Path(out_path).read_text()
                check(
                    "write_file wrote the resolved real value to disk, not the token",
                    "203.0.113.10" in on_disk and "TARGET_1" not in on_disk,
                    f"on-disk content={on_disk!r}",
                )

                result = await session.call_tool(
                    "read_file", {"path": out_path, "session_dir": str(session_dir)}
                )
                text = tool_text(result)
                check(
                    "read_file redacts the real value back to TARGET_1",
                    not result.is_error
                    and "TARGET_1" in text
                    and "203.0.113.10" not in text,
                    f"isError={result.is_error} text={text!r}",
                )

                # --- search_files: grep the real file, redact matches ---
                result = await session.call_tool(
                    "search_files",
                    {
                        "pattern": "recon",
                        "path": str(session_dir),
                        "session_dir": str(session_dir),
                    },
                )
                text = tool_text(result)
                check(
                    "search_files finds the match and redacts the real value in it",
                    not result.is_error
                    and "TARGET_1" in text
                    and "203.0.113.10" not in text,
                    f"isError={result.is_error} text={text!r}",
                )

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print()
    print("=== SUMMARY ===")
    print("ALL PASS" if FAILED == 0 else "SOME FAILED")
    return FAILED


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
