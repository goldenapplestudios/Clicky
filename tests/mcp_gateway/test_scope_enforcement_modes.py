#!/usr/bin/env python3
"""Real end-to-end check of server.py's register_target enforce/warn/off
mode switching (CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT), added when that
switching was implemented (previously only scope-enforcement-hook.sh, now
retired, had this logic - see server.py's register_target docstring).

Every register_target call below passes session_dir explicitly (the
directory make_session_dir() builds, with its own session.json so it
passes server.py's _validate_session_dir()) - server.py never reads
SESSION_DIR from the process environment or any pointer file, so these
checks don't set it either.

Same style as live_server_check.py: launches server.py as a real
subprocess over stdio and drives it with real MCP tools/call requests,
once per mode, against an OUT_OF_SCOPE target - not a description of
expected behavior, an actual client/server exchange for each of the 3
modes.

Usage: test_scope_enforcement_modes.py <server.py path>
Exits 0 if every check passes, 1 otherwise. Prints one PASS/FAIL line per
check plus a final summary.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession
from mcp.types import ElicitResult

SERVER_PATH = sys.argv[1]

FAILED = 0

OUT_OF_SCOPE_TARGET = "198.51.100.5"
NOT_LISTED_TARGET = "192.0.2.77"


def check(label: str, condition: bool, detail: str = "") -> None:
    global FAILED
    if condition:
        print(f"PASS: {label}")
    else:
        FAILED = 1
        print(f"FAIL: {label}" + (f" - {detail}" if detail else ""))


async def elicit_should_not_be_called(context, params):
    """warn/off must never elicit - register unconditionally either way."""
    raise AssertionError(
        f"elicitation was triggered but this mode must never elicit: {params!r}"
    )


def make_recording_elicit(record: list):
    """An elicitation callback that RECORDS the ask and declines it.

    Distinct from elicit_should_not_be_called, which raises: an exception in
    the callback is an *unexpected internal error* to register_target, which
    then fails open and registers the target anyway (its documented fail-open
    behavior). That makes "raised" indistinguishable from "never asked" at the
    tool result. Declining cleanly is a real operator decision, so the tool
    refuses - letting a test assert separately on WHETHER it asked (the
    record) and on what it did with the answer (is_error)."""

    async def callback(context, params):
        record.append(params.message)
        return ElicitResult(action="decline")

    return callback


def tool_text(result) -> str:
    parts = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text is not None:
            parts.append(text)
    return "\n".join(parts)


def make_session_dir(tmp_dir: str) -> Path:
    session_dir = Path(tmp_dir) / "session"
    session_dir.mkdir()
    # A real Clicky session directory always has a session.json (written by
    # session-manager.sh create / create_session as one of its first acts);
    # server.py's _validate_session_dir() requires one before accepting
    # session_dir as a valid argument at all.
    (session_dir / "session.json").write_text(
        '{"session_id": "fixture-session", "target": "fixture"}'
    )
    (session_dir / "scope.json").write_text(
        """{
  "targets": {
    "in_scope": ["203.0.113.10"],
    "out_of_scope": ["198.51.100.5"]
  }
}
"""
    )
    return session_dir


async def check_enforce_denies_out_of_scope(tmp_root: str) -> None:
    tmp_dir = tempfile.mkdtemp(dir=tmp_root, prefix="enforce-")
    session_dir = make_session_dir(tmp_dir)
    env = {
        **os.environ,
        "CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT": "enforce",
    }
    params = StdioServerParameters(command=sys.executable, args=[SERVER_PATH], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(
            read, write, elicitation_callback=elicit_should_not_be_called
        ) as session:
            await session.initialize()
            result = await session.call_tool(
                "register_target",
                {"target": OUT_OF_SCOPE_TARGET, "session_dir": str(session_dir)},
            )
            check(
                "enforce mode: OUT_OF_SCOPE target is denied",
                result.is_error,
                f"isError={result.is_error} text={tool_text(result)!r}",
            )
    log_path = session_dir / "logs" / "scope-enforcement.log"
    check(
        "enforce mode: no scope-enforcement.log written for a clean deny "
        "(only warn-mode/error paths log)",
        not log_path.exists(),
        f"unexpected log content: {log_path.read_text() if log_path.exists() else ''!r}",
    )


async def check_enforce_agent_token_reregister_is_in_scope(tmp_root: str) -> None:
    """Regression: a dispatched agent re-registers using the TOKEN it was
    handed (e.g. "TARGET_1"), not the raw target - every agent file tells it
    to call register_target on "the value you were given," and the value it
    was given is the token. register_target must resolve that token back to
    its real value before scope-checking; otherwise classify() compares the
    literal string "TARGET_1" against a scope.json holding the real IP, gets
    NOT_LISTED, and fires an elicitation on the PRIMARY in-scope target -
    breaking autonomous /pentest runs. elicit_should_not_be_called makes any
    elicitation here a hard failure (that was the pre-fix behavior)."""
    tmp_dir = tempfile.mkdtemp(dir=tmp_root, prefix="enforce-token-")
    session_dir = make_session_dir(tmp_dir)
    env = {
        **os.environ,
        "CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT": "enforce",
    }
    params = StdioServerParameters(command=sys.executable, args=[SERVER_PATH], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(
            read, write, elicitation_callback=elicit_should_not_be_called
        ) as session:
            await session.initialize()
            # 1) Orchestrator registers the raw in-scope target -> TARGET_1.
            first = await session.call_tool(
                "register_target",
                {"target": "203.0.113.10", "session_dir": str(session_dir)},
            )
            check(
                "enforce mode: raw in-scope target registers (orchestrator path)",
                not first.is_error and tool_text(first).strip() == "TARGET_1",
                f"isError={first.is_error} text={tool_text(first)!r}",
            )
            # 2) A dispatched agent re-registers using the TOKEN it was handed.
            #    Must resolve to the same in-scope value: same token back, no elicit.
            second = await session.call_tool(
                "register_target",
                {"target": "TARGET_1", "session_dir": str(session_dir)},
            )
            check(
                "enforce mode: re-registering with the token (agent path) stays "
                "IN_SCOPE and returns the same token, without elicitation",
                not second.is_error and tool_text(second).strip() == "TARGET_1",
                f"isError={second.is_error} text={tool_text(second)!r}",
            )


async def check_enforce_autodiscovered_host_does_not_elicit(tmp_root: str) -> None:
    """Regression: the gateway mints TARGET_n by two paths, and they must not
    disagree. redact()/_discover() mints promiscuously for PRIVACY (no scope
    check, by design - an unredacted value must never reach the model), while
    register_target is the AUTHORIZATION path. Live, a vhost found in scan
    output was auto-minted as TARGET_5 and then an agent asking for that same
    value's token was stopped by an elicitation on a host the session was
    already working with - halting the autonomous run.

    Part 1 asserts a value the privacy path already minted registers without
    elicitation. Part 2 is the negative control: a genuinely novel host must
    STILL elicit, proving the gate was made consistent, not disabled."""
    tmp_dir = tempfile.mkdtemp(dir=tmp_root, prefix="autodiscovered-")
    session_dir = make_session_dir(tmp_dir)
    env = {
        **os.environ,
        "CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT": "enforce",
    }
    params = StdioServerParameters(command=sys.executable, args=[SERVER_PATH], env=env)
    asked: list = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(
            read, write, elicitation_callback=make_recording_elicit(asked)
        ) as session:
            await session.initialize()
            # 1) A hostname appears in command OUTPUT -> the privacy path mints
            #    a token for it, with no scope check (that is by design).
            ran = await session.call_tool(
                "execute_command",
                {
                    "command": "echo 'Host: connected.htb responded'",
                    "session_dir": str(session_dir),
                },
            )
            ran_text = tool_text(ran)
            check(
                "output redaction auto-mints a token for a discovered host "
                "(privacy path, unscoped by design)",
                "connected.htb" not in ran_text and "TARGET_" in ran_text,
                f"text={ran_text!r}",
            )
            # 2) An agent now asks for that same value's token. It is NOT_LISTED
            #    in scope.json, but the session already works with it, so the
            #    authorization path must not re-litigate -> no elicitation.
            reg = await session.call_tool(
                "register_target",
                {"target": "connected.htb", "session_dir": str(session_dir)},
            )
            reg_text = tool_text(reg)
            check(
                "NOT_LISTED host already minted by output redaction registers "
                "without elicitation (the autonomy stall)",
                not reg.is_error
                and reg_text.strip().startswith("TARGET_")
                and asked == [],
                f"isError={reg.is_error} text={reg_text!r} asked={asked!r}",
            )
            # 3) NEGATIVE CONTROL: a host never seen this session is genuinely
            #    novel and must still elicit. elicit_should_not_be_called makes
            #    that surface as an error - which is the PASS condition here.
            novel = await session.call_tool(
                "register_target",
                {"target": "192.0.2.77", "session_dir": str(session_dir)},
            )
            check(
                "a novel IP ADDRESS is a new network destination and STILL "
                "elicits; a declined ask refuses it",
                len(asked) == 1 and "192.0.2.77" in asked[0] and novel.is_error,
                f"asked={asked!r} isError={novel.is_error} "
                f"text={tool_text(novel)!r}",
            )
            # 4) A hostname NEVER seen in this engagement has no provenance
            #    tying it to an authorized host, so it is not an alias and
            #    must still be asked about.
            unseen = await session.call_tool(
                "register_target",
                {"target": "unrelated.example.org", "session_dir": str(session_dir)},
            )
            check(
                "a hostname never seen this session is NOT an alias and still "
                "elicits (provenance, not merely being a name, is the signal)",
                len(asked) == 2
                and "unrelated.example.org" in asked[1]
                and unseen.is_error,
                f"asked={asked!r} isError={unseen.is_error} "
                f"text={tool_text(unseen)!r}",
            )


async def check_warn_allows_and_logs(tmp_root: str) -> None:
    tmp_dir = tempfile.mkdtemp(dir=tmp_root, prefix="warn-")
    session_dir = make_session_dir(tmp_dir)
    env = {
        **os.environ,
        "CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT": "warn",
    }
    params = StdioServerParameters(command=sys.executable, args=[SERVER_PATH], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(
            read, write, elicitation_callback=elicit_should_not_be_called
        ) as session:
            await session.initialize()
            result = await session.call_tool(
                "register_target",
                {"target": OUT_OF_SCOPE_TARGET, "session_dir": str(session_dir)},
            )
            text = tool_text(result)
            check(
                "warn mode: OUT_OF_SCOPE target is still registered (never blocks)",
                not result.is_error and text.strip() == "TARGET_1",
                f"isError={result.is_error} text={text!r}",
            )
    log_path = session_dir / "logs" / "scope-enforcement.log"
    log_content = log_path.read_text() if log_path.exists() else ""
    check(
        "warn mode: what-would-have-happened is logged to logs/scope-enforcement.log",
        log_path.exists()
        and "WARN mode - would have denied" in log_content
        and OUT_OF_SCOPE_TARGET in log_content,
        f"log content={log_content!r}",
    )


async def check_off_allows_silently(tmp_root: str) -> None:
    tmp_dir = tempfile.mkdtemp(dir=tmp_root, prefix="off-")
    session_dir = make_session_dir(tmp_dir)
    env = {
        **os.environ,
        "CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT": "off",
    }
    params = StdioServerParameters(command=sys.executable, args=[SERVER_PATH], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(
            read, write, elicitation_callback=elicit_should_not_be_called
        ) as session:
            await session.initialize()
            result = await session.call_tool(
                "register_target",
                {"target": OUT_OF_SCOPE_TARGET, "session_dir": str(session_dir)},
            )
            text = tool_text(result)
            check(
                "off mode: OUT_OF_SCOPE target is registered unconditionally",
                not result.is_error and text.strip() == "TARGET_1",
                f"isError={result.is_error} text={text!r}",
            )
            # off must skip scope checking entirely - not even a warn-style log.
            result2 = await session.call_tool(
                "register_target",
                {"target": NOT_LISTED_TARGET, "session_dir": str(session_dir)},
            )
            text2 = tool_text(result2)
            check(
                "off mode: NOT_LISTED target is also registered unconditionally, no elicitation",
                not result2.is_error and text2.strip() == "TARGET_2",
                f"isError={result2.is_error} text={text2!r}",
            )
    log_path = session_dir / "logs" / "scope-enforcement.log"
    check(
        "off mode: no scope-enforcement.log written at all (checking is skipped, not just silenced)",
        not log_path.exists(),
        f"unexpected log content: {log_path.read_text() if log_path.exists() else ''!r}",
    )


async def check_default_mode_is_enforce(tmp_root: str) -> None:
    """No CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT set at all -> defaults to enforce."""
    tmp_dir = tempfile.mkdtemp(dir=tmp_root, prefix="default-")
    session_dir = make_session_dir(tmp_dir)
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT"}
    params = StdioServerParameters(command=sys.executable, args=[SERVER_PATH], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(
            read, write, elicitation_callback=elicit_should_not_be_called
        ) as session:
            await session.initialize()
            result = await session.call_tool(
                "register_target",
                {"target": OUT_OF_SCOPE_TARGET, "session_dir": str(session_dir)},
            )
            check(
                "unset scope_enforcement env var defaults to enforce mode (denies OUT_OF_SCOPE)",
                result.is_error,
                f"isError={result.is_error} text={tool_text(result)!r}",
            )


async def main() -> int:
    tmp_root = tempfile.mkdtemp(prefix="clicky-mcp-gateway-scope-modes-")
    try:
        await check_enforce_denies_out_of_scope(tmp_root)
        await check_enforce_agent_token_reregister_is_in_scope(tmp_root)
        await check_enforce_autodiscovered_host_does_not_elicit(tmp_root)
        await check_warn_allows_and_logs(tmp_root)
        await check_off_allows_silently(tmp_root)
        await check_default_mode_is_enforce(tmp_root)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    print()
    print("=== SUMMARY ===")
    print("ALL PASS" if FAILED == 0 else "SOME FAILED")
    return FAILED


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
