#!/usr/bin/env python3
"""MCP Gateway server - registered as an MCP server as of Phase 2.

Exposes 8 MCP tools that resolve TARGET_n/CRED_*_n placeholder tokens to
real values before acting, and redact real values back to tokens in
whatever they return - so a caller only ever sees tokens in tool-call
arguments and tool-result content, while the actual command execution /
file I/O / network calls use real data. See SKILL.md for the full design
and current phase status: as of Phase 2, this server is registered in
.claude-plugin/plugin.json's `mcpServers` block, launched via
scripts/launch.sh (which provisions its venv synchronously before
exec-ing this file - see SKILL.md for why launching via the venv python
directly isn't safe), so Claude Code will launch it - but no agent has
been given these tools in place of direct Bash/Read/Write/WebFetch yet
(that wiring is Phase 3), so nothing calls it in a real session today.

Built on the official `mcp` SDK's MCPServer (skills/mcp-gateway/
requirements.txt pins the exact version) - not hand-rolled JSON-RPC.

Session context: `session_dir` is an explicit, required parameter on every
tool that operates *within* an existing session (`register_target`,
`execute_command`, `fetch_url`, `read_file`, `write_file`,
`search_files`, `log_agent_boundary`) - never read from this process's
own environment, never read from a pointer file written by some earlier
call. The one exception is `create_session(target)`, which needs no
`session_dir` because it creates one, and returns `{"session_dir": ...,
"session_id": ...}` - that return value is the *only* source of truth
for `session_dir` for the rest of an engagement. The caller (an
orchestrating command/workflow, or an agent dispatched by one) captures
it once and threads it through every later gateway call and Task-tool
dispatch explicitly, the same way Clicky's agents already carry
`$SESSION_ID` explicitly rather than assuming it's ambiently available
(see `agents/exploit-agent.md`: "Substitute the literal session ID you
were handed as part of your dispatch context").

This replaces an earlier, rejected design where `_session_dir()` read
`$SESSION_DIR` from the process environment first, then silently fell back
to a `${CLAUDE_PLUGIN_DATA}/.current-session` pointer file written by
`commands/pentest.md` Step 1 for the rest of this (long-lived) process's
life. That design fixed a real cold-start bug (this server's own
`SESSION_DIR` env var, if set at all, is fixed once at process launch -
before any engagement exists - and can never change afterward) but did so
by introducing ambient, silently-inferred session state as a *permanent*
mechanism, not just a one-time bootstrap. Reviewed against real precedent
(LSP's `initialize`/`rootUri` pattern, MCP's own protocol design
philosophy, and general RPC/context-propagation practice - e.g. Go's
mandatory explicit-`Context`-parameter convention) and rejected: for a
credential-handling gateway specifically, a stale or wrong pointer silently
misdirecting a tool call to the wrong engagement's session directory is a
real target/credential cross-contamination risk, not a style issue. There
is no pointer file anywhere in this module anymore - `create_session()`
returning `session_dir` directly to its caller, who threads it through
everything downstream, fully replaces the need for one. See SKILL.md's
"Session context" section for the full design.

Phase 0 multi-CLI groundwork (see the multi-CLI portability plan this
implements): every tool below now accepts an optional `caller` parameter
(the calling agent's own name, e.g. "recon-agent" - every agent's prompt
already knows its own identity) and appends a JSONL trace record to
`$SESSION_DIR/logs/trace.jsonl` on every call, via the `_trace()` helper
below. This replaces the previous hook-based tracing
(`hooks/hooks.json`'s PostToolUse/PostToolUseFailure/SubagentStop entries
-> skills/session-management/scripts/trace-logger.sh, now deleted), which
depended on Claude Code's specific hook event names and payload contract,
and cross-referenced Claude's own session_id against a separately
maintained "current session" pointer file. Since every agent action
already funnels through this gateway by construction, logging it here
instead removes that dependency entirely - portable to any MCP-capable
host, not just Claude Code - and keys trace records on `session_dir`
directly: always an explicit, already-validated parameter on every call
already, no pointer-file indirection needed. The new `log_agent_boundary`
tool below replaces what the retired SubagentStop hook used to mark (an
agent dispatch starting/finishing) - the orchestrating command/workflow
calls it explicitly, the same way it already calls
`create_session`/`register_target` explicitly rather than relying on
ambient state.

Run directly for stdio transport:
    python3 server.py
(no `SESSION_DIR` env var needed or read - call `create_session` first,
over MCP, the same as any other client would.)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import httpx2  # noqa: E402  (transitive dep of `mcp` itself, see requirements.txt)
from mcp.server.mcpserver import Context, MCPServer  # noqa: E402
from pydantic import BaseModel  # noqa: E402

import scope_gate  # noqa: E402
from token_store import TokenStore  # noqa: E402

mcp = MCPServer(
    name="clicky-mcp-gateway",
    title="Clicky MCP Gateway",
    version="0.1.0",
    instructions=(
        "Privacy-preserving execution gateway for Clicky pentest engagements. "
        "All arguments and return values use TARGET_n/CRED_*_n tokens instead "
        "of real hosts/credentials - this server resolves tokens to real "
        "values before acting and redacts real values back to tokens before "
        "returning output. Call create_session(target) first to obtain a "
        "session_dir; every other tool requires that session_dir explicitly."
    ),
)


class ConfirmTargetRegistration(BaseModel):
    """Elicitation schema for register_target's NOT_LISTED case."""

    confirm: bool


_SESSION_MANAGER_SCRIPT = (
    _HERE.parent / "session-management" / "scripts" / "session-manager.sh"
)
_VALIDATE_TARGET_SCRIPT = (
    _HERE.parent / "target-validation" / "scripts" / "validate-target.sh"
)


def _default_session_base() -> str:
    """Same base-directory resolution session-manager.sh itself uses:
    the `default_session_directory` userConfig option
    (`CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY`) when set, else
    `~/.claude/sessions`.
    """
    return os.environ.get(
        "CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY",
        str(Path.home() / ".claude" / "sessions"),
    )


def _validate_session_dir(session_dir: str) -> str:
    """Validate an explicitly-provided `session_dir` and return it unchanged.

    `session_dir` is a required, explicit parameter on every tool below that
    operates within a session - there is no environment-variable or
    pointer-file fallback of any kind. A missing or invalid value fails
    loudly here rather than silently resolving through some other
    mechanism - for a credential-handling gateway, silently misdirecting a
    call to the wrong (or a nonexistent) engagement's session directory is
    a real cross-contamination risk, not a style issue.

    "Valid" means: a non-empty path to an existing directory that actually
    looks like a Clicky session (has a `session.json`, written by
    `create_session`/`session-manager.sh create` as one of the first things
    it does) - not just any directory that happens to exist.
    """
    if not session_dir or not str(session_dir).strip():
        raise ValueError(
            "session_dir is required and must be the exact session_dir "
            "value returned by create_session() - it is never read from "
            "this process's environment or inferred from a pointer file."
        )
    path = Path(session_dir)
    if not path.is_dir():
        raise ValueError(
            f"session_dir {session_dir!r} does not exist or is not a "
            "directory. Pass the exact session_dir value create_session() "
            "returned, not a guessed or reconstructed path."
        )
    if not (path / "session.json").is_file():
        raise ValueError(
            f"session_dir {session_dir!r} exists but does not look like a "
            "valid Clicky session directory (missing session.json). Pass "
            "the exact session_dir value create_session() returned."
        )
    return session_dir


def _scope_path(session_dir: str) -> str:
    return str(Path(session_dir) / "scope.json")


_SCOPE_ENFORCEMENT_MODES = ("enforce", "warn", "off")


def _scope_enforcement_mode() -> str:
    """Read CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT, same convention (and
    same default/fallback rules) scope-enforcement-hook.sh used before it
    was retired in favor of this gateway: "enforce" (default) actually
    denies/asks, "warn" logs what it would have done but never blocks,
    "off" disables scope checking entirely. Any unrecognized value is
    treated as "enforce", matching the userConfig description in
    .claude-plugin/plugin.json.
    """
    mode = os.environ.get("CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT", "enforce")
    return mode if mode in _SCOPE_ENFORCEMENT_MODES else "enforce"


def _log_scope_event(session_dir: str, message: str) -> None:
    """Best-effort append to the session's scope-enforcement log.

    Same log path/format scope-enforcement-hook.sh used
    ($SESSION_DIR/logs/scope-enforcement.log, one UTC-timestamped line per
    event) so existing tooling/operators that already know to check that
    file after the hook's retirement keep finding it in the same place.
    The bracketed tag is "[mcp-gateway]" rather than the old
    "[scope-enforcement-hook]" since this gateway is now what's writing
    it. Never raises - a logging failure must never block target
    registration (fail-open, same principle as below).
    """
    try:
        log_dir = Path(session_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "scope-enforcement.log"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} [mcp-gateway] {message}\n")
    except OSError:
        pass


def _trace(
    session_dir: str,
    event: str,
    tool_name: str,
    caller: str = "",
    tool_input: dict | None = None,
    tool_result: str | None = None,
    error: str | None = None,
) -> None:
    """Best-effort append of one JSONL trace record to
    $SESSION_DIR/logs/trace.jsonl.

    Replaces the retired hook-based trace-logger.sh (PostToolUse/
    PostToolUseFailure/SubagentStop in hooks/hooks.json), which depended
    on Claude Code's specific hook event names/payload contract and
    cross-referenced Claude's own session_id against a separately
    maintained "current session" pointer file. Every action here already
    flows through this gateway with an explicit, already-validated
    session_dir, so this keys directly on that instead - no pointer-file
    indirection, no dependency on any host CLI's hook system. See the
    module docstring's "Phase 0 multi-CLI groundwork" note.

    `tool_input`/`tool_result` are expected to already be in token form:
    received arguments are already tokens by this gateway's whole design
    (see module docstring), and callers pass the same already-redacted
    string they're about to return as `tool_result` - this function does
    not itself resolve or redact anything.

    Never raises - a tracing failure must never break the underlying
    tool call, same fail-open principle as `_log_scope_event` above.
    """
    try:
        log_dir = Path(session_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        trace_path = log_dir / "trace.jsonl"
        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "session_dir": session_dir,
            "event": event,
            "tool_name": tool_name,
            "caller": caller or "unknown",
            "tool_input": tool_input or {},
            "tool_result": tool_result,
            "error": error,
        }
        with open(trace_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


@mcp.tool()
def create_session(target: str, caller: str = "") -> dict:
    """Create a new Clicky session for `target` and return its session_dir/session_id.

    The one gateway tool that does NOT take `session_dir` - it creates one.
    This is the actual first gateway call of any new engagement (see
    commands/pentest.md Step 1 / workflows/pentest-parallel.js's init
    stage). Every other tool in this module requires an explicit,
    already-existing `session_dir`; this is where that value originates.
    The caller must capture the returned `session_dir` and thread it
    explicitly through every later gateway call and Task-tool dispatch for
    the rest of the engagement (see SKILL.md's "Session context" section)
    - nothing here, or anywhere else in this module, stores it for later
    implicit reuse.

    Shells out to skills/session-management/scripts/session-manager.sh's
    `create` subcommand rather than reimplementing session-directory-tree
    creation here, so that logic (the canonical
    recon/exploit/privesc/loot/reports/checkpoints/credentials/logs tree,
    session.json's shape) stays defined in exactly one place. That script
    only prints the new session_id to stdout, not the full session_dir
    path, so this function additionally computes session_dir the same way
    commands/pentest.md's Step 1 always has (honoring
    CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY, falling back to
    ~/.claude/sessions) and confirms the directory it implies actually
    exists and looks like a real session before returning it - trusting a
    raw session_id string alone, unconfirmed, is exactly the kind of
    "assume it worked" gap this redesign is trying to close.

    Validates `target` (via skills/target-validation/scripts/
    validate-target.sh - the same check commands/pentest.md's Step 1 ran
    before session creation in the old direct-Bash model) before creating
    anything: an invalid/dangerous target must never get a session
    directory allocated for it, so this check runs first and raises
    without calling session-manager.sh at all if it fails - not deferred
    to a later, already-session-scoped call the way it would have to be if
    validation instead ran through execute_command.

    `caller` (optional) identifies whichever orchestrating command/agent
    made this call, for the session trace - see `_trace()`. Failures
    before a session_dir exists (validation, session-manager.sh errors)
    have nowhere session-scoped to log to, so only the successful case is
    traced here; those earlier failures surface directly as MCP errors
    instead.

    Raises RuntimeError if `target` fails validation, session-manager.sh
    isn't found, the create subcommand fails, produces no session ID, or
    the resulting session_dir doesn't actually exist.
    """
    try:
        validate_proc = subprocess.run(
            ["bash", str(_VALIDATE_TARGET_SCRIPT), target],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"create_session: failed to run validate-target.sh for target "
            f"{target!r}: {exc}"
        ) from exc

    if validate_proc.returncode != 0:
        raise ValueError(
            f"create_session: target failed validation - "
            f"{(validate_proc.stdout + validate_proc.stderr).strip()}"
        )

    if not _SESSION_MANAGER_SCRIPT.is_file():
        raise RuntimeError(
            f"create_session: session-manager.sh not found at "
            f"{_SESSION_MANAGER_SCRIPT}"
        )

    try:
        proc = subprocess.run(
            ["bash", str(_SESSION_MANAGER_SCRIPT), "create", target],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"create_session: failed to run session-manager.sh create for "
            f"target {target!r}: {exc}"
        ) from exc

    if proc.returncode != 0:
        raise RuntimeError(
            "create_session: session-manager.sh create failed "
            f"(exit {proc.returncode}): {proc.stdout}{proc.stderr}"
        )

    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    session_id = lines[-1].strip() if lines else ""
    if not session_id:
        raise RuntimeError(
            "create_session: session-manager.sh create produced no session "
            f"ID on stdout (stdout={proc.stdout!r} stderr={proc.stderr!r})"
        )

    session_dir = str(Path(_default_session_base()) / session_id)

    try:
        _validate_session_dir(session_dir)
    except ValueError as exc:
        raise RuntimeError(
            f"create_session: session-manager.sh create reported session_id "
            f"{session_id!r}, but the resulting session_dir failed "
            f"validation: {exc}"
        ) from exc

    _trace(
        session_dir,
        event="tool_call",
        tool_name="create_session",
        caller=caller,
        tool_input={"target": target},
        tool_result=f"session_id={session_id}",
    )

    return {"session_dir": session_dir, "session_id": session_id}


@mcp.tool()
async def register_target(
    target: str, session_dir: str, ctx: Context, caller: str = ""
) -> str:
    """Classify `target` against `session_dir`'s scope.json and register a
    token for it.

    `session_dir` is required (the exact value `create_session()` returned
    at the start of this engagement) - see `_validate_session_dir()`.
    `caller` (optional) identifies the calling agent, for the session
    trace - see `_trace()`.

    Behavior is controlled by the scope_enforcement userConfig option
    (CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT), replicating the retired
    scope-enforcement-hook.sh's exact mode semantics:
      - "off": scope checking is skipped entirely; target is registered
        unconditionally (no elicitation, no denial).
      - "warn": never blocks - the target is always registered (even if
        OUT_OF_SCOPE), but what would have happened is logged to
        $SESSION_DIR/logs/scope-enforcement.log.
      - "enforce" (default): IN_SCOPE targets are registered immediately.
        OUT_OF_SCOPE targets are refused outright. Targets that aren't
        listed either way trigger an elicitation asking the operator to
        confirm before registering (covers legitimate mid-engagement
        pivots to newly-discovered hosts, same rationale as the old
        hook's "ask" decision for Bash/WebFetch - see
        skills/target-validation/SKILL.md).

    Any *unexpected* internal error while classifying or elicited (as
    opposed to an explicit deny/decline, which is not an error) fails
    open - the target is registered rather than the operator being locked
    out - matching scope-enforcement-hook.sh's explicit fail-open design
    principle: a scope gate that can lock an authorized operator out of a
    fully-authorized engagement due to an internal bug is worse for
    adoption than no gate.

    Returns the minted or already-existing token (e.g. "TARGET_1").
    """
    session_dir = _validate_session_dir(session_dir)
    scope_path = _scope_path(session_dir)
    store = TokenStore(session_dir)

    mode = _scope_enforcement_mode()

    if mode == "off":
        token = store.register(target, "target")
        # store.redact(target) here (after register()) finds the value
        # already known and substitutes its token - safe. Calling it
        # *before* registration, or on a target that was never
        # registered, would instead fall through to redact()'s own
        # auto-discovery and mint a fresh token as a side effect of
        # merely trying to log something - see the OUT_OF_SCOPE/declined
        # branches below, which deliberately never do this.
        _trace(
            session_dir,
            event="tool_call",
            tool_name="register_target",
            caller=caller,
            tool_input={"target": store.redact(target), "mode": mode},
            tool_result=token,
        )
        return token

    try:
        classification = scope_gate.classify(target, scope_path)

        if mode == "warn":
            if classification == scope_gate.OUT_OF_SCOPE:
                _log_scope_event(
                    session_dir,
                    f"WARN mode - would have denied: target '{target}' is "
                    f"explicitly out of scope per {scope_path}",
                )
            elif classification == scope_gate.NOT_LISTED:
                _log_scope_event(
                    session_dir,
                    f"WARN mode - would have asked: target '{target}' is not "
                    f"explicitly listed in scope.json ({scope_path})",
                )
            token = store.register(target, "target")
            # Safe to redact here - see the "off" branch above for why.
            _trace(
                session_dir,
                event="tool_call",
                tool_name="register_target",
                caller=caller,
                tool_input={
                    "target": store.redact(target),
                    "mode": mode,
                    "classification": classification,
                },
                tool_result=token,
            )
            return token

        # mode == "enforce"
        if classification == scope_gate.OUT_OF_SCOPE:
            # Deliberately do NOT call store.redact(target) here: the
            # target was just refused, never registered, so redact()
            # would fall through to its own auto-discovery and mint a
            # fresh token for it as a side effect of merely tracing the
            # refusal - defeating the point of refusing it. Log a
            # placeholder instead; the real value is never registered
            # anywhere by this branch.
            _trace(
                session_dir,
                event="tool_error",
                tool_name="register_target",
                caller=caller,
                tool_input={"target": "<refused, out of scope - not logged>", "mode": mode},
                error=f"out of scope per {scope_path}",
            )
            raise ValueError(
                f"Target is explicitly out of scope per {scope_path}; refusing to register."
            )

        if classification == scope_gate.NOT_LISTED:
            result = await ctx.elicit(
                message=(
                    f"Target '{target}' is not explicitly listed in scope.json "
                    f"({scope_path}). Approve registering it as an in-scope target "
                    "for this session?"
                ),
                schema=ConfirmTargetRegistration,
            )
            if result.action != "accept" or not result.data.confirm:
                # Same reasoning as the OUT_OF_SCOPE branch above: never
                # register/mint a token, never redact() the raw value
                # either, for exactly the same side-effect reason.
                _trace(
                    session_dir,
                    event="tool_error",
                    tool_name="register_target",
                    caller=caller,
                    tool_input={
                        "target": "<refused, elicitation declined - not logged>",
                        "mode": mode,
                    },
                    error=(
                        "unlisted target registration not approved "
                        f"(action={result.action})"
                    ),
                )
                raise ValueError(
                    f"Registration of unlisted target '{target}' was not approved "
                    f"(elicitation action: {result.action})."
                )

        token = store.register(target, "target")
        # Safe to redact here - see the "off" branch above for why.
        _trace(
            session_dir,
            event="tool_call",
            tool_name="register_target",
            caller=caller,
            tool_input={
                "target": store.redact(target),
                "mode": mode,
                "classification": classification,
            },
            tool_result=token,
        )
        return token
    except ValueError:
        # An explicit scope decision (deny, or elicitation declined/
        # cancelled) - a real decision, not an internal error, so it must
        # propagate rather than being swallowed by the fail-open handler
        # below. Already traced at the raise points above.
        raise
    except Exception as exc:
        # Fail open on any *unexpected* internal error (e.g. scope_gate
        # or the elicitation round trip raising something other than the
        # deliberate ValueErrors above) - see docstring.
        _log_scope_event(
            session_dir,
            f"internal error during scope check for target '{target}' "
            f"({exc!r}) - failing open, registering unconditionally",
        )
        token = store.register(target, "target")
        # Safe to redact here - see the "off" branch above for why.
        _trace(
            session_dir,
            event="tool_call",
            tool_name="register_target",
            caller=caller,
            tool_input={"target": store.redact(target), "mode": mode},
            tool_result=token,
            error=f"internal error, failed open: {exc!r}",
        )
        return token


@mcp.tool()
def execute_command(
    command: str, session_dir: str, timeout_s: int = 300, caller: str = ""
) -> str:
    """Resolve tokens in `command` (using `session_dir`'s token map), run
    it, and return redacted output.

    `session_dir` is required (the exact value `create_session()` returned)
    and validated up front - see `_validate_session_dir()`. `caller`
    (optional) identifies the calling agent, for the session trace - see
    `_trace()`. Every call resolves tokens before running and redacts
    output afterward; there is no bootstrap exception anymore.
    `create_session()` is the one gateway tool that doesn't need a
    `session_dir` (it creates one and returns it before any other tool is
    ever called), so by the time `execute_command` is ever invoked -
    including the very first bootstrap call of a brand-new engagement,
    immediately after `create_session()` returns - a real session
    directory with a real (possibly still-empty) `.token-map.json` always
    exists to resolve/redact against.

    `command` is run through the shell (like Clicky's existing Bash tool)
    after every known token has been substituted for its real value.
    stdout and stderr are captured together, then passed through
    token_store.redact() before being returned - so any real target/
    credential value appearing in the command's own output is replaced
    with its token (minting a new one on first sight if needed).
    """
    session_dir = _validate_session_dir(session_dir)
    store = TokenStore(session_dir)
    resolved = store.resolve(command)

    try:
        proc = subprocess.run(
            resolved,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        output = f"[exit {proc.returncode}]\n{proc.stdout}{proc.stderr}"
    except subprocess.TimeoutExpired:
        output = f"[TIMEOUT after {timeout_s}s]"

    redacted = store.redact(output)
    _trace(
        session_dir,
        event="tool_call",
        tool_name="execute_command",
        caller=caller,
        tool_input={"command": command, "timeout_s": timeout_s},
        tool_result=redacted,
    )
    return redacted


@mcp.tool()
def fetch_url(url: str, session_dir: str, caller: str = "") -> str:
    """Resolve tokens in `url`, fetch it, and return redacted output.

    `session_dir` is required (the exact value `create_session()`
    returned) - see `_validate_session_dir()`. `caller` (optional)
    identifies the calling agent, for the session trace - see `_trace()`.

    Uses httpx2 (already a transitive dependency of the `mcp` package
    itself - see requirements.txt) rather than adding a separate HTTP
    client dependency.
    """
    session_dir = _validate_session_dir(session_dir)
    store = TokenStore(session_dir)
    resolved = store.resolve(url)

    try:
        resp = httpx2.get(resolved, follow_redirects=True, timeout=30.0)
        headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        output = f"[HTTP {resp.status_code}]\n{headers}\n\n{resp.text}"
    except httpx2.HTTPError as e:
        output = f"[ERROR] {e}"

    redacted = store.redact(output)
    _trace(
        session_dir,
        event="tool_call",
        tool_name="fetch_url",
        caller=caller,
        tool_input={"url": url},
        tool_result=redacted,
    )
    return redacted


@mcp.tool()
def read_file(path: str, session_dir: str, caller: str = "") -> str:
    """Resolve tokens in `path`, read the file, and return redacted content.

    `session_dir` is required (the exact value `create_session()`
    returned) - see `_validate_session_dir()`. `caller` (optional)
    identifies the calling agent, for the session trace - see `_trace()`.
    """
    session_dir = _validate_session_dir(session_dir)
    store = TokenStore(session_dir)
    resolved_path = store.resolve(path)

    try:
        content = Path(resolved_path).read_text(errors="replace")
    except OSError as e:
        redacted = store.redact(f"[ERROR] {e}")
        _trace(
            session_dir,
            event="tool_error",
            tool_name="read_file",
            caller=caller,
            tool_input={"path": path},
            error=redacted,
        )
        return redacted

    redacted = store.redact(content)
    _trace(
        session_dir,
        event="tool_call",
        tool_name="read_file",
        caller=caller,
        tool_input={"path": path},
        tool_result=redacted,
    )
    return redacted


@mcp.tool()
def write_file(path: str, content: str, session_dir: str, caller: str = "") -> str:
    """Resolve tokens in both `path` and `content`, write the file, confirm.

    `session_dir` is required (the exact value `create_session()`
    returned) - see `_validate_session_dir()`. `caller` (optional)
    identifies the calling agent, for the session trace - see `_trace()`.

    Both `path`/`content` arguments are resolved token -> real value before
    writing, so an agent can compose file paths and content entirely out
    of tokens. Only `path` (not the full `content`) is recorded in the
    trace's `tool_input` - written content can be large and is already
    fully recoverable from the file itself.
    """
    session_dir = _validate_session_dir(session_dir)
    store = TokenStore(session_dir)
    resolved_path = store.resolve(path)
    resolved_content = store.resolve(content)

    try:
        p = Path(resolved_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(resolved_content)
    except OSError as e:
        redacted = store.redact(f"[ERROR] write to {resolved_path} failed: {e}")
        _trace(
            session_dir,
            event="tool_error",
            tool_name="write_file",
            caller=caller,
            tool_input={"path": path},
            error=redacted,
        )
        return redacted

    redacted = store.redact(f"OK: wrote {len(resolved_content)} bytes to {resolved_path}")
    _trace(
        session_dir,
        event="tool_call",
        tool_name="write_file",
        caller=caller,
        tool_input={"path": path},
        tool_result=redacted,
    )
    return redacted


@mcp.tool()
def search_files(pattern: str, path: str, session_dir: str, caller: str = "") -> str:
    """Resolve tokens, grep for `pattern` under `path`, return redacted matches.

    `session_dir` is required (the exact value `create_session()`
    returned) - see `_validate_session_dir()`. `caller` (optional)
    identifies the calling agent, for the session trace - see `_trace()`.
    """
    session_dir = _validate_session_dir(session_dir)
    store = TokenStore(session_dir)
    resolved_pattern = store.resolve(pattern)
    resolved_path = store.resolve(path)

    try:
        proc = subprocess.run(
            ["grep", "-rn", "--", resolved_pattern, resolved_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = proc.stdout + proc.stderr
        if not output.strip():
            output = "[no matches]"
    except FileNotFoundError:
        output = "[ERROR] grep is not available on this system"
    except subprocess.TimeoutExpired:
        output = "[TIMEOUT]"

    redacted = store.redact(output)
    _trace(
        session_dir,
        event="tool_call",
        tool_name="search_files",
        caller=caller,
        tool_input={"pattern": pattern, "path": path},
        tool_result=redacted,
    )
    return redacted


_AGENT_BOUNDARY_PHASES = ("start", "end")


@mcp.tool()
def log_agent_boundary(
    agent_name: str, phase: str, session_dir: str, summary: str = ""
) -> str:
    """Mark an agent dispatch starting or finishing, for the session trace.

    `phase` must be "start" or "end". Replaces what the retired
    SubagentStop hook used to mark (see module docstring's "Phase 0
    multi-CLI groundwork" note) - the orchestrating command/workflow
    (commands/pentest.md, or its per-CLI equivalent) calls this
    explicitly immediately before and after each agent dispatch, the same
    way it already calls create_session/register_target explicitly rather
    than relying on any host CLI's hook system.

    `summary` is optional free text on the "end" call only (e.g. a short
    account of what the dispatched agent accomplished) - approximates
    what the old hook payload's `last_assistant_message`/`stop_reason`
    fields captured, now supplied explicitly by the caller instead of
    reconstructed from a hook payload. It's resolved/redacted through the
    session's token store like any other content-bearing argument, even
    though it's expected to already be in token form.

    `session_dir` is required (the exact value `create_session()`
    returned) - see `_validate_session_dir()`.
    """
    session_dir = _validate_session_dir(session_dir)
    if phase not in _AGENT_BOUNDARY_PHASES:
        raise ValueError(
            f"log_agent_boundary: phase must be one of {_AGENT_BOUNDARY_PHASES}, "
            f"got {phase!r}"
        )

    store = TokenStore(session_dir)
    redacted_summary = store.redact(store.resolve(summary)) if summary else ""

    _trace(
        session_dir,
        event=f"agent_{phase}",
        tool_name="log_agent_boundary",
        caller=agent_name,
        tool_input={"agent_name": agent_name, "phase": phase},
        tool_result=redacted_summary or None,
    )

    return f"OK: logged {phase} boundary for agent {agent_name!r}"


if __name__ == "__main__":
    mcp.run()
