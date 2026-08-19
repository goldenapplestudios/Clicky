---
name: mcp-gateway
description: Privacy-preserving MCP execution gateway that resolves TARGET_n/CRED_*_n tokens to real values before acting and redacts real values back to tokens in tool output, so raw targets/credentials never need to flow through the model as plain tool-call content
allowed-tools: Bash, Read
---

# MCP Gateway Skill

## Status: registered, running, and adopted by all 10 agents

This server is fully wired in: `.claude-plugin/plugin.json`'s `mcpServers`
block registers it as `clicky-gateway`, launched via `scripts/launch.sh`
(see below), and `hooks/hooks.json` has a `SessionStart` entry that also
runs `scripts/provision-venv.sh` at the start of every session. Claude Code
therefore actually launches this server and its `initialize`/`tools/list`
handshake succeeds. All 10 `agents/*.md` files (`recon`, `decision`,
`exploit`, `privesc`, `loot`, `cloud-recon`, `source-analyzer`,
`verification`, `report`, `severity-analyst`) have had their `tools:`
frontmatter rewritten to grant exclusively a subset of
`mcp__plugin_clicky_clicky-gateway__*` tools in place of direct
Bash/Read/Write/WebFetch - zero direct tool grants remain anywhere in the
plugin. (The original scope-enforcement `PreToolUse` hook,
`skills/target-validation/scripts/scope-enforcement-hook.sh`, has also been
retired, in favor of `register_target`'s own scope check below - see
`skills/target-validation/SKILL.md`'s "Automatic Scope Enforcement" section
for what that means now that every agent is wired onto this gateway.)

### `launch.sh`: why the server isn't launched via the venv python directly

`mcpServers.clicky-gateway.command` points at `scripts/launch.sh`, not
`${CLAUDE_PLUGIN_DATA}/venv/bin/python` directly, because `SessionStart`
hooks and `mcpServers` process launch are **not ordered relative to each
other** in Claude Code - confirmed empirically, not just suspected, in a
real Claude Code 2.1.233 session (`--plugin-dir` load of this repo,
2026-08-15): the MCP server connection attempt for `clicky-gateway` fired
and failed with `ENOENT` (`posix_spawn` on
`${CLAUDE_PLUGIN_DATA}/venv/bin/python`, which didn't exist yet) about 12
seconds *before* the `SessionStart` hook's own `provision-venv.sh` call
finished creating that same venv, and Claude Code did not retry the
connection afterwards - the server stayed broken for the rest of that
session. `launch.sh` closes that gap by calling `provision-venv.sh`
synchronously (idempotent and now lock-protected against exactly this
kind of concurrent invocation - see that script's header) before exec-ing
the real interpreter, so the server's own launch no longer depends on the
`SessionStart` hook having won any race. The `SessionStart` hook stays
registered too, since it still usefully warms the venv in the common case
where it does finish first.

## Purpose

Previously, Clicky's agents called Bash/WebFetch/Read directly, so raw
target IPs, hostnames, and discovered credentials flowed to the model as
plain tool-call/tool-result content for the whole engagement. This skill is
the gateway architecture that fixed that: all 10 agents have lost their
direct Bash/Read/Write/WebFetch grants and instead call a subset of the MCP
tools `server.py` exposes here. Each tool resolves placeholder tokens
(`TARGET_1`, `CRED_HASH_1`, etc.) to real values before acting, and redacts
real values back to tokens in whatever it returns - so the model only ever
sees tokens in either direction, while the actual command execution, file
I/O, and network calls underneath use real data.

## The 7 tools

All 7 are registered on an `mcp.server.mcpserver.MCPServer` instance in
`server.py` via `@mcp.tool()`. Six of them take an explicit, required
`session_dir: str` parameter; `create_session` is the exception, since its
whole job is to produce that value in the first place (see "Session
context" below).

1. **`create_session(target: str) -> dict`** - validates `target` (via
   `skills/target-validation/scripts/validate-target.sh` - an invalid or
   dangerous target never gets a session allocated for it) and, if valid,
   creates a new Clicky session for it (shells out to
   `skills/session-management/scripts/session-manager.sh`'s `create`
   subcommand) and returns `{"session_dir": "...", "session_id": "..."}`.
   Takes no `session_dir` - it creates one. This is the actual first
   gateway call of any new engagement.
2. **`register_target(target: str, session_dir: str) -> str`** - classifies
   `target` against `session_dir`'s `scope.json` via `scope_gate.classify()`.
   `IN_SCOPE` registers and returns a token immediately; `OUT_OF_SCOPE`
   raises an error; `NOT_LISTED` asks the operator to confirm via the MCP
   SDK's elicitation mechanism (`Context.elicit()`) before registering -
   see "Scope-check integration" below.
3. **`execute_command(command: str, session_dir: str, timeout_s: int = 300) -> str`** -
   resolves tokens in `command` (using `session_dir`'s token map), runs it
   through the shell, captures stdout+stderr, redacts the result.
4. **`fetch_url(url: str, session_dir: str) -> str`** - resolves tokens in
   `url`, fetches it (via `httpx2`, already a transitive dependency of the
   `mcp` package itself), redacts the result.
5. **`read_file(path: str, session_dir: str) -> str`** - resolves tokens in
   `path`, reads the file, redacts the content before returning.
6. **`write_file(path: str, content: str, session_dir: str) -> str`** -
   resolves tokens in both `path` and `content` (token -> real value)
   before writing, then confirms the write.
7. **`search_files(pattern: str, path: str, session_dir: str) -> str`** -
   resolves tokens, runs `grep -rn` under `path`, redacts the matches.

Every `session_dir` argument above is validated on entry (non-empty, an
existing directory, and one that actually contains a `session.json` -
see `_validate_session_dir()` in `server.py`) - an invalid or missing value
fails loudly with a clear error rather than silently resolving through
some other mechanism.

## The token scheme

`token_store.py`'s `TokenStore` is the two-way real-value <-> token index
for one session, backed by `$SESSION_DIR/.token-map.json` (mode 0600,
created fresh whenever a session directory doesn't already have one).
Writes are atomic (tempfile + `os.replace`) and serialized with an
advisory `flock` on a sidecar `.token-map.json.lock`, so overlapping tool
calls within or across agent turns can't corrupt the map.

Token naming is deterministic and sequential per kind:

| Kind | Token prefix | Minted by |
|---|---|---|
| `target` | `TARGET_1`, `TARGET_2`, ... | `register_target`, and auto-discovery in `redact()` |
| `cred_key` | `CRED_KEY_1`, ... | auto-discovery only (PEM private key blocks) |
| `cred_apikey` | `CRED_APIKEY_1`, ... | auto-discovery only (`api_key=...`-shaped secrets) |
| `cred_hash` | `CRED_HASH_1`, ... | auto-discovery only (password/NTLM/bcrypt/etc. hashes) |
| `cred_user` | `CRED_USER_1`, ... | explicit `register()` calls only (not yet wired to anything in Phase 1) |
| `cred_pass` | `CRED_PASS_1`, ... | explicit `register()` calls only (not yet wired to anything in Phase 1) |

The `CRED_*` family is split by shape rather than one generic `CRED_n`,
since the patterns used for auto-discovery already distinguish these
shapes and a differentiated token (`CRED_HASH_2` vs `CRED_APIKEY_1`) reads
more usefully in a transcript than an opaque `CRED_3`. `cred_user`/
`cred_pass` exist as registerable kinds for a future caller that already
knows a value is specifically a username or password (e.g. a later
credential-harvesting integration), but `redact()`'s auto-discovery never
mints those two on its own - a bare "word: word" shape in free-text tool
output is too ambiguous to safely auto-tag as a credential pair without
real false-positive cost, so that judgment call is deliberately left to an
explicit caller rather than a regex.

Core operations:

- **`register(real_value, kind) -> token`** - returns the existing token
  if `real_value` is already known (lookup is by value alone, not
  value+kind - a given real value maps to exactly one token for the life
  of the session), else mints and persists a new sequential token.
- **`resolve(text) -> text`** - replaces every known token in `text` with
  its real value (inbound: agent -> server). A no-op if `text` contains no
  known tokens.
- **`redact(text) -> text`** - replaces every known real value in `text`
  with its token (outbound: server -> agent), *and* auto-registers+
  tokenizes any newly-discovered target- or credential-shaped value it
  finds. A no-op if `text` contains no known real values and nothing
  newly-discoverable.

### Auto-discovery reuses this repo's existing pattern-matching, not new regexes

`redact()`'s discovery step is deliberately built on top of patterns this
repo already has and tests elsewhere, not reinvented from scratch:

- **Target shapes** (IPv4/CIDR, coarse IPv6, dotted hostnames, bare
  letter+digit hostnames like `dc01`) come directly from
  `skills/target-validation/scripts/extract-targets.py`'s own
  `extract_from_text()` function, loaded dynamically at runtime (that
  script's filename has a hyphen, so it can't be imported with a plain
  `import` statement). Its known blind spots and false-positive trade-offs
  (documented in that script's own module docstring) apply here unchanged.
- **Credential shapes** are adapted from two existing scripts' regexes,
  both read in full before writing `token_store.py`:
  - the private-key-block and `api_key=...` patterns in
    `skills/report-generation/scripts/report-generator.sh`'s `sanitize()`
    function;
  - the hash-length/format patterns in
    `skills/credential-harvesting/scripts/hash-identifier.py`'s `PATTERNS`
    list (bcrypt, glibc `$1$`/`$5$`/`$6$` crypt, bare 32/40/64/128-char hex
    runs).

  Both are known best-effort, over-matching trade-offs (e.g. a git commit
  hash or another unrelated 40-hex-char string will also get tokenized as
  `CRED_HASH_n`) - same accepted trade-off `extract-targets.py` documents
  about itself: one spurious token costs nothing but a slightly odd name,
  it doesn't silently leak anything, and false negatives (a credential
  shape not on this list) are the real risk, not false positives.

## Scope-check integration

`scope_gate.py`'s `classify(target, scope_path)` does not reimplement
scope matching - it shells out to the existing
`skills/target-validation/scripts/scope-validator.sh`, so the matching
rules (CIDR / IP-range / wildcard-domain / exact-match against
`scope.json`) live in exactly one place. It returns one of `IN_SCOPE`,
`OUT_OF_SCOPE`, or `NOT_LISTED`.

`register_target` is the only one of the 7 tools that runs a scope check
today. It is the natural chokepoint: every other tool operates on tokens
that were already resolved through `register_target` at some earlier
point, so gating registration is equivalent to gating what real values
ever enter the token map in the first place. `execute_command`/
`fetch_url`/etc. do not re-run scope classification themselves.

`register_target` also implements the `enforce`/`warn`/
`off` mode switching that `scope-enforcement-hook.sh` (now retired) used
to implement, read from the same `CLAUDE_PLUGIN_OPTION_SCOPE_ENFORCEMENT`
env var (`scope_enforcement` userConfig option, default `enforce`):

- `enforce` (default): `OUT_OF_SCOPE` is refused outright; `NOT_LISTED`
  triggers an elicitation; `IN_SCOPE` registers immediately.
- `warn`: never blocks - the target is always registered regardless of
  classification, but what would have happened is logged to
  `$SESSION_DIR/logs/scope-enforcement.log` (same path the old hook used,
  tagged `[mcp-gateway]` instead of `[scope-enforcement-hook]`).
- `off`: skips the scope check (and `classify()` call) entirely - the
  target is registered unconditionally, no elicitation, nothing logged.

Deliberate two-layer difference from the old hook, preserved on purpose:
`scope_gate.classify()` itself still treats any failure to get a clean
classification (missing scope file, missing `python3`/`bash`, a crash) as
`NOT_LISTED` rather than a silent allow - in `enforce` mode that still
means the operator is *asked*, not locked out, so this isn't in tension
with fail-open. The actual fail-open guarantee (an *unexpected* exception
anywhere in `register_target`'s mode-handling or elicitation logic results
in the target being registered rather than the operator being blocked)
lives one level up, in `register_target` itself, matching
`scope-enforcement-hook.sh`'s documented fail-open design principle: a
scope gate that can lock an authorized operator out of a fully-authorized
engagement due to an internal bug is worse for adoption than no gate.

For the `NOT_LISTED` case in `enforce` mode, `register_target` uses the MCP
SDK's real elicitation API - `Context.elicit(message, schema)`, where
`schema` is a small Pydantic model (`ConfirmTargetRegistration(confirm:
bool)`) - to ask the operator to confirm before registering. See "SDK API
note" below: this is `mcp==2.0.0`'s actual current elicitation shape,
verified against the installed package's source rather than assumed from
the SDK's own documentation examples.

`tests/mcp_gateway/test_scope_enforcement_modes.py` drives all three modes
against a real subprocess server over real MCP stdio, including confirming
`warn`'s log line and that `off`/`warn` never trigger elicitation.

## Session context

`session_dir` is an explicit, required parameter on every tool that
operates *within* an existing session (`register_target`,
`execute_command`, `fetch_url`, `read_file`, `write_file`,
`search_files`) - it is never read from this process's own environment
and never inferred from a pointer file. `create_session(target)` is the
only tool that doesn't take `session_dir`, because its job is to create
one; it returns `{"session_dir": "...", "session_id": "..."}`, and that
return value is the sole source of truth for `session_dir` for the rest of
the engagement. The caller captures it once and threads it through every
later gateway call and Task-tool dispatch explicitly - the same pattern
Clicky's agents already use for `$SESSION_ID` (see
`agents/exploit-agent.md`: "Substitute the literal session ID you were
handed as part of your dispatch context").

`_validate_session_dir()` in `server.py` checks every incoming
`session_dir` on every call: non-empty, an existing directory, and one
that actually contains a `session.json` (the marker `create_session`/
`session-manager.sh create` writes as one of its first acts). A missing or
invalid `session_dir` raises immediately with a clear error - there is no
path by which a tool call succeeds by silently resolving `session_dir`
some other way.

Calling any of the six session-scoped tools without first calling
`create_session` is simply an error (a required argument is missing or
doesn't resolve to a real session) - not a special "no active session yet"
mode that runs unredacted. See "Fixing the cold-start bug without a
permanent pointer file" below for why this is deliberately simpler than an
earlier design.

## Fixing the cold-start bug without a permanent pointer file

**The underlying bug, confirmed via a real cold-start test:** the gateway
server is a long-lived process, launched once by Claude Code via
`mcpServers`/`scripts/launch.sh`. A design that resolved `session_dir` from
`$SESSION_DIR` in this process's own environment would be broken by
construction for the very first call of a brand-new engagement: that env
var, if set at all, is fixed at process-launch time, before any Clicky
engagement exists, and can never change for the rest of the process's
life. Confirmed empirically: an earlier version of `commands/pentest.md`
Step 1 that assumed ambient `SESSION_DIR` availability failed immediately
with `SESSION_DIR is not set` on a genuine cold start (`claude --plugin-dir
<repo> -p "/clicky:pentest 10.10.10.10"`, no pre-existing session
directory, no `SESSION_DIR` env var set anywhere beforehand).

**The rejected intermediate fix:** a prior revision of this file kept
`$SESSION_DIR` env-var resolution as the primary path and added a
permanent fallback - a `${CLAUDE_PLUGIN_DATA}/.current-session` pointer
file, written once by `commands/pentest.md` Step 1 right after session
creation, silently read by every tool call thereafter for the rest of the
gateway process's life. That fixed the cold start but did so by making
ambient, silently-inferred session state the permanent mechanism, not just
a one-time bootstrap - reviewed against real precedent (LSP's
`initialize`/`rootUri` pattern, MCP's own protocol design philosophy, and
general RPC/context-propagation practice, e.g. Go's mandatory
explicit-`Context`-parameter convention) and rejected: a stale or wrong
pointer silently misdirecting a tool call to the wrong engagement's session
directory is a real target/credential cross-contamination risk for this
specific gateway, not a style issue. It was also two-faced in practice:
`${CLAUDE_PLUGIN_DATA}` is a single stable directory shared across *all* of
a user's Claude Code sessions running this plugin, so two genuinely
concurrent `/pentest` engagements would race on the same pointer file, with
the second write silently winning for any later call anywhere else that
fell back to it.

**The actual fix: make `session_dir` an explicit parameter everywhere, and
add one tool that doesn't need it.** `create_session(target) -> dict` is
the one gateway tool with no `session_dir` argument - it creates the
session and returns `{"session_dir": ..., "session_id": ...}` directly to
its caller (see `commands/pentest.md` Step 1 / `workflows/
pentest-parallel.js`'s init stage). Every other tool requires `session_dir`
explicitly, validated on every call (see "Session context" above). There
is no pointer file anywhere in this module, and no code path where a tool
call succeeds by silently reading one - `create_session()`'s own return
value, threaded through explicitly by the caller from that point on, is
the entire mechanism. This also closes a second gap the pointer-file design
had: because `execute_command` used to tolerate running with *no* session
resolvable at all (to let the very first bootstrap command run before any
session existed), that one call ran with zero token resolution/redaction -
a real target value could reach that call's output unredacted. With
`create_session` returning `session_dir` before any `execute_command` call
ever needs to happen, that tolerance - and the gap it created - no longer
exists: every `execute_command` call, including the first one of a brand
new engagement, resolves and redacts normally.

## Environment setup

`requirements.txt` pins `mcp==2.0.0` (see that file's header comment for
why 2.0.0 rather than the `mcp>=1.29,<2` fallback - short version: it
installed and imported cleanly in this environment with no conflicts, so
there was no reason to fall back). `scripts/provision-venv.sh` creates (or
reuses) a venv at `${CLAUDE_PLUGIN_DATA:-/tmp/clicky-mcp-gateway-data}/venv`
and reinstalls `requirements.txt` only when its contents have changed
since the last successful install (tracked via a cached copy at
`.requirements.lock` next to the venv, plus a `provision.log` recording
what each run actually did, and a `.provision.lock/` directory-based lock
serializing concurrent runs). It is registered as a `SessionStart` hook in
`hooks/hooks.json` *and* called synchronously by `scripts/launch.sh` before
that script execs the server - see "`launch.sh`: why the server isn't
launched via the venv python directly" above for why both callers exist.

## SDK API note (read before assuming the plan sketch's imports are exact)

The originating plan for this phase sketched `from mcp.server import
MCPServer` plus `Context`, `Resolve`, `Elicit`, `ElicitationResult` as the
likely elicitation surface. Verified against the actual installed
`mcp==2.0.0` package:

- `from mcp.server import MCPServer` works (re-exported at that level).
- `Context` is **not** re-exported at `mcp.server` - it lives at
  `mcp.server.mcpserver.Context`. `server.py` imports both from there:
  `from mcp.server.mcpserver import Context, MCPServer`.
- The real elicitation call is simpler than the plan's sketch suggested:
  `await ctx.elicit(message: str, schema: type[BaseModel]) ->
  ElicitationResult[SchemaModel]`, where `ElicitationResult` is a type
  alias for `AcceptedElicitation[T] | DeclinedElicitation | CancelledElicitation`.
  Check `result.action` (`"accept"` / `"decline"` / `"cancel"`) and, only
  when it's `"accept"`, read `result.data`. `Resolve`/`Elicit`/
  `ListRoots`/`Sample` (also exported from `mcp.server.mcpserver`) are a
  separate, lower-level multi-round-trip mechanism used for resource
  templates that need to ask a client-side question mid-read; they are
  not needed for `register_target`'s simple confirm-or-refuse case and
  `server.py` does not use them.

## Testing

`tests/mcp_gateway/` exercises the real modules and the real server
process (not just import-and-hope): `token_store.py`'s register/resolve/
redact round-trip and auto-discovery, `scope_gate.py`'s classification
against a fixture `scope.json`, `server.py` started as a real subprocess
and sent a real `initialize` + `tools/list` MCP request over stdio (all 7
tools including a real `create_session` call, explicit `session_dir`
threading through every other tool, and a real elicitation round trip),
the `enforce`/`warn`/`off`
mode switching described above (`test_scope_enforcement_modes.py`, also a
real subprocess/real-MCP-stdio check), and
`scripts/provision-venv.sh`'s create-then-skip-reinstall behavior. See
`tests/mcp_gateway/` for the individual test scripts, and the Phase 1/
Phase 2 verification write-ups (this build's own PR/commit descriptions)
for actual recorded pass/fail output.
