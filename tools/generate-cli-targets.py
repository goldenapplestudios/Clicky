#!/usr/bin/env python3
"""Generate per-CLI portability artifacts from Clicky's Claude-Code-native
source of truth (`agents/*.md`, `commands/*.md`).

Why this exists: Clicky is built as a Claude Code plugin, but its actual
attack logic (agent prompts, skill content, the MCP gateway) is
substrate-neutral - the MCP privacy gateway is a standard MCP server, and
OpenCode/Codex CLI/Copilot CLI all have their own native agent/MCP/skill
systems. Rather than maintain N parallel copies of 10 agents by hand, this
script reads Claude Code's `agents/*.md`/`commands/*.md` as the single
source of truth and generates thin, per-CLI artifacts - the same pattern
`NeoTheCapt/RedteamAgent` uses for its own Claude Code/OpenCode/Codex
support (source of truth + generated per-CLI artifacts, not a shared
runtime abstraction layer).

Generated output is checked into the repo (run this script and commit the
result whenever `agents/*.md`/`commands/*.md` change) - end users of a
generated target shouldn't need Python or this script, only maintainers
regenerating after an agent/command edit. `tests/run_all.sh` includes a
drift check (regenerate to a temp dir, diff against the checked-in
output) so a forgotten regeneration fails loudly instead of silently
drifting.

Currently supports: OpenCode (`opencode` subcommand), Codex CLI (`codex`
subcommand). Copilot CLI is a planned follow-up (see the multi-CLI
portability plan) - each target needed its own live-verification pass
against the real binary before a generator was built for it, same
discipline both sections below were held to (see each section's
extensive doc comments for what was actually confirmed, and how, before
any of it was written) - Codex's in particular reversed an initial
"blocked" conclusion after deeper live testing found the failure was
model-specific, not categorical (see that section's doc comment).

Usage:
    python3 tools/generate-cli-targets.py opencode
    python3 tools/generate-cli-targets.py opencode --check   # drift check only, no writes
    python3 tools/generate-cli-targets.py codex
    python3 tools/generate-cli-targets.py codex --check
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / "agents"
COMMANDS_DIR = REPO_ROOT / "commands"

# ---------------------------------------------------------------------
# Advanced per-agent framework/model assignment (tools/clicky-setup.sh
# --advanced, see tools/advanced_agent_assignment.py). Operator-written,
# not checked into the repo - `{"<agent-name>": "<model>"}`, e.g.
# `{"severity-analyst-agent": "gpt-5.4"}`. Scoped to Codex and OpenCode
# only: both have a confirmed, real per-agent model mechanism (Codex's
# `model = "..."` TOML field, already in use for the CODEX_MODEL pin
# below; OpenCode's documented-but-previously-unpopulated `model:
# <provider>/<model-id>` frontmatter field). Copilot CLI's agent
# frontmatter schema has no confirmed model field - deliberately not
# guessed at here; see advanced_agent_assignment.py's own doc comment.
_AGENT_MODEL_OVERRIDES_PATH = Path(
    os.environ.get("CLICKY_AGENT_MODELS_PATH", Path.home() / ".clicky" / "agent-models.json")
)
_agent_model_overrides_raw_cache: dict | None = None


def _agent_model_overrides_raw() -> dict:
    """Raw {"<agent-name>": {"framework": "...", "model": "..."}} as
    tools/advanced_agent_assignment.py writes it - each entry tagged
    with which framework it's for, since the same file is the source
    for all three per-agent-model-capable targets and an assignment
    made for one framework must never bleed into another."""
    global _agent_model_overrides_raw_cache
    if _agent_model_overrides_raw_cache is None:
        _agent_model_overrides_raw_cache = {}
        if _AGENT_MODEL_OVERRIDES_PATH.exists():
            try:
                with open(_AGENT_MODEL_OVERRIDES_PATH) as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    _agent_model_overrides_raw_cache = data
            except (OSError, json.JSONDecodeError):
                pass
    return _agent_model_overrides_raw_cache


def _agent_model_overrides(framework: str) -> dict[str, str]:
    """{"<agent-name>": "<model>"} filtered to entries assigned to
    `framework` specifically (e.g. "codex" or "opencode") - an
    assignment made for a different framework is correctly invisible
    here, not silently applied to the wrong target."""
    out = {}
    for name, assignment in _agent_model_overrides_raw().items():
        if isinstance(assignment, dict) and assignment.get("framework") == framework and assignment.get("model"):
            out[str(name)] = str(assignment["model"])
    return out


# ---------------------------------------------------------------------
# Minimal frontmatter parsing - agents/*.md and commands/*.md frontmatter
# is deliberately simple (flat key: value pairs, some comma-separated
# lists on one line), so a hand-rolled parser avoids adding a PyYAML
# dependency to a repo-maintenance script nobody but a maintainer runs.
# Not a general YAML parser - would need real work to handle nested
# structures, multi-line values, or quoted strings with colons in them,
# none of which any file in agents/ or commands/ currently uses.
# ---------------------------------------------------------------------


def parse_frontmatter(path: Path) -> tuple[dict[str, str], str]:
    """Split `path` into (frontmatter dict, body). Frontmatter values are
    left as raw strings - callers split comma-separated fields themselves
    (see `split_list()`)."""
    text = path.read_text()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        raise ValueError(f"{path}: no frontmatter block found")
    fm_text, body = m.group(1), m.group(2)
    fm: dict[str, str] = {}
    for line in fm_text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        key, _, value = line.partition(":")
        fm[key.strip()] = value.strip()
    return fm, body


def split_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


# ---------------------------------------------------------------------
# OpenCode target
#
# Every fact this section relies on was confirmed empirically against a
# real installed `opencode` binary (v1.1.59, Homebrew), not inferred from
# docs or the earlier GitHub-source research pass alone - see the
# multi-CLI portability plan's Phase 1 section for the full record. In
# summary, confirmed live:
#
#   - Agent files: `.opencode/agents/<name>.md` (also `.opencode/agent/`
#     works via a brace-glob, but docs only document the plural form).
#   - `opencode debug agent <name>` shows an agent's fully RESOLVED
#     permission/tool set. An agent whose frontmatter `permission:` map
#     lists ONLY a single MCP tool as `allow`, and nothing else, still
#     resolves EVERY OpenCode built-in tool as available (`bash: true,
#     read: true, glob: true, grep: true, edit: true, write: true,
#     task: true, webfetch: true, todowrite: true, websearch: true,
#     codesearch: true` in the resolved `tools` map) - OpenCode bakes a
#     `"*": "allow"` default into every agent's ruleset BEFORE merging in
#     the agent's own overrides. Adding explicit `deny` entries for each
#     of those built-ins was then confirmed to flip every one of them to
#     `false` in the resolved tools map - so BUILTIN_DENY_LIST below is
#     not a guess, it's the confirmed-necessary and confirmed-sufficient
#     fix. `skill` is deliberately left off this deny list (stays
#     allowed) since agents need it to load Clicky's own skill content.
#   - MCP tool naming: registering the real `clicky-gateway` MCP server
#     and asking a live model (a free `opencode/*` model, real
#     `opencode run` dispatch, not simulated) to list its available
#     tools returned exactly `clicky-gateway_<tool_name>` for all 8 real
#     gateway tools (e.g. `clicky-gateway_execute_command`) - confirming
#     the naming convention is `<mcp-config-key>_<tool_name>`, a single
#     underscore, no other prefix.
#   - `environment` (not `env`) is the MCP local-server config key that
#     actually reaches the spawned process - confirmed by registering
#     the real `skills/mcp-gateway/scripts/launch.sh` this way and
#     having a live dispatched agent successfully run a command
#     containing a literal, unmodified `${CLAUDE_PLUGIN_ROOT}/skills/...`
#     path exactly as it appears in agents/*.md prose (specifically
#     `${CLAUDE_PLUGIN_ROOT}/skills/tool-management/scripts/
#     tool-fallback.sh nmap`) - it resolved and ran correctly, confirming
#     the entire "env injection needs zero changes to the 211 existing
#     ${CLAUDE_PLUGIN_ROOT} references" design decision, not just in
#     theory.
#   - `skills.paths` (an array of directories) in `opencode.json` was
#     confirmed via `opencode debug skill` to discover all 26 of
#     Clicky's real skills directly from `skills/`, full content
#     included, with zero symlinks or copies.
#   - Full adversarial test: an agent with the confirmed deny list plus
#     only gateway tools allowed, asked to run `whoami` "using any tool
#     you have," had no `bash` tool available at all and instead used
#     `clicky-gateway_create_session` -> `clicky-gateway_execute_command`
#     - which correctly enforced Clicky's own dangerous-target
#     validation (refused `127.0.0.1`, "Cannot scan localhost") before
#     succeeding against a real target. This is the actual security
#     property this whole design exists to preserve, confirmed against a
#     real model actually trying to use it, not just a static config
#     check.
#
# Two things confirmed live but NOT yet replicated by this generator,
# flagged here rather than silently glossed over:
#   - Per-agent skill restriction: Claude Code's `skills:` frontmatter
#     scopes which skills an agent has access to. OpenCode's `skill`
#     tool, once allowed, exposes every skill registered via
#     `skills.paths` globally - there's no per-agent skill allowlist
#     mechanism confirmed to exist. Each generated agent's body notes
#     which skills it was scoped to in Claude Code, but that's
#     documentation only on this target, not an enforced restriction.
#   - decision-agent's `memory: user` (Claude Code's persistent
#     cross-session agent memory) has no confirmed OpenCode equivalent -
#     noted in the generated file as a known gap, not replicated.
# ---------------------------------------------------------------------

# Confirmed via `opencode debug agent <name>` against opencode 1.1.59 -
# see the doc comment above. Deliberately excludes "skill" (left allowed)
# and OpenCode's other meta-permissions (question/doom_loop/
# external_directory/plan_enter/plan_exit), which aren't filesystem/shell/
# subagent-dispatch escape hatches the way these are.
BUILTIN_DENY_LIST = [
    "bash",
    "read",
    "glob",
    "grep",
    "edit",
    "write",
    "task",
    "webfetch",
    "todowrite",
    "websearch",
    "codesearch",
]

# tools: frontmatter values look like
# "mcp__plugin_clicky_clicky-gateway__execute_command" - this is Claude
# Code's own MCP tool-namespacing convention (see docs/architecture.md's
# "Audit Trail" section / skills/mcp-gateway/server.py's module
# docstring): mcp__plugin_<plugin.json "name">_<mcpServers key>__<tool>.
# OpenCode's confirmed convention is <mcp-config-key>_<tool_name> - a
# single underscore, no "mcp__plugin_" prefix, no plugin name segment.
_CLAUDE_MCP_TOOL_RE = re.compile(
    r"^mcp__plugin_clicky_clicky-gateway__(?P<tool>\w+)$"
)


def claude_tool_to_opencode(tool: str) -> str:
    """Translate one Claude Code tool-grant string to its OpenCode
    permission-map key. Gateway tools become `clicky-gateway_<name>`
    (confirmed naming, see doc comment above); `Task`/`TodoWrite` (only
    ever seen on commands/pentest.md's own allowed-tools, never on a
    leaf agent) become the built-in `task`/`todowrite` keys."""
    m = _CLAUDE_MCP_TOOL_RE.match(tool)
    if m:
        return f"clicky-gateway_{m.group('tool')}"
    if tool == "Task":
        return "task"
    if tool == "TodoWrite":
        return "todowrite"
    raise ValueError(f"Unrecognized tool grant, don't know how to translate: {tool!r}")


def build_permission_map(tools: list[str], extra_allow: list[str] | None = None) -> dict[str, str]:
    """Build an OpenCode `permission:` map: `allow` on every translated
    tool (plus any orchestrator-only extras like `task`/`todowrite`),
    `deny` on every OpenCode built-in NOT already being explicitly
    allowed. Confirmed necessary (not just cautious) - see doc comment
    above: an unlisted built-in defaults to *allowed*, not denied.
    """
    allow = {claude_tool_to_opencode(t) for t in tools}
    allow.update(extra_allow or [])
    perm: dict[str, str] = {t: "allow" for t in sorted(allow)}
    for builtin in BUILTIN_DENY_LIST:
        if builtin not in perm:
            perm[builtin] = "deny"
    return perm


def render_permission_yaml(perm: dict[str, str]) -> str:
    lines = ["permission:"]
    for key, action in perm.items():
        # Quote keys containing characters YAML would otherwise treat
        # specially (colons are none of ours have, but the leading
        # "clicky-gateway_" keys are plain identifiers - quoting
        # unconditionally is simplest and always valid YAML).
        lines.append(f'  "{key}": {action}')
    return "\n".join(lines)


def generate_opencode_agent(agent_path: Path) -> str:
    fm, body = parse_frontmatter(agent_path)
    name = fm["name"]
    description = fm["description"]
    tools = split_list(fm.get("tools", ""))
    skills = split_list(fm.get("skills", ""))
    perm = build_permission_map(tools)

    model_override = _agent_model_overrides("opencode").get(name)

    notes = [
        "<!--",
        f"  Generated by tools/generate-cli-targets.py from agents/{agent_path.name}.",
        "  Do not edit by hand - edit the source file and regenerate.",
        "",
    ]
    if model_override:
        notes.append(
            f"  model: {model_override} - set via tools/clicky-setup.sh --advanced"
        )
        notes.append("  (~/.clicky/agent-models.json).")
    else:
        notes += [
            "  model: inherit (Claude Code's frontmatter) has no direct OpenCode",
            "  equivalent - omitted here, so this agent uses whatever model",
            "  `opencode run -m <provider>/<model>` or the caller's own default",
            "  supplies. To pin a specific model for this agent, run",
            "  tools/clicky-setup.sh --advanced.",
        ]
    if skills:
        notes.append("")
        notes.append(
            "  Scoped to these skills in Claude Code (skills: frontmatter): "
            + ", ".join(skills)
            + ". OpenCode has no confirmed per-agent skill-allowlist mechanism -"
        )
        notes.append(
            "  this agent's `skill` tool (left allowed, not in the deny list"
        )
        notes.append(
            "  below) can load any skill registered via opencode.json's"
        )
        notes.append("  `skills.paths`, not just these. Documentation only here.")
    if fm.get("memory"):
        notes.append("")
        notes.append(
            f"  memory: {fm['memory']} (Claude Code's persistent cross-session"
        )
        notes.append(
            "  agent memory) has no confirmed OpenCode equivalent - not replicated."
        )
    notes.append("-->")

    frontmatter_lines = [
        "---",
        f"description: {description}",
        "mode: subagent",
    ]
    if model_override:
        frontmatter_lines.append(f"model: {model_override}")
    frontmatter_lines.append(render_permission_yaml(perm))

    return "\n".join(
        [
            *frontmatter_lines,
            "---",
            "",
            "\n".join(notes),
            "",
            body.strip(),
            "",
        ]
    )


# The orchestrator (commands/pentest.md's own logic) needs `task` (to
# dispatch the 9 subagents) and `todowrite` allowed, unlike every leaf
# agent - it's the one file in this repo whose Claude Code `allowed-tools`
# already includes `Task, TodoWrite` alongside 6 of the 7 gateway tools
# (never `fetch_url` - see pentest.md's own Gateway Calling Convention
# section for why).
_ORCHESTRATOR_EXTRA_ALLOW = ["task", "todowrite"]


def generate_opencode_orchestrator_agent() -> str:
    fm, body = parse_frontmatter(COMMANDS_DIR / "pentest.md")
    tools = [
        t.strip()
        for t in split_list(fm.get("allowed-tools", ""))
        if t.strip() not in ("Task", "TodoWrite")
    ]
    perm = build_permission_map(tools, extra_allow=_ORCHESTRATOR_EXTRA_ALLOW)

    notes = [
        "<!--",
        "  Generated by tools/generate-cli-targets.py from commands/pentest.md.",
        "  Do not edit by hand - edit the source file and regenerate.",
        "",
        "  Claude Code's /pentest is a slash command whose OWN frontmatter",
        "  grants Task + gateway tools directly - there is no separate",
        "  'orchestrator agent' definition file on that target. OpenCode's",
        "  command model instead delegates to a named agent (confirmed via",
        "  `opencode debug config`: a command's resolved shape is",
        "  {template, description, agent}), so this agent exists specifically",
        "  to hold the orchestrator's permission set on this target -",
        "  `.opencode/command/pentest.md` just points at it.",
        "-->",
    ]

    return "\n".join(
        [
            "---",
            "description: Comprehensive penetration testing orchestrator - dispatches recon/decision/exploit/privesc/loot/cloud-recon/source-analyzer/verification/report subagents in sequence",
            "mode: primary",
            render_permission_yaml(perm),
            "---",
            "",
            "\n".join(notes),
            "",
            body.strip(),
            "",
        ]
    )


def generate_opencode_command(command_path: Path, *, agent: str) -> str:
    fm, body = parse_frontmatter(command_path)
    description = fm.get("description", "")
    return "\n".join(
        [
            "---",
            f"description: {description}",
            f"agent: {agent}",
            "---",
            "",
            f"<!-- Generated by tools/generate-cli-targets.py from commands/{command_path.name}. Do not edit by hand. -->",
            "",
            body.strip(),
            "",
        ]
    )


# sessions/resume/archive are pure local session-bookkeeping in Claude
# Code (scoped Bash(cmd:*)/Read/Write/Grep grants, never touch a live
# target, never go through the gateway - see each command's own
# allowed-tools). OpenCode's permission patterns could in principle
# replicate Claude Code's per-subcommand Bash(mkdir:*) scoping (the
# resolved permission list already showed pattern-scoped rules like
# `read` + `*.env` => ask), but that granularity wasn't empirically
# tested here - out of scope for this pass. These get a broader `bash:
# allow` instead, an intentionally-noted, lower-stakes trade-off (no
# target/credential exposure risk in this command class) rather than a
# silent claim of equivalence.
_SESSION_BOOKKEEPING_PERMISSION = {
    "bash": "allow",
    "read": "allow",
    "write": "allow",
    "grep": "allow",
}


def generate_opencode_session_agent(name: str, description: str) -> str:
    notes = [
        "<!--",
        f"  Generated by tools/generate-cli-targets.py for the {name} command.",
        "  Do not edit by hand.",
        "",
        "  Claude Code's version scopes Bash to specific subcommands",
        "  (Bash(mkdir:*), Bash(ls:*), etc.) - OpenCode's `bash` permission",
        "  wasn't empirically tested for that same per-subcommand pattern",
        "  granularity here, so this is a broader `bash: allow` instead. An",
        "  intentionally-noted trade-off, not a silent equivalence claim: this",
        "  command class is pure local session bookkeeping (session-manager.sh",
        "  create/update/log/info/list/resume/archive), never touches a live",
        "  target or the gateway, so the broader grant carries no",
        "  target/credential exposure risk.",
        "-->",
    ]
    perm = dict(_SESSION_BOOKKEEPING_PERMISSION)
    for builtin in BUILTIN_DENY_LIST:
        if builtin not in perm:
            perm[builtin] = "deny"
    return "\n".join(
        [
            "---",
            f"description: {description}",
            "mode: subagent",
            render_permission_yaml(perm),
            "---",
            "",
            "\n".join(notes),
            "",
        ]
    )


def generate_opencode_json() -> str:
    # Confirmed live (opencode 1.1.59): opencode.json's own values are
    # NOT shell/variable-expanded - a literal "${CLAUDE_PLUGIN_ROOT}"
    # string in `command`/`environment` fails outright (`posix_spawn
    # '${CLAUDE_PLUGIN_ROOT}/...': ENOENT`, the literal unexpanded string
    # in the error). Unlike Claude Code (which expands ${CLAUDE_PLUGIN_ROOT}
    # itself before spawning mcpServers.command), OpenCode has no
    # equivalent config-level templating - so this bakes in the real
    # absolute repo path at generation time instead. Real, honest
    # trade-off: this file becomes specific to wherever the repo was
    # cloned when generated; regenerate after moving/re-cloning the repo.
    repo_root_str = str(REPO_ROOT)
    config = {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "clicky-gateway": {
                "type": "local",
                "command": [
                    f"{repo_root_str}/skills/mcp-gateway/scripts/launch.sh"
                ],
                "environment": {"CLAUDE_PLUGIN_ROOT": repo_root_str},
            }
        },
        "skills": {"paths": [f"{repo_root_str}/skills"]},
    }
    header = (
        "// Generated by tools/generate-cli-targets.py. Do not edit by hand.\n"
        "//\n"
        "// Paths below are absolute, baked in at generation time - confirmed\n"
        "// live (opencode 1.1.59) that OpenCode does NOT expand ${VAR}-style\n"
        "// placeholders in its own config values (unlike Claude Code, which\n"
        "// expands ${CLAUDE_PLUGIN_ROOT} before spawning mcpServers.command).\n"
        "// If this repo is moved or re-cloned elsewhere, regenerate this file:\n"
        "// `python3 tools/generate-cli-targets.py opencode`.\n"
    )
    return header + json.dumps(config, indent=2) + "\n"


OPENCODE_SESSION_COMMANDS = [
    ("sessions", "session-bookkeeping-sessions", "List active sessions, or show detailed status for one"),
    ("resume", "session-bookkeeping-resume", "Resume a session for further work"),
    ("archive", "session-bookkeeping-archive", "Archive a completed pentest session"),
]


def generate_opencode(out_dir: Path) -> dict[Path, str]:
    """Return {relative_path: content} for every OpenCode artifact -
    doesn't write anything itself, so the same logic drives both real
    generation and the --check drift comparison."""
    files: dict[Path, str] = {}

    for agent_path in sorted(AGENTS_DIR.glob("*.md")):
        content = generate_opencode_agent(agent_path)
        files[Path(".opencode/agents") / agent_path.name] = content

    files[Path(".opencode/agents/pentest-orchestrator.md")] = (
        generate_opencode_orchestrator_agent()
    )
    files[Path(".opencode/command/pentest.md")] = generate_opencode_command(
        COMMANDS_DIR / "pentest.md", agent="pentest-orchestrator"
    )

    for cmd_name, agent_name, description in OPENCODE_SESSION_COMMANDS:
        files[Path(f".opencode/agents/{agent_name}.md")] = (
            generate_opencode_session_agent(agent_name, description)
        )
        files[Path(f".opencode/command/{cmd_name}.md")] = generate_opencode_command(
            COMMANDS_DIR / f"{cmd_name}.md", agent=agent_name
        )

    files[Path("opencode.json")] = generate_opencode_json()

    return files


# ---------------------------------------------------------------------
# Codex CLI target
#
# Every fact below was confirmed empirically against a real installed
# `codex` binary (codex-cli 0.147.0, upgraded from a stale legacy npm
# install via `npm install -g @openai/codex@latest`), not inferred from
# docs alone - see the multi-CLI portability plan's Phase 2 section for
# the full record, including an initial "blocked" conclusion that was
# REVERSED after deeper live testing. Worth telling that story briefly
# here since it shapes two load-bearing design choices below:
#
#   A first live test (a real `codex exec` dispatch, correctly-registered
#   gateway, no error) got "tool not available" when asked to call a
#   specific gateway tool by name. That matched two open upstream GitHub
#   issues (openai/codex#17904, #16475) with no known workaround at the
#   time. Pushed to dig deeper (how does a real comparator - RedteamAgent
#   - actually handle this? would containerizing sidestep it?) rather
#   than accept that at face value, and the deeper pass reversed it:
#
#   - The failure is MODEL-SPECIFIC, not categorical. `codex exec`
#     defaults to whatever model is configured; that happened to be
#     `gpt-5.6-sol`, which resolves to `tool_mode: code_mode_only` -
#     exactly the code path an open bug (openai/codex#32101, "Code Mode
#     omits tool_search from exec") breaks. `gpt-5.4` resolves
#     differently and was reported working across every relevant GitHub
#     thread found - confirmed live: the *identical* gateway
#     registration, unchanged, succeeded with `-m gpt-5.4` after failing
#     with the default model. Every generated agent below pins
#     `model = "gpt-5.4"` for exactly this reason - this is a real
#     constraint, not a preference, and should be re-verified (via
#     `codex debug models`, checking `tool_mode`/`supports_search_tool`
#     for the target model) before ever changing it.
#   - The containerization question got a real answer, not an assertion:
#     #16475's own reporter already reproduced the identical failure
#     inside Docker with no TTY: the root cause traces to exact Rust
#     source (`spec_plan.rs`/`mcp_tool_exposure.rs`/`code_mode.rs`) with
#     zero environment dependency, and every effective workaround found
#     across the whole issue cluster is a config-file edit, none touch
#     process/environment/sandboxing. Containerizing would not have
#     fixed this - it wasn't an environment bug.
#   - RedteamAgent's own Codex integration (read in full: `install.sh`'s
#     `codex)` branch, its generated `.codex/agents/*.toml`) registers
#     ZERO custom MCP servers for Codex - it runs pentesting tools as
#     plain `docker exec` shell-outs through Codex's own built-in shell
#     tool instead, sidestepping this whole bug family by not depending
#     on the thing that's broken. That's not an option compatible with
#     Clicky's core requirement (100% of agent actions through the
#     gateway), so it's context, not a template copied here.
#
# Other confirmed-live facts, mechanical but equally load-bearing:
#
#   - `.codex/agents/<name>.toml` custom agents ARE current (not
#     superseded by the new `codex plugin` marketplace system, confirmed
#     an unrelated skills/MCP/hooks *distribution* mechanism from
#     `codex-rs/plugin/src/manifest.rs` source directly - no
#     agent/persona field exists in that struct at all).
#   - There is NO CLI flag to directly invoke a specific custom agent
#     (no `--agent`, confirmed absent from both `codex --help` and
#     `codex exec --help`). Custom agents are dispatched TO by a
#     top-level session via natural-language delegation ("Have
#     recon-agent do X" - Codex's own internal `SpawnAgent`/`Wait` tools
#     handle the rest, confirmed live by watching them fire in a real
#     dispatch) - never invoked directly as the primary session persona
#     the way OpenCode's `--agent` flag works. This is actually a close
#     match for Clicky's own existing dispatch language
#     (`commands/pentest.md` already says "Use a recon-agent to...", not
#     "invoke recon-agent") - no orchestrator-specific agent file is
#     needed the way OpenCode's `pentest-orchestrator.md` was: the
#     top-level `codex exec` session simply IS the orchestrator, driven
#     by pentest.md's own content as its initial prompt (see
#     `.codex/prompts/pentest.md` below).
#   - An agent TOML's `mcp_servers` field must be a MAP of
#     `server-name -> {command, env, ...}` FULL SERVER-CONFIG STRUCTS -
#     confirmed the hard way: `mcp_servers = ["clicky-gateway"]` (array)
#     failed with "invalid type: sequence, expected a map"; `{clicky-
#     gateway = true}` (boolean reference to an already-globally-
#     registered server) failed with "invalid type: boolean, expected
#     struct RawMcpServerConfig". Each generated agent duplicates the
#     full command+env registration inline - there is no "just reference
#     the global one by name" shorthand. A real, confirmed consequence:
#     when a subagent with its own inline registration gets spawned, it
#     launches its OWN separate gateway server process (confirmed live -
#     watched two concurrent `server.py` processes running at once,
#     correctly serialized by the gateway's existing `provision-venv.sh`
#     mkdir-lock, no corruption, just slower on first cold use). This is
#     fine, not a bug to fix - the gateway's TokenStore already uses
#     file-level locking specifically because concurrent access across
#     agent turns was always an expected case (see token_store.py).
#   - MCP registration is confirmed GLOBAL-ONLY: a project-level
#     `.codex/config.toml`'s `[mcp_servers.*]` block is silently never
#     loaded (confirmed by a real dispatch reporting zero tools despite
#     a seemingly-correct project config file); `codex mcp add` targets
#     `~/.codex/config.toml` explicitly. The top-level/orchestrator
#     session needs its OWN gateway access (separate from any subagent's
#     inline copy) for its own direct `create_session`/`register_target`
#     calls, and that access can only come from this global registration
#     - hence `install.sh` below runs the real `codex mcp add` command
#     rather than just writing a project file Codex would silently
#     ignore, the exact trap live testing fell into first.
#   - Custom prompts (`~/.codex/prompts/*.md`, the closest analog to a
#     Claude Code slash command) are confirmed global-only too (prior
#     research: docs plus a project-scoped-prompts feature request,
#     openai/codex#9848, closed as not planned) - same asymmetry as MCP
#     registration, same reason `install.sh` copies them in rather than
#     leaving them to be discovered from the repo.
#   - Codex has no `permission: deny`-style mechanism the way OpenCode
#     does - `sandbox_mode` only scopes read/write access, it doesn't
#     remove the built-in shell tool's existence. The actual enforcement
#     lever, confirmed live via the same adversarial pattern used for
#     OpenCode (agent denied shell, asked to run `whoami` "using any
#     tool it has"): `--disable shell_tool` (equivalently `-c
#     features.shell_tool=false`) genuinely removes the built-in shell
#     tool while leaving MCP tools intact, and - confirmed separately -
#     this propagates correctly to a SPAWNED SUBAGENT too, not just the
#     top-level session that set it. Since every Clicky agent (leaf and
#     orchestrator alike) is gateway-only with no legitimate direct-shell
#     use case, this needs to be set on every Clicky-related Codex
#     invocation. Deliberately NOT baked into a persistent global config
#     change (that would also disable shell for the operator's other,
#     non-Clicky Codex usage on the same machine) - instead
#     `run-clicky-agent.sh` below wraps every invocation with the flag,
#     scoped to Clicky sessions only.
#   - `caller` attribution isn't automatic - a real dispatch through a
#     subagent with no explicit instruction defaulted to `caller:
#     "Codex"` rather than the agent's own name. Each generated agent's
#     `developer_instructions` explicitly says to pass `caller="<agent-
#     name>"`, matching the same convention already documented in
#     `agents/*.md`'s Gateway Calling Convention sections for Claude
#     Code/OpenCode.
#   - Skills (`[[skills.config]]`) are registered at the GLOBAL config
#     level by `install.sh` below, not per-agent. The bug that originally
#     motivated that choice (openai/codex#14161, per-agent overrides
#     non-functional) is now confirmed CLOSED/fixed as of a PR merged
#     2026-03-16, well before 0.147.0 - per-agent skill scoping (closer
#     to Claude Code's actual per-agent `skills:` restriction) is a
#     legitimate future refinement now that the bug is gone, just not
#     built in this pass given global registration is simpler and
#     already confirmed to work.
# ---------------------------------------------------------------------

# Confirmed live: this is the one model that reliably exposes MCP tools
# in `codex exec` sessions across every test run and every relevant
# GitHub thread found during research - see the doc comment above.
# `gpt-5.6-sol` (Codex's own interactive default at time of writing)
# does NOT work reliably (resolves to `tool_mode: code_mode_only`, which
# hits openai/codex#32101). Re-verify via `codex debug models` before
# ever changing this - the failure is driven partly by server-delivered
# model-catalog metadata OpenAI can change without a client-side version
# bump (confirmed: openai/codex#33575 was fixed purely server-side).
CODEX_MODEL = "gpt-5.4"

_CODEX_GATEWAY_TOML = f"""\
[mcp_servers.clicky-gateway]
command = "{{repo_root}}/skills/mcp-gateway/scripts/launch.sh"

[mcp_servers.clicky-gateway.env]
CLAUDE_PLUGIN_ROOT = "{{repo_root}}"
"""


def _toml_multiline_string(text: str) -> str:
    """Render `text` as a TOML triple-quoted LITERAL string (`'''...'''`),
    not a basic string (`\"\"\"...\"\"\"`) - caught by real validation, not
    guessed: a basic string treats `\\` as an escape character, and
    agents/*.md's actual content contains literal backslashes (a Windows
    UNC path in one of loot-agent.md's examples, `\\\\dc01\\sysvol\\...`,
    failed to parse as TOML before this fix). A literal string processes
    no escapes at all, exactly right for pasting markdown verbatim - the
    only thing it can't contain is a literal `'''` sequence, checked
    below rather than silently corrupted."""
    assert "'''" not in text, "body contains a literal triple-single-quote - needs manual TOML escaping"
    return f"'''\n{text}\n'''"


def generate_codex_agent(agent_path: Path) -> str:
    fm, body = parse_frontmatter(agent_path)
    name = fm["name"]
    description = fm["description"]
    skills = split_list(fm.get("skills", ""))
    repo_root_str = str(REPO_ROOT)

    caller_note = (
        f'Pass caller="{name}" on every clicky-gateway MCP tool call you make, '
        "for session-trace attribution (this is not automatic - confirmed live "
        'that an unprompted call defaults to caller="Codex").'
    )
    skills_note = (
        (
            "Skills registered for this engagement (see the operator's global "
            "~/.codex/config.toml skills.config, set up by .codex/install.sh): "
            + ", ".join(skills)
            + ". Codex's per-agent skill scoping bug (openai/codex#14161) is "
            "fixed as of 0.147.0, but this generator registers skills globally "
            "for simplicity - all skills are technically visible to every "
            "agent, not just these; treat this list as the ones you actually "
            "need for your role."
        )
        if skills
        else ""
    )

    instructions_parts = [
        f"You are {name}. {description}",
        caller_note,
    ]
    if skills_note:
        instructions_parts.append(skills_note)
    instructions_parts.append(
        "You have no shell/file-edit tool - the operator's run-clicky-agent.sh "
        "wrapper disables it globally for Clicky sessions. Every action goes "
        "through your clicky-gateway MCP tools instead. Full instructions "
        "follow:"
    )
    instructions_parts.append(body.strip())
    developer_instructions = "\n\n".join(instructions_parts)

    override = _agent_model_overrides("codex").get(name)
    model = override or CODEX_MODEL
    model_note = (
        "# model is pinned to a confirmed-working value (see CODEX_MODEL's doc\n"
        "# comment in the generator) - Codex's default model has an open\n"
        "# upstream bug (openai/codex#32101) that silently drops MCP tool\n"
        "# exposure for some models. Don't remove this without re-verifying.\n"
        if not override
        else (
            f"# model overridden to {model!r} via tools/clicky-setup.sh --advanced\n"
            f"# (~/.clicky/agent-models.json) - NOT independently verified to avoid\n"
            "# the openai/codex#32101 MCP-tool-exposure bug the way CODEX_MODEL\n"
            "# (gpt-5.4) is. If this agent's MCP tools stop appearing, that bug is\n"
            "# the first thing to check - revert this override to confirm.\n"
        )
    )
    header = (
        f"# Generated by tools/generate-cli-targets.py from agents/{agent_path.name}.\n"
        "# Do not edit by hand - edit the source file and regenerate.\n"
        "#\n"
        + model_note
        + "#\n"
        "# mcp_servers below duplicates the gateway's full command+env\n"
        "# registration inline (confirmed required - a boolean/array reference\n"
        "# to the globally-registered server is rejected by Codex's schema).\n"
        "# When this agent is spawned as a subagent, it launches its own\n"
        "# gateway server process, separate from the top-level session's -\n"
        "# confirmed safe (the gateway's TokenStore already file-locks for\n"
        "# concurrent access), just slower on first cold venv provisioning.\n"
    )

    gateway_block = _CODEX_GATEWAY_TOML.format(repo_root=repo_root_str)

    return (
        header
        + "\n"
        + f'name = "{name}"\n'
        + f"description = {json.dumps(description)}\n"
        + f'model = "{model}"\n'
        + f"developer_instructions = {_toml_multiline_string(developer_instructions)}\n"
        + "\n"
        + gateway_block
    )


CODEX_SESSION_COMMANDS = ["sessions", "resume", "archive"]


def generate_codex_prompt(command_path: Path) -> str:
    """Custom-prompt equivalent of a Claude Code slash command - confirmed
    global-only (see the section doc comment), so this is checked into
    the repo for review/diffing but needs `.codex/install.sh` to actually
    copy it into $CODEX_HOME/prompts/ before Codex will discover it."""
    fm, body = parse_frontmatter(command_path)
    description = fm.get("description", "")
    header = (
        f"<!-- Generated by tools/generate-cli-targets.py from commands/{command_path.name}. "
        "Do not edit by hand. Install: .codex/install.sh copies this into "
        "$CODEX_HOME/prompts/ - Codex only discovers custom prompts there, "
        "confirmed never from a project-relative path (openai/codex#9848). -->\n"
    )
    frontmatter = f"---\ndescription: {description}\n---\n\n"
    return header + frontmatter + body.strip() + "\n"


def generate_codex_install_sh() -> str:
    repo_root_str = str(REPO_ROOT)
    return f"""\
#!/bin/bash
#
# Generated by tools/generate-cli-targets.py. Do not edit by hand.
#
# Codex CLI's MCP-server registration and custom prompts are both
# confirmed global-only (see tools/generate-cli-targets.py's Codex
# section doc comment) - there is no project-relative equivalent Codex
# will discover on its own, unlike agents/*.toml (which IS project-
# scoped and needs no install step). This script performs the two real
# global-install actions needed, using Codex's own official CLI where
# one exists rather than hand-editing ~/.codex/config.toml directly.
#
# Safe to re-run - removes any existing registration first.
#
set -euo pipefail

REPO_ROOT="{repo_root_str}"

echo "--- Registering clicky-gateway MCP server globally (~/.codex/config.toml) ---"
codex mcp remove clicky-gateway >/dev/null 2>&1 || true
codex mcp add clicky-gateway \\
    --env "CLAUDE_PLUGIN_ROOT=$REPO_ROOT" \\
    -- "$REPO_ROOT/skills/mcp-gateway/scripts/launch.sh"

CODEX_HOME="${{CODEX_HOME:-$HOME/.codex}}"
echo "--- Installing custom prompts into $CODEX_HOME/prompts/ ---"
mkdir -p "$CODEX_HOME/prompts"
cp "$REPO_ROOT"/.codex/prompts/*.md "$CODEX_HOME/prompts/"

cat << 'EOF'

--- One more manual step: skills registration ---
Codex's skills.config is confirmed to only load from the global
~/.codex/config.toml (same project-relative limitation as MCP servers
and prompts above), but this script won't auto-edit that file's
unfamiliar [[skills.config]] section for you - add this block yourself
(or merge it if you already have other [[skills.config]] entries):

EOF
python3 - "$REPO_ROOT" << 'PYEOF'
import sys
from pathlib import Path
repo_root = sys.argv[1]
skills_dir = Path(repo_root) / "skills"
for skill_dir in sorted(skills_dir.iterdir()):
    skill_md = skill_dir / "SKILL.md"
    if skill_md.is_file():
        print(f'[[skills.config]]\\npath = "{{skill_md}}"\\nenabled = true\\n')
PYEOF

cat << 'EOF'
--- Done. To dispatch Clicky agents, use: ---
  ./tools/run-clicky-agent.sh "your prompt here"
(not a bare `codex exec` call - see that script for why shell_tool must
be disabled for every Clicky session, and why the model is pinned.)
EOF
"""


def generate_codex_run_wrapper() -> str:
    return f"""\
#!/bin/bash
#
# Generated by tools/generate-cli-targets.py. Do not edit by hand.
#
# Wraps `codex exec` with the two flags every Clicky Codex session needs
# - confirmed live, not defaults, see tools/generate-cli-targets.py's
# Codex section doc comment for the full evidence trail:
#
#   -m {CODEX_MODEL}         the one model confirmed to reliably expose MCP
#                    tools in exec sessions (Codex's own default model
#                    hits an open upstream bug, openai/codex#32101)
#   --disable shell_tool
#                    removes the built-in shell tool - Codex has no
#                    `permission: deny`-style mechanism, this is the
#                    confirmed-working lever, and it's scoped to just
#                    this invocation (not a persistent global config
#                    change) so the operator's other Codex usage is
#                    unaffected
#
# Run .codex/install.sh once first (registers the gateway + prompts
# globally - Codex confirmed to never discover either from a
# project-relative path).
#
set -euo pipefail
exec codex exec -m {CODEX_MODEL} --disable shell_tool "$@"
"""


def generate_codex(out_dir: Path) -> dict[Path, str]:
    """Return {relative_path: content} for every Codex CLI artifact -
    same shape as generate_opencode()."""
    files: dict[Path, str] = {}

    for agent_path in sorted(AGENTS_DIR.glob("*.md")):
        stem = agent_path.stem  # e.g. "recon-agent"
        files[Path(f".codex/agents/{stem}.toml")] = generate_codex_agent(agent_path)

    for cmd_name in ["pentest"] + CODEX_SESSION_COMMANDS:
        files[Path(f".codex/prompts/{cmd_name}.md")] = generate_codex_prompt(
            COMMANDS_DIR / f"{cmd_name}.md"
        )

    files[Path(".codex/install.sh")] = generate_codex_install_sh()
    files[Path("tools/run-clicky-agent.sh")] = generate_codex_run_wrapper()

    return files


# ---------------------------------------------------------------------
# Copilot CLI target
#
# Every fact below was confirmed empirically against a real installed
# `copilot` binary (GitHub Copilot CLI 1.0.80, confirmed "latest version"
# via `copilot version`, npm-installed), cross-checked against the real,
# public `github/copilot-cli` issue tracker (`gh issue view` - not just a
# one-shot doc summary) after the user directly pushed back on doing
# enough version-specific research before building. Two real corrections
# came out of that:
#
#   - **Workspace `.mcp.json`/`.github/mcp.json` is confirmed BROKEN, not
#     just unconfirmed** - a real, open, tracked bug
#     (github/copilot-cli#3126: `resolveDiscoveredConfig()` never passes
#     `includeWorkspaceSources: true`, so the workspace config source is
#     silently skipped even though config-discovery is nominally
#     enabled). Confirmed by direct reproduction: a hand-written,
#     schema-correct `.mcp.json` in a scratch project registered cleanly
#     per `copilot mcp get` (`Status: Enabled`) but its tools never
#     reached the model in an actual session - repeatably, not a fluke.
#     **The fix that actually works, confirmed live**: embed the full
#     MCP server definition directly in each agent's OWN frontmatter
#     (`mcp-servers:`), which is a genuinely separate code path from the
#     broken workspace-config loader and DOES work. This is better news
#     than it sounds - it means the whole Copilot target stays fully
#     project-scoped and self-contained, no global install step needed
#     the way Codex requires (see that section) - closer to OpenCode's
#     model than Codex's.
#   - **The embedded `mcp-servers.<name>` struct needs two fields the
#     first attempt omitted, each caught by an actual schema-validation
#     error, not guessed**: `args` (required, even as an empty array -
#     `mcp-servers.clicky-gateway.args: Required`) and `tools` (required
#     at the server-definition level, `["*"]` for all - a DIFFERENT
#     `tools` field from the agent's own top-level `tools:` allowlist
#     that references this server by name).
#
# Other confirmed-live facts:
#
#   - `.github/agents/<name>.md`, project-scoped, discovered and
#     directly invokable via `--agent <name>` - confirmed via a real
#     dispatch. Unlike Codex (no such flag, natural-language delegation
#     only), this is a close match for OpenCode's `--agent` model.
#   - The agent's own top-level `tools:` array is a pure ALLOWLIST, not
#     OpenCode's allow+explicit-deny permission map - confirmed live: an
#     agent with `tools: ['clicky-gateway']` resolved to EXACTLY the 8
#     `clicky-gateway-<name>` tools (hyphen-separated, confirmed real
#     naming - a real dispatch asked to list its own tools) plus two
#     always-present utility tools (`skill`, `sql` - session/skill
#     bookkeeping, not a bypass vector), with zero built-in
#     bash/edit/view/create/grep/glob/web_fetch tools present. No
#     explicit deny list needed here, unlike OpenCode - simpler by
#     construction. Docs separately confirm `tools:` defaults to ALL
#     tools if omitted entirely, so it must always be set explicitly.
#   - Full adversarial test, same pattern as OpenCode/Codex: an agent
#     restricted to `tools: ['clicky-gateway']`, asked to run `whoami`
#     "using any tool you have," had no shell tool at all and correctly
#     chained `create_session` -> `execute_command` through the gateway
#     instead, hitting Clicky's own dangerous-target validation
#     (refused `127.0.0.1`, retried with a real target) exactly like
#     the other two targets.
#   - Orchestrator-to-leaf delegation confirmed live via the built-in
#     `task` tool: an agent granted `tools: ['task', 'clicky-gateway']`
#     successfully delegated to a separately-defined named agent
#     (`Test-recon-agent(gpt-5-mini) Create Clicky session` in the real
#     transcript), which then used its OWN embedded gateway registration
#     independently. No orchestrator-specific file format needed beyond
#     what every agent already has - just grant `task` in addition to
#     the gateway.
#   - Skills: a `.claude/skills` symlink to the real `skills/` directory
#     is discovered correctly (`copilot skill list` showed the real
#     skill under "Project skills:") - project-relative, no install
#     step, matching OpenCode's `skills.paths` convenience rather than
#     Codex's global-only registration.
#   - No custom slash-command / user-definable prompt system exists in
#     this version (confirmed: `copilot help commands` lists only
#     built-ins - `/init`, `/agent`, `/skills`, `/mcp`, `/model`,
#     `/delegate`, `/tasks`, etc., nothing for custom project commands).
#     There is no `/pentest`-equivalent to generate - the orchestrator
#     agent, invoked directly via `--agent pentest-orchestrator`, IS the
#     entry point, same conclusion as Codex reached for a different
#     reason (no CLI-level agent-selection flag there; here there IS
#     one, but still no separate command layer to generate).
#   - `--allow-all-tools` is confirmed required for non-interactive `-p`
#     mode (documented directly: "required for non-interactive mode").
#   - Real, documented reliability risk worth stating plainly, not
#     glossing over: github/copilot-cli#4421 (open) - the MCP
#     `initialize` handshake has a hard-coded 60s budget with NO retry
#     for the rest of the session if exceeded; measured root cause is
#     specifically `npx`-launched servers' ~15s median spawn overhead
#     (vs ~3s for a direct binary/script launch) occasionally crossing
#     the ceiling under load (~29% failure rate in the reporter's own
#     measurement). Clicky's gateway is NOT npx-launched - it execs
#     directly into a provisioned venv via launch.sh, and this
#     project's own Phase 0 testing already measured a warm-venv launch
#     at ~0s and a cold one at ~14s, both safely under 60s - so this
#     target is less exposed than the reported case, but the underlying
#     "zero retry, permanently toolless for the session" mechanism is
#     real and not something this generator can work around. If a
#     Copilot session ever reports clicky-gateway tools unavailable,
#     the known behavior (per the issue) is that only a fresh session
#     recovers it, not a retry within the same one.
#   - No evidence found of a Copilot-specific broken-default-model bug
#     analogous to Codex's #32101 - no model is pinned here, matching
#     OpenCode's approach of leaving model selection to the caller's
#     default, with an optional per-agent override path documented.
#   - `user-invocable: false` is set on the 10 leaf agents per the
#     original docs-only research (a field controlling whether the
#     model can autonomously self-select an agent, distinct from the
#     `tools:` restriction) - NOT independently re-verified live in this
#     pass the way everything else in this section was, flagged
#     honestly rather than presented as confirmed to the same standard.
# ---------------------------------------------------------------------


def _yaml_quote(value: str) -> str:
    """Minimal single-quote YAML scalar quoting - doubles embedded single
    quotes per YAML's own escaping rule. Good enough for the plain
    paths/descriptions this generator ever emits; not a general YAML
    encoder."""
    return "'" + value.replace("'", "''") + "'"


def _copilot_mcp_servers_block(indent: str = "") -> str:
    """The embedded mcp-servers.clicky-gateway block, confirmed required
    to route around the workspace-.mcp.json bug (github/copilot-cli#3126)
    - see the section doc comment. `args` and `tools` are both required
    fields at this level (confirmed via real schema-validation errors),
    not optional extras."""
    repo_root_str = str(REPO_ROOT)
    lines = [
        "mcp-servers:",
        "  clicky-gateway:",
        "    type: local",
        f"    command: {_yaml_quote(f'{repo_root_str}/skills/mcp-gateway/scripts/launch.sh')}",
        "    args: []",
        "    tools: [\"*\"]",
        "    env:",
        f"      CLAUDE_PLUGIN_ROOT: {_yaml_quote(repo_root_str)}",
    ]
    return "\n".join(indent + line for line in lines)


def generate_copilot_agent(agent_path: Path) -> str:
    fm, body = parse_frontmatter(agent_path)
    name = fm["name"]
    description = fm["description"]
    skills = split_list(fm.get("skills", ""))

    caller_note = (
        f'Pass caller="{name}" on every clicky-gateway MCP tool call you make, '
        "for session-trace attribution (this is not automatic on other CLI "
        'targets - confirmed live elsewhere that an unprompted call can '
        'default to a generic caller name rather than the agent\'s own).'
    )
    skills_note = (
        (
            "Skills relevant to this role (discovered project-wide via "
            "`.claude/skills` - Copilot has no confirmed per-agent skill "
            "allowlist, so every skill is technically visible to every "
            "agent, not just these): " + ", ".join(skills) + "."
        )
        if skills
        else ""
    )
    preamble_parts = [
        f"You are {name}. {description}",
        caller_note,
    ]
    if skills_note:
        preamble_parts.append(skills_note)
    preamble_parts.append(
        "You have no shell/file-edit tool - your `tools:` grant below is "
        "restricted to clicky-gateway only. Every action goes through your "
        "clicky-gateway MCP tools instead. Full instructions follow:"
    )
    body_out = "\n\n".join(preamble_parts) + "\n\n" + body.strip()

    header = (
        f"<!-- Generated by tools/generate-cli-targets.py from agents/{agent_path.name}. "
        "Do not edit by hand - edit the source file and regenerate.\n\n"
        "mcp-servers is embedded here (not in a workspace .mcp.json) because "
        "workspace-level MCP config is confirmed broken in the currently "
        "installed Copilot CLI version (github/copilot-cli#3126 - "
        "resolveDiscoveredConfig() never sets includeWorkspaceSources).\n\n"
        "user-invocable: false is per docs, not independently live-verified "
        "in this pass - see the generator's Copilot section doc comment. -->\n"
    )

    frontmatter = "\n".join(
        [
            "---",
            f"description: {json.dumps(description)}",
            "tools: ['clicky-gateway']",
            "user-invocable: false",
            _copilot_mcp_servers_block(),
            "---",
        ]
    )

    return header + "\n" + frontmatter + "\n\n" + body_out.strip() + "\n"


def generate_copilot_orchestrator_agent() -> str:
    fm, body = parse_frontmatter(COMMANDS_DIR / "pentest.md")
    description = fm.get(
        "description",
        "Comprehensive penetration testing orchestrator",
    )

    header = (
        "<!-- Generated by tools/generate-cli-targets.py from commands/pentest.md.\n"
        "Do not edit by hand - edit the source file and regenerate.\n\n"
        "Copilot CLI has no custom slash-command/prompt system (confirmed: "
        "`copilot help commands` lists only built-ins) and no dedicated "
        "'primary agent' concept the way OpenCode has - this agent IS the "
        "entry point, invoked directly via `--agent pentest-orchestrator` "
        "(see tools/run-clicky-copilot-agent.sh). It's granted `task` in "
        "addition to clicky-gateway so it can delegate to the 10 leaf agents "
        "- confirmed live that a top-level agent with `tools: ['task', "
        "'clicky-gateway']` can successfully delegate to a separately-"
        "defined named agent, which then uses its own independent gateway "
        "registration. -->\n"
    )

    frontmatter = "\n".join(
        [
            "---",
            f"description: {json.dumps(description)}",
            "tools: ['task', 'clicky-gateway']",
            _copilot_mcp_servers_block(),
            "---",
        ]
    )

    return header + "\n" + frontmatter + "\n\n" + body.strip() + "\n"


def generate_copilot_run_wrapper() -> str:
    return """\
#!/bin/bash
#
# Generated by tools/generate-cli-targets.py. Do not edit by hand.
#
# Copilot CLI has no `/pentest`-equivalent custom command (confirmed: no
# custom slash-command system exists in this version) and no separate
# "primary agent" concept - the orchestrator agent itself is the entry
# point. This wraps `copilot --agent pentest-orchestrator` with the flag
# non-interactive mode requires (confirmed: "--allow-all-tools ... required
# for non-interactive mode").
#
# No install step needed first (unlike Codex) - every generated agent's
# MCP server registration is embedded in its own frontmatter, which is
# confirmed to work standalone (see tools/generate-cli-targets.py's
# Copilot section doc comment for why workspace-level registration is
# deliberately NOT used here).
#
set -euo pipefail
exec copilot --agent pentest-orchestrator --allow-all-tools "$@"
"""


def generate_copilot(out_dir: Path) -> dict[Path, str]:
    """Return {relative_path: content} for every Copilot CLI artifact -
    same shape as generate_opencode()/generate_codex()."""
    files: dict[Path, str] = {}

    for agent_path in sorted(AGENTS_DIR.glob("*.md")):
        stem = agent_path.stem
        files[Path(f".github/agents/{stem}.md")] = generate_copilot_agent(agent_path)

    files[Path(".github/agents/pentest-orchestrator.md")] = (
        generate_copilot_orchestrator_agent()
    )
    files[Path("tools/run-clicky-copilot-agent.sh")] = generate_copilot_run_wrapper()

    return files


# ---------------------------------------------------------------------


def write_files(files: dict[Path, str], root: Path) -> None:
    for rel_path, content in files.items():
        dest = root / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
        if dest.suffix == ".sh":
            dest.chmod(dest.stat().st_mode | 0o111)


def ensure_symlinks(symlinks: dict[Path, Path], root: Path) -> None:
    """Create each `link -> target` symlink (relative, so the repo stays
    portable if cloned elsewhere) if not already correctly present.
    Confirmed necessary for Copilot CLI: `.claude/skills` -> `skills`
    lets it discover all 26 real skills directly (confirmed live via
    `copilot skill list`), no content duplication."""
    for link_rel, target_rel in symlinks.items():
        link = root / link_rel
        link.parent.mkdir(parents=True, exist_ok=True)
        desired_target = os.path.relpath(root / target_rel, link.parent)
        if link.is_symlink() and os.readlink(link) == desired_target:
            continue
        if link.exists() or link.is_symlink():
            if link.is_dir() and not link.is_symlink():
                # A real directory already sits there - don't clobber
                # something that isn't ours to manage.
                continue
            link.unlink()
        link.symlink_to(desired_target)


def check_symlinks(symlinks: dict[Path, Path], root: Path) -> list[str]:
    problems = []
    for link_rel, target_rel in symlinks.items():
        link = root / link_rel
        desired_target = os.path.relpath(root / target_rel, link.parent)
        if not link.is_symlink():
            problems.append(f"missing symlink: {link_rel} -> {target_rel}")
        elif os.readlink(link) != desired_target:
            problems.append(
                f"symlink {link_rel} points at {os.readlink(link)!r}, expected {desired_target!r}"
            )
    return problems


# OpenCode itself auto-provisions these inside `.opencode/` the first
# time it runs against a project referencing a plugin package (observed
# live: a `node_modules/@opencode-ai/plugin` install, `package.json`,
# `bun.lock`, plus its own `.gitignore` listing exactly these four names)
# - nothing this generator produces or manages. Excluded from the
# orphan check by name, not deleted; `.opencode/.gitignore` (itself one
# of these) is what actually keeps them out of git once committed.
_OPENCODE_OWNED_PATHS = {
    Path(".opencode/node_modules"),
    Path(".opencode/bun.lock"),
    Path(".opencode/package.json"),
    Path(".opencode/.gitignore"),
}


# Codex artifacts fully occupy `.codex/` (owned outright, like OpenCode
# owns `.opencode/`), but `tools/run-clicky-agent.sh` is the one Codex
# artifact living alongside this generator script itself in `tools/` -
# that directory is NOT owned outright (tools/generate-cli-targets.py
# lives there too and must never be flagged as "orphaned").
_CODEX_OWNED_DIRS = {Path(".codex")}
_CODEX_OWNED_FILES = {Path("tools/run-clicky-agent.sh")}


def check_drift(
    files: dict[Path, str],
    root: Path,
    *,
    owned_dirs: set[Path],
    owned_files: set[Path] = frozenset(),
    excluded: set[Path] = frozenset(),
) -> list[str]:
    """Return a list of human-readable drift descriptions - empty means
    the checked-in output matches what this script would generate right
    now. `owned_dirs` are fully-owned subtrees (every file under them
    should be in `files`, else it's orphaned); `owned_files` are
    individual paths outside any owned dir; `excluded` are real paths
    under an owned dir that this generator doesn't manage itself (e.g.
    OpenCode's own auto-provisioned node_modules/)."""
    problems = []
    for rel_path, content in files.items():
        dest = root / rel_path
        if not dest.is_file():
            problems.append(f"missing: {rel_path}")
        elif dest.read_text() != content:
            problems.append(f"stale (regenerate needed): {rel_path}")
    # Also catch generated files that exist on disk but this run no
    # longer produces (e.g. an agent was deleted from agents/).
    for existing in root.rglob("*"):
        if not existing.is_file():
            continue
        rel = existing.relative_to(root)
        if any(
            rel == ex or str(rel).startswith(str(ex) + "/") for ex in excluded
        ):
            continue
        owned = rel in owned_files or any(
            rel == d or str(rel).startswith(str(d) + "/") for d in owned_dirs
        )
        if owned and rel not in files:
            problems.append(f"orphaned (no longer generated): {rel}")
    return problems


_TARGETS = {
    "opencode": {
        "generate": generate_opencode,
        "owned_dirs": {Path(".opencode")},
        "owned_files": {Path("opencode.json")},
        "excluded": _OPENCODE_OWNED_PATHS,
        "symlinks": {},
    },
    "codex": {
        "generate": generate_codex,
        "owned_dirs": _CODEX_OWNED_DIRS,
        "owned_files": _CODEX_OWNED_FILES,
        "excluded": set(),
        "symlinks": {},
    },
    "copilot": {
        "generate": generate_copilot,
        # Scoped to .github/agents specifically, NOT all of .github/ - a
        # typical repo's .github/ holds CI workflows, issue templates,
        # etc. that this generator has nothing to do with and must never
        # flag as orphaned.
        "owned_dirs": {Path(".github/agents")},
        "owned_files": {Path("tools/run-clicky-copilot-agent.sh")},
        "excluded": set(),
        "symlinks": {Path(".claude/skills"): Path("skills")},
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=sorted(_TARGETS))
    parser.add_argument(
        "--check",
        action="store_true",
        help="Don't write anything - exit 1 if checked-in output would differ from a fresh generation",
    )
    args = parser.parse_args()

    spec = _TARGETS[args.target]
    files = spec["generate"](REPO_ROOT)

    if args.check:
        problems = check_drift(
            files,
            REPO_ROOT,
            owned_dirs=spec["owned_dirs"],
            owned_files=spec["owned_files"],
            excluded=spec["excluded"],
        )
        problems += check_symlinks(spec["symlinks"], REPO_ROOT)
        if problems:
            print(f"Generated {args.target} artifacts are out of date:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            print(
                f"\nRun: python3 tools/generate-cli-targets.py {args.target}",
                file=sys.stderr,
            )
            return 1
        print(f"{args.target} artifacts are up to date.")
        return 0

    write_files(files, REPO_ROOT)
    ensure_symlinks(spec["symlinks"], REPO_ROOT)
    print(f"Wrote {len(files)} {args.target} artifact(s) under {REPO_ROOT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
