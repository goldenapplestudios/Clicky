"""Advanced: assign specific Clicky agents to specific AI frameworks/models.

Invoked via `tools/clicky-setup.sh --advanced` - deliberately not part of
the default wizard flow, since this is real added complexity that most
operators don't need. Generalizes the one-off "severity-analyst-agent
runs through Codex" pattern into something any operator can apply to any
agent. Needs python3 (checked by clicky-setup.sh before delegating here)
- a fair ask for this specific, opt-in, power-user path, since it already
needs tools/generate-cli-targets.py (itself Python) to apply Codex/
OpenCode overrides, unlike the default wizard flow, which is pure bash.

Scope, stated honestly rather than overclaimed:

- **Codex / OpenCode**: real, working, already-verified mechanisms.
  `tools/generate-cli-targets.py` bakes a per-agent `model` value into
  each generated target - Codex's TOML `model = "..."` field (already
  proven in production for the CODEX_MODEL pin) and OpenCode's
  documented `model: <provider>/<model-id>` frontmatter field (documented
  by that generator's own prior comments, previously just never
  populated). This script writes ~/.clicky/agent-models.json and
  triggers regeneration for both targets.
- **Copilot CLI**: NOT supported here. Its agent frontmatter schema has
  no confirmed model field in anything verified so far this project -
  guessing at one would violate this project's own primary-sources
  discipline. Flagged plainly to the operator, not silently skipped.
- **Claude Code**: uses the `--agents` CLI flag (confirmed real,
  install-mode-agnostic, non-file-mutating mechanism - see
  code.claude.com/docs/en/sub-agents's model-resolution order). Always
  supplies a byte-faithful FULL redefinition (real description/tools/
  prompt read from the actual agents/<name>.md, only `model` changed) -
  correct and safe regardless of whether Claude Code's `--agents` merges
  partial definitions or requires full ones for an existing plugin-agent
  name, a question this project's own research left genuinely
  unresolved (see the implementation plan's Verification section) rather
  than guessed at. **Not yet live-dispatch-tested** - the JSON this
  script assembles has not yet been run through a real
  `claude --agents '{...}' -p ...` call to confirm the gateway-only
  `tools:` restriction survives intact. Said plainly in this script's
  own output, not hidden.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLICKY_CONFIG_DIR = Path(os.environ.get("CLICKY_CONFIG_DIR", Path.home() / ".clicky"))

AGENT_NAMES = [
    "cloud-recon-agent", "decision-agent", "exploit-agent", "loot-agent",
    "privesc-agent", "recon-agent", "report-agent", "severity-analyst-agent",
    "source-analyzer-agent", "verification-agent",
]

CLAUDE_MODEL_ALIASES = {"sonnet", "opus", "haiku", "fable", "inherit"}


def _load_generator_module(repo_root: Path):
    """Dynamic import - tools/generate-cli-targets.py's hyphenated
    filename isn't a valid Python module name for a plain `import`."""
    spec = importlib.util.spec_from_file_location(
        "generate_cli_targets", repo_root / "tools" / "generate-cli-targets.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parse_agent_frontmatter(gen_module, agent_path: Path) -> tuple[dict, str]:
    return gen_module.parse_frontmatter(agent_path)


def _print_agent_table(assignments: dict[str, dict]) -> None:
    print()
    for i, name in enumerate(AGENT_NAMES, 1):
        current = assignments.get(name)
        status = f"-> {current['framework']}/{current['model']}" if current else "(default)"
        print(f"  {i:2}. {name:28} {status}")


def _prompt_assignment() -> tuple[str, str] | None:
    """One line, e.g. '3 opus' (Claude alias) or '8 codex gpt-5.4'
    (framework model) or '8 codex gpt-5.4 - reset' style not supported;
    blank line to finish. Kept intentionally terse - this is the
    advanced/opt-in flow, but still shouldn't require reading a manual."""
    try:
        line = input("  Assign (e.g. '3 opus' or '8 codex gpt-5.4'), or blank to finish: ").strip()
    except EOFError:
        return None
    if not line:
        return None
    parts = line.split()
    if len(parts) == 2:
        idx_str, model = parts
        framework = "claude"
    elif len(parts) == 3:
        idx_str, framework, model = parts
    else:
        print("  Couldn't parse that - try '<number> <model>' or '<number> <framework> <model>'.")
        return _prompt_assignment()

    if not idx_str.isdigit() or not (1 <= int(idx_str) <= len(AGENT_NAMES)):
        print(f"  '{idx_str}' isn't a valid agent number (1-{len(AGENT_NAMES)}).")
        return _prompt_assignment()
    name = AGENT_NAMES[int(idx_str) - 1]

    if framework not in ("claude", "codex", "opencode"):
        print(f"  '{framework}' isn't supported here - claude, codex, or opencode only (see this file's own doc comment for why Copilot isn't).")
        return _prompt_assignment()

    return name, {"framework": framework, "model": model}


def _build_claude_agents_wrapper(repo_root: Path, assignments: dict[str, dict]) -> Path | None:
    claude_assignments = {n: a for n, a in assignments.items() if a["framework"] == "claude"}
    if not claude_assignments:
        return None

    gen = _load_generator_module(repo_root)
    agents_json: dict[str, dict] = {}
    for name, assignment in claude_assignments.items():
        agent_path = repo_root / "agents" / f"{name}.md"
        fm, body = _parse_agent_frontmatter(gen, agent_path)
        tools = [t.strip() for t in fm.get("tools", "").split(",") if t.strip()]
        agents_json[name] = {
            "description": fm["description"],
            "prompt": body.strip(),
            "tools": tools,
            "model": assignment["model"],
        }

    out_path = repo_root / "tools" / "run-clicky-agent-models.sh"
    # shlex.quote(), NOT Python's `!r` repr - agent prompt bodies are real
    # prose and routinely contain apostrophes ("agent's", "doesn't", ...;
    # confirmed: 40+ in exploit-agent.md alone), which `!r` would embed
    # unsafely (Python's repr picks its own quote character for *Python*
    # literal safety, not shell safety - it is not the same problem).
    # shlex.quote() is the actual right tool: real single-argument
    # POSIX-shell-safe quoting, handles embedded single quotes correctly.
    payload = shlex.quote(json.dumps(agents_json))
    out_path.write_text(
        "#!/bin/bash\n"
        "#\n"
        "# Generated by tools/advanced_agent_assignment.py - do not edit by hand,\n"
        "# re-run `tools/clicky-setup.sh --advanced` instead.\n"
        "#\n"
        "# Launches Claude Code with per-agent model overrides for: "
        + ", ".join(sorted(claude_assignments)) + "\n"
        "#\n"
        "# Each overridden agent's --agents entry is a full, byte-faithful\n"
        "# redefinition (real description/tools/prompt from the actual\n"
        "# agents/<name>.md, only `model` changed) - not a sparse override -\n"
        "# because whether Claude Code's --agents flag merges a partial\n"
        "# definition into an existing plugin agent or requires a full one is\n"
        "# genuinely unresolved in this project's own research (see the\n"
        "# Kalilix/setup-wizard implementation plan's Verification section).\n"
        "# Supplying a full redefinition is correct either way. NOT YET\n"
        "# LIVE-DISPATCH-TESTED - said plainly, not hidden: this has not been\n"
        "# run through a real dispatch to confirm the gateway-only `tools:`\n"
        "# restriction survives. Verify this before relying on it for a real\n"
        "# engagement.\n"
        "#\n"
        "# Usage: tools/run-clicky-agent-models.sh [claude args...]\n"
        "\n"
        "set -euo pipefail\n"
        "\n"
        f"exec claude --agents {payload} \"$@\"\n"
    )
    out_path.chmod(0o755)
    return out_path


def run_advanced_flow(repo_root: Path, clicky_config_dir: Path) -> int:
    print("Advanced: per-agent framework/model assignment")
    print("=" * 48)
    print(
        "Codex and OpenCode are fully supported (real, verified mechanisms).\n"
        "Copilot CLI isn't - no confirmed per-agent model field exists for it.\n"
        "Claude Code is supported via a generated wrapper script, but that\n"
        "wrapper hasn't been live-dispatch-tested yet - see this flow's own\n"
        "output at the end for what that means before you rely on it."
    )

    agent_models_path = clicky_config_dir / "agent-models.json"
    assignments: dict[str, dict] = {}
    if agent_models_path.exists():
        try:
            with open(agent_models_path) as f:
                assignments = json.load(f)
        except (OSError, json.JSONDecodeError):
            pass

    _print_agent_table(assignments)
    while True:
        result = _prompt_assignment()
        if result is None:
            break
        name, assignment = result
        assignments[name] = assignment
        _print_agent_table(assignments)

    if not assignments:
        print("No assignments made - nothing to do.")
        return 0

    clicky_config_dir.mkdir(parents=True, exist_ok=True)
    with open(agent_models_path, "w") as f:
        json.dump(assignments, f, indent=2)
    print(f"\n✓ Wrote {agent_models_path}")

    # Codex/OpenCode: regenerate via the real generator, using the file
    # we just wrote (CLICKY_AGENT_MODELS_PATH defaults to exactly this
    # path - see generate-cli-targets.py - so no extra env plumbing
    # needed for a normal operator run).
    for target in ("codex", "opencode"):
        if any(a["framework"] == target for a in assignments.values()):
            result = subprocess.run(
                [sys.executable, str(repo_root / "tools" / "generate-cli-targets.py"), target],
                cwd=repo_root,
            )
            if result.returncode == 0:
                print(f"✓ Regenerated {target} artifacts with the new model assignment(s)")
            else:
                print(f"✗ Regenerating {target} failed - see output above")

    wrapper = _build_claude_agents_wrapper(repo_root, assignments)
    if wrapper:
        print(f"✓ Wrote {wrapper} - NOT yet live-dispatch-tested (see the file's own header)")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(run_advanced_flow(REPO_ROOT, CLICKY_CONFIG_DIR))
