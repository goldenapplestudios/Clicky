# Integrating Clicky with Springtale

Clicky has no built-in awareness of Springtale (`scopecreep-zip/springtale`) and doesn't need any - this doc exists so a `connector-clicky` crate built in the Springtale repo has a single, verified source of truth for how to drive Clicky headlessly, instead of re-deriving it from scratch or guessing at flags. The integration is entirely one-directional: Springtale spawns a Clicky-capable CLI as a subprocess and reads back the files that CLI produces. Nothing in Clicky changes to support this - the multi-CLI portability work already makes `/pentest` runnable non-interactively, and this doc plus `tools/run-headless.sh` package that up.

See the Springtale-side plan this backs: `docs/intended-arch/CLICKY_CONNECTOR_PLAN.md` in the Springtale repo.

## The wrapper: `tools/run-headless.sh`

```
tools/run-headless.sh <target> ["context"] [--cli claude|codex|copilot]
                       [--plugin-root PATH] [--max-budget-usd N]
                       [--report-format markdown|html|pdf] [--report-out FILE]
```

Spawns a Clicky-capable CLI non-interactively against `<target>`, waits for it to exit, locates the session directory the run created, and prints one JSON line on stdout:

```json
{"session_id": "pentest_20260818_142301_54321", "session_dir": "/home/user/.claude/sessions/pentest_20260818_142301_54321", "findings_json": "/home/user/.claude/sessions/pentest_20260818_142301_54321/reports/findings.json", "report": null}
```

`findings_json` is `null` only if the run logged no findings at all (a real possible outcome, not an error). `report` is `null` unless `--report-format` was passed. Non-zero exit + no stdout on any failure (usage error / CLI invocation failure / couldn't locate the session directory - see the script's header for the exact codes).

This is the one thing a Springtale connector's `execute()` needs to call: one subprocess, one JSON line back, then read whatever file `findings_json`/`report` point at.

## Why session discovery isn't just "read the session id from the CLI's own output"

There are two different, unrelated "session" concepts in play here, confirmed by reading the actual scripts rather than assumed:

- **The host CLI's own conversation/session id** - what `claude -p ... --output-format json` reports in its result envelope. This identifies the *conversation*, not the pentest engagement.
- **Clicky's own pentest session id** - minted by `skills/session-management/scripts/session-manager.sh`'s `create_session()` as `pentest_$(date +%Y%m%d_%H%M%S)_$$`, living at `$SESSION_BASE/$session_id` where `SESSION_BASE` is `$CLAUDE_PLUGIN_OPTION_DEFAULT_SESSION_DIRECTORY` if set, else `~/.claude/sessions`. This is the id that actually matters - it's the directory everything (`recon/`, `exploit/`, `privesc/`, `loot/`, `reports/`, `checkpoints/`, `credentials/`, `logs/`, `session.json`) gets written under.

These are not the same value, and nothing surfaces Clicky's session id in the host CLI's own `--output-format json` envelope (that envelope is about the conversation, not about what `/pentest`'s internal `create_session` gateway call returned). `session-manager.sh` does write a `$SESSION_BASE/.current-session` pointer file on every `create_session` call, but its own comment says plainly: *"A concurrent second /pentest run will overwrite this pointer, at which point the recovery hook simply stops finding the earlier session"* - i.e. it's a best-effort convenience for Clicky's own Stop-hook recovery logic, not something safe for an external caller to trust if two runs might overlap.

`tools/run-headless.sh` instead snapshots the set of `$SESSION_BASE/pentest_*` directories immediately before spawning the CLI and diffs against the set immediately after it exits - the new directory is the one this run created, regardless of what the pointer file says. This is safe as long as this script's own invocations aren't run concurrently with each other for the same target CLI (a reasonable constraint for a connector that serializes its own dispatches, which `run_pentest` should).

## Reading results back

- **Raw structured findings**: `$session_dir/reports/findings.json`. Written incrementally during the engagement by `session-manager.sh log_finding` calls; may be absent if literally nothing was found. Each finding carries `.validation.tier1_trace_check` / `.validation.tier2_review` - see `skills/session-management/SKILL.md` for what "confirmed" vs. "needs manual review" means before treating a finding as verified.
- **Formatted report** (markdown/html/pdf): only generated on request, via `skills/report-generation/scripts/report-generator.sh --session-id ID --format FORMAT --output FILE` - `tools/run-headless.sh --report-format ...` does this for you. `html`/`pdf` require `pandoc` on the machine actually running the CLI (not the machine running the wrapper, if those differ).
- **Interop formats** (SARIF, CycloneDX, AIBOM): exist (`skills/report-generation/scripts/{sarif_convert,cyclonedx_convert,aibom_convert}.py`) but consume `skills/source-code-analysis`'s own findings files (`source_findings.json`/`dependency_findings.json`), not the general pentest `findings.json` - relevant only if the engagement included source-code analysis, not for a general recon/exploit run.

## Per-CLI invocation notes

Only what's real and live-verified, from `tools/generate-cli-targets.py`'s own doc comments (that file is the source of truth for all of this - re-check it if these ever drift):

- **Claude Code** (default, and the only one this session verified end-to-end against a real target): `claude -p "/pentest <target>" --output-format json --permission-mode bypassPermissions --plugin-dir <this-repo>`.
- **Codex CLI**: no direct flags in the wrapper - delegates to the already-generated `tools/run-clicky-agent.sh`, which pins `-m gpt-5.4` (the default model silently drops MCP tool exposure via an open upstream bug, `openai/codex#32101`) and `--disable shell_tool`. Requires `.codex/install.sh` to have been run once first - Codex registers MCP servers and custom prompts globally only, never from a project-relative path.
- **Copilot CLI**: delegates to `tools/run-clicky-copilot-agent.sh`. Copilot has no custom slash-command system in the confirmed-tested version, so there's no `/pentest` to invoke - the `pentest-orchestrator` agent itself is the entry point (`--agent pentest-orchestrator --allow-all-tools`), given the target/context directly rather than a slash command string.
- **OpenCode**: not wired into `run-headless.sh` yet. No generated wrapper script exists for it (only Codex and Copilot have one under `tools/`) - add one following the same pattern (see how the other two are generated) before adding `opencode` support here, rather than guessing its exact non-interactive flag shape.

## What this doc deliberately does not cover

Anything on the Springtale side - the `Connector` trait implementation, capability manifest, approval-gate wiring, or the builtin Recipe. That's `docs/intended-arch/CLICKY_CONNECTOR_PLAN.md` in the Springtale repo, which this doc is written to support.
