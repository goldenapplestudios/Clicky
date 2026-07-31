# Clicky Observability

> **Navigation**: [Usage](usage.md) | [Architecture](architecture.md) | [Agents](agents.md) | [Workflow](workflow.md) | [Skills](skills.md) | [Observability](observability.md) | [Sandboxing](sandboxing.md) | [README](../README.md)

---

When a run fails partway through, or you just want to know whether Clicky's actual success rates match the HTB baseline it was built from, you need a record of what was actually attempted. There are two tiers, and they're complementary rather than alternatives.

## Tier 1: Trace log (default, ships with the plugin)

Every install gets this for free — no setup required. Three hooks (`PostToolUse`, `PostToolUseFailure`, `SubagentStop`, defined in `hooks/hooks.json`) write one JSONL line per tool call or subagent completion to `~/.claude/pentest-traces/<claude_session_id>.jsonl`, tagged with which agent made the call (`agent_type`/`agent_id`) and, when the tool call failed, the actual error.

Review a run with:

```bash
scripts/session-review.sh                    # most recent run
scripts/session-review.sh <claude_session_id> # a specific run
```

(this script lives in `skills/report-generation/scripts/`). It prints a chronological walk-through and groups failures by agent, so you can see exactly where a run went sideways.

This is the right tool for reviewing one run, or a handful, right after they happen. It's a flat file — there's no cross-run querying, trending, or dashboarding built in.

## Tier 2: OpenTelemetry (opt-in, for real analysis at scale)

Claude Code has full built-in OpenTelemetry support, well beyond what Tier 1 gives you: `claude_code.tool_decision` and `claude_code.tool_result` events, `claude_code.api_request`/`api_error` events, all correlated by a shared `prompt.id` and `session.id`, plus a beta distributed-tracing mode with a real span hierarchy (`claude_code.interaction` → `claude_code.tool` → nested subagent spans, carrying `agent_id`/`parent_agent_id`). Export it to Jaeger, Datadog, or any OTLP-compatible backend, and you can answer questions like "has our real SMB null-session success rate drifted over the last 20 engagements?" — something a pile of JSONL files can't do on its own.

This isn't something Clicky bundles — it's infrastructure your own environment provides. To turn it on:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_LOGS_EXPORTER=otlp            # or "console" for local debugging
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

# For full span-level detail (beta):
export CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1
export OTEL_TRACES_EXPORTER=otlp
```

When filtering, `agent_type`/`agent.name` map onto Clicky's own agent names (`recon-agent`, `decision-agent`, `exploit-agent`, `privesc-agent`, `loot-agent`, `cloud-recon-agent`), and `prompt.id`/`session.id` let you tie every event on a single `/pentest` invocation back together. See Claude Code's own [monitoring documentation](https://code.claude.com/docs/en/monitoring-usage) for the complete event/attribute reference.

## Which one should I use?

- Debugging a single run right after it happened, or you don't want to run any extra infrastructure: **Tier 1**, `scripts/session-review.sh`.
- Running Clicky across many engagements and want real trend analysis, or you already have an OTel collector: **Tier 2**.
- Refining `decision-agent`'s learned success rates (its persistent memory — see [Agents](agents.md#persistent-memory)): read Tier 1's output after each engagement; Tier 2 if you want to validate that learning against a larger sample.
