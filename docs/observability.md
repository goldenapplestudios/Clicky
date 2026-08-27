# Clicky Observability

> **Navigation**: [Usage](usage.md) | [Architecture](architecture.md) | [Agents](agents.md) | [Workflow](workflow.md) | [Skills](skills.md) | [Observability](observability.md) | [Sandboxing](sandboxing.md) | [README](../README.md)

---

When a run fails partway through, or you just want to see how Clicky's actual observed success rates are trending (via `skills/htb-decision-tree`'s self-calibration - see `agents.md#htb-decision-tree`), you need a record of what was actually attempted. There are two tiers, and they're complementary rather than alternatives.

## Tier 1: Trace log (default, ships with the plugin)

Every install gets this for free — no setup required. Since every agent action already funnels through the `clicky-gateway` MCP server by construction, the gateway itself (`skills/mcp-gateway/server.py`'s `_trace()` helper) writes one JSONL line per gateway tool call directly into that session's own `$SESSION_DIR/logs/trace.jsonl`, tagged with which agent made the call (`caller`) and, when the call failed, the actual error. Agent-dispatch boundaries are marked the same way, via the `log_agent_boundary` gateway tool that `commands/pentest.md` calls immediately before/after each dispatch.

This replaced an earlier design built on Claude-Code-specific `PostToolUse`/`PostToolUseFailure`/`SubagentStop` hooks (`hooks/hooks.json`) writing to a global `~/.claude/pentest-traces/<claude_session_id>.jsonl`, cross-referenced against a session via a separately-maintained pointer file — retired as part of Clicky's multi-CLI portability work, since it depended on a specific host CLI's hook event/payload contract. Gateway-side tracing has no such dependency (any MCP-capable host works identically) and keys directly on `session_dir` instead of a pointer-file guess.

Review a run with:

```bash
scripts/session-review.sh                    # most recent run
scripts/session-review.sh <session_id>        # a specific run
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

When filtering, `agent_type`/`agent.name` map onto Clicky's own agent names (`recon-agent`, `decision-agent`, `exploit-agent`, `privesc-agent`, `loot-agent`, `cloud-recon-agent`, `source-analyzer-agent`, `verification-agent`, `report-agent`), and `prompt.id`/`session.id` let you tie every event on a single `/pentest` invocation back together. See Claude Code's own [monitoring documentation](https://code.claude.com/docs/en/monitoring-usage) for the complete event/attribute reference.

## A note on trace-log safety

All 11 agents (see [Agents](agents.md)) hold gateway-only tool grants (`mcp__plugin_clicky_clicky-gateway__*`) - none has a direct `Bash`/`Read`/`Write`/`Grep`/`WebFetch` tool. The gateway tokenizes target/credential values in what it hands back before its result ever reaches the model, and the model in turn only ever sends the gateway tokenized values (e.g. `TARGET_1`) rather than raw IPs/hostnames/credentials. `_trace()` (in `skills/mcp-gateway/server.py`) writes exactly the `tool_input`/`tool_result` values each tool call already received/computed - i.e. exactly what the model sent to and received from a tool call, nothing captured independently below that layer. The practical result is that Tier 1 trace logs (`$SESSION_DIR/logs/trace.jsonl`) end up token-safe by construction: real target/credential values shouldn't appear in them, because the gateway resolves tokens to real values only internally and redacts real values back to tokens before returning - the exact same already-redacted string that gets traced is what the model sees. This is an incidental benefit of the gateway architecture, not a separate redaction step tracing performs itself.

## Which one should I use?

- Debugging a single run right after it happened, or you don't want to run any extra infrastructure: **Tier 1**, `scripts/session-review.sh`.
- Running Clicky across many engagements and want real trend analysis, or you already have an OTel collector: **Tier 2**.
- Refining `htb-decision-tree`'s calibrated success rates (`skills/session-management/scripts/attempt-aggregator.sh`, computed from every session's `logs/attempts.jsonl`) and `decision-agent`'s complementary finer-grained memory (its persistent memory — see [Agents](agents.md#persistent-memory)): read Tier 1's output after each engagement; Tier 2 if you want to validate that learning against a larger sample.
