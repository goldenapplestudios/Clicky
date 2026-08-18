# Clicky and the Sandboxed Bash Tool

> **Navigation**: [Usage](usage.md) | [Architecture](architecture.md) | [Agents](agents.md) | [Workflow](workflow.md) | [Skills](skills.md) | [Observability](observability.md) | [Sandboxing](sandboxing.md) | [README](../README.md)

---

Claude Code has a built-in sandboxed Bash tool (Seatbelt on macOS, bubblewrap on Linux/WSL2) that restricts what a Bash command and its child processes can read, write, and reach over the network - enforced at the OS level, not just by Claude choosing not to run something. This is documented in full at [code.claude.com/docs/en/sandboxing](https://code.claude.com/docs/en/sandboxing); this page covers what's specific to using it with Clicky.

**This no longer overlaps with Clicky's own scope enforcement at all - the two now apply to disjoint traffic.** The scope gate described in `skills/target-validation/SKILL.md` ("Automatic Scope Enforcement") - `skills/mcp-gateway`'s `register_target` tool, backed by `scope-validator.sh` and understanding Clicky's `scope.json` - is plugin-owned, on by default (`enforce` mode), and is the real, currently-active gate for everything Clicky itself does: the orchestrating `/pentest` command and all 9 `agents/*.md` files have had their `tools:`/`allowed-tools:` frontmatter rewritten to grant exclusively `skills/mcp-gateway`'s 7 MCP tools, with zero direct `Bash`/`Read`/`Write`/`Grep`/`WebFetch` grants left anywhere in the plugin. The Claude Code sandbox described on this page is a separate, Claude-Code-native feature that governs the built-in `Bash` tool and its child processes specifically - and, per "Known limitations" below, an MCP server (which is what every one of Clicky's shell commands now runs through, via `execute_command`) sits outside that boundary regardless of `sandbox.enabled`. So this sandbox does **not** provide defense-in-depth on top of Clicky's own engagement traffic - enabling it has zero effect on anything a dispatched agent or the `/pentest` command itself does. It's still worth knowing about for any *other* Bash usage in the same Claude Code session - ad hoc commands you or Claude run directly outside `/pentest` dispatch - and (see the finding below) it has real limits for IP-based targets specifically even there. The sandbox lives entirely in Claude Code's own `settings.json`, outside anything `plugin.json` can control. Clicky does not - and should not - write to your global Claude Code settings automatically; enabling the sandbox is your call.

## Step 0 finding: does the network allowlist support IP addresses or CIDR ranges?

This was the open question before writing this doc, since most pentest targets (HTB-style boxes, internal engagements) are raw IPs, not hostnames. Verified against Claude Code's authoritative settings reference (`code.claude.com/docs/en/settings`), not assumed:

> `network.allowedDomains` — Array of **domains** to allow for outbound network traffic. Supports wildcards (e.g., `*.example.com`). Example: `["github.com", "*.npmjs.org"]`

And from the sandboxing page itself: "The built-in proxy enforces the allowlist based on the **requested hostname**."

**Confirmed: no CIDR or IP-range syntax exists anywhere in the documentation.** Every documented example is a domain name; the only supported pattern beyond an exact string is a `*.` prefix wildcard. There is no `10.10.10.0/24`-style entry and no indication one is planned.

**Not explicitly confirmed either way: whether a single literal IP address (e.g. `"10.10.10.10"`) works as an exact-match entry.** The matching logic is described as hostname-based, and an IP-shaped HTTP/CONNECT request's "hostname" is literally the IP string, so a literal IP entry plausibly works as an exact match the same way `"github.com"` does - but no documentation example, positive or negative, addresses this directly. This session did not empirically test it live: doing so would mean flipping `sandbox.enabled: true` in your real Claude Code settings, which is a user-facing environment change Clicky won't make on its own initiative. **If you rely on this, verify it yourself first** - `/sandbox` in a scratch session, add a single target IP to `allowedDomains`, and confirm a request to it succeeds while an unlisted IP is blocked or prompts.

### Practical implication

Because there's no CIDR support, a `/24`-style engagement scope can't be expressed as one allowlist entry - you'd need one exact-match entry per live host, added as you discover them, which is workable but manual. For a single-target engagement (the common case), listing that one IP (if the "not explicitly confirmed" point above holds up in your own test) or the target's hostname (if it has one) is straightforward. For hostname-based engagements the wildcard support (`*.example.com`) covers a lot more ground with a lot less maintenance. `skills/mcp-gateway`'s `register_target` (calling `scope-validator.sh`) doesn't have this limitation - it reads `scope.json` directly and already handles CIDR, IP ranges, and wildcards - and, per the correction above, it's the one of the two that actually gates Clicky's own engagement traffic; this sandbox's allowlist, if you enable it, is protecting a different, narrower slice of activity (see "Recommended configuration" below), not standing in front of the same traffic `register_target` already covers.

## Recommended configuration

If you choose to enable the sandbox anyway - for the ad hoc, outside-of-`/pentest`-dispatch Bash usage described above, not because it gates Clicky's own engagement traffic - a reasonable starting point in `~/.claude/settings.json`:

```json
{
  "sandbox": {
    "enabled": true,
    "network": {
      "allowedDomains": ["<target-ip-or-hostname-from-scope.json>"],
      "strictAllowlist": true
    },
    "filesystem": {
      "allowWrite": ["~/.claude/sessions"]
    },
    "excludedCommands": ["docker *"]
  }
}
```

- **`network.allowedDomains`**: populate from the engagement's `scope.json` `targets.in_scope` list - one entry per host (see the CIDR limitation above). Verify per-entry against the "not explicitly confirmed" point before trusting it for IP-shaped targets.
- **`network.strictAllowlist: true`**: denies sandboxed commands access to anything outside the allowlist instead of prompting - matches Clicky's Track 2 posture of "blocked, not flagged" as the default stance.
- **`filesystem.allowWrite`**: Clicky writes session data under `~/.claude/sessions` (or wherever `default_session_directory` points), which needs to be writable in addition to the working directory the sandbox already allows by default.
- **`excludedCommands: ["docker *"]`**: only needed if you personally run `docker` directly in this session, outside of Clicky's own dispatch - Clicky's own container-security testing (see below) never touches the sandboxed `Bash` tool in the first place, so this carve-out doesn't affect it either way.

## Known limitations for Clicky specifically

**`docker` is entirely incompatible with the sandbox** (confirmed in Claude Code's own troubleshooting docs: "`docker` commands fail: `docker` is incompatible with the sandbox"). This mattered when `skills/container-security/SKILL.md`'s Docker API/escape checks still ran via a directly-granted `Bash` tool and needed an `excludedCommands: ["docker *"]` carve-out to work under an enabled sandbox. Now that container-security testing, like every other agent action, is dispatched via the gateway's `execute_command` instead, it never touches the sandboxed `Bash` tool at all - so this incompatibility, and the carve-out it used to require, are both moot for Clicky's own testing specifically. See the next point for why.

**Hooks and MCP servers run unconstrained regardless of `sandbox.enabled` - this is the actual reason the sandbox no longer covers Clicky's own engagement traffic (see the top of this page).** The sandbox covers the Bash tool and its child processes only. Clicky's own hooks (the `SessionStart` venv provisioner, the `Stop`-hook recovery loop) and the `clicky-gateway` MCP server - including everything `execute_command` shells out to on an agent's or the `/pentest` command's behalf, its scope check, and its own trace logging - all run outside the sandbox boundary no matter what. This is an acceptable trade-off for Clicky's threat model (these are small, reviewable shell/Python scripts shipped with the plugin, not arbitrary third-party code) but is a real, stated limitation, not something to gloss over.

**Network filtering doesn't inspect TLS by default.** The sandbox's proxy makes allow/deny decisions from the client-supplied hostname without decrypting traffic, so a sufficiently adversarial payload running inside the sandbox could in principle attempt domain fronting against an over-broad `allowedDomains` entry. Keep your allowlist to the actual in-scope target(s), not broad wildcards, for this reason as well as the CIDR one above.

## Where the operator sees this

`commands/pentest.md` Step 1 prints a reminder pointing at this document, with the resolved engagement target(s) substituted in, once `scope.json` is available - a nudge, not an automated settings write. Clicky never modifies your `settings.json` on its own. Per the correction at the top of this page: that reminder is about optional protection for *other* Bash usage in the same session, not about `execute_command` itself, which (per "Known limitations" above) runs outside the sandbox boundary regardless of whether you enable it.
