# Clicky and the Sandboxed Bash Tool

> **Navigation**: [Usage](usage.md) | [Architecture](architecture.md) | [Agents](agents.md) | [Workflow](workflow.md) | [Skills](skills.md) | [Observability](observability.md) | [Sandboxing](sandboxing.md) | [README](../README.md)

---

Claude Code has a built-in sandboxed Bash tool (Seatbelt on macOS, bubblewrap on Linux/WSL2) that restricts what a Bash command and its child processes can read, write, and reach over the network - enforced at the OS level, not just by Claude choosing not to run something. This is documented in full at [code.claude.com/docs/en/sandboxing](https://code.claude.com/docs/en/sandboxing); this page covers what's specific to using it with Clicky.

**This is opt-in defense-in-depth on top of Clicky's own scope enforcement, not a replacement for it.** The primary, always-on scope gate is the `PreToolUse` hook described in `skills/target-validation/SKILL.md` ("Automatic Scope Enforcement") - it's plugin-owned, on by default, and understands Clicky's `scope.json`. The sandbox lives entirely in Claude Code's own `settings.json`, outside anything `plugin.json` can control, and (see the finding below) has real limits for IP-based pentest targets specifically. Clicky does not - and should not - write to your global Claude Code settings automatically; enabling the sandbox is your call.

## Step 0 finding: does the network allowlist support IP addresses or CIDR ranges?

This was the open question before writing this doc, since most pentest targets (HTB-style boxes, internal engagements) are raw IPs, not hostnames. Verified against Claude Code's authoritative settings reference (`code.claude.com/docs/en/settings`), not assumed:

> `network.allowedDomains` — Array of **domains** to allow for outbound network traffic. Supports wildcards (e.g., `*.example.com`). Example: `["github.com", "*.npmjs.org"]`

And from the sandboxing page itself: "The built-in proxy enforces the allowlist based on the **requested hostname**."

**Confirmed: no CIDR or IP-range syntax exists anywhere in the documentation.** Every documented example is a domain name; the only supported pattern beyond an exact string is a `*.` prefix wildcard. There is no `10.10.10.0/24`-style entry and no indication one is planned.

**Not explicitly confirmed either way: whether a single literal IP address (e.g. `"10.10.10.10"`) works as an exact-match entry.** The matching logic is described as hostname-based, and an IP-shaped HTTP/CONNECT request's "hostname" is literally the IP string, so a literal IP entry plausibly works as an exact match the same way `"github.com"` does - but no documentation example, positive or negative, addresses this directly. This session did not empirically test it live: doing so would mean flipping `sandbox.enabled: true` in your real Claude Code settings, which is a user-facing environment change Clicky won't make on its own initiative. **If you rely on this, verify it yourself first** - `/sandbox` in a scratch session, add a single target IP to `allowedDomains`, and confirm a request to it succeeds while an unlisted IP is blocked or prompts.

### Practical implication

Because there's no CIDR support, a `/24`-style engagement scope can't be expressed as one allowlist entry - you'd need one exact-match entry per live host, added as you discover them, which is workable but manual. For a single-target engagement (the common case), listing that one IP (if the "not explicitly confirmed" point above holds up in your own test) or the target's hostname (if it has one) is straightforward. For hostname-based engagements the wildcard support (`*.example.com`) covers a lot more ground with a lot less maintenance. Track 2's `PreToolUse` hook (`scope-enforcement-hook.sh`) doesn't have this limitation - it reads `scope.json` directly and already handles CIDR, IP ranges, and wildcards via `scope-validator.sh` - which is exactly why it's the primary gate and this is framed as defense-in-depth on top, not the other way around.

## Recommended configuration

If you choose to enable the sandbox for pentest work, a reasonable starting point in `~/.claude/settings.json`:

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
- **`excludedCommands: ["docker *"]`**: required if you do any container-security testing - see below.

## Known limitations for Clicky specifically

**`docker` is entirely incompatible with the sandbox** (confirmed in Claude Code's own troubleshooting docs: "`docker` commands fail: `docker` is incompatible with the sandbox"). `skills/container-security/SKILL.md`'s Docker API/escape checks need the `excludedCommands: ["docker *"]` carve-out above, which means **container-security testing runs fully unsandboxed** whenever that exclusion is active - the sandbox provides no protection for that portion of an engagement. If full sandboxing is a hard requirement, run container-security testing in a separate, explicitly-unsandboxed, extra-scrutiny session instead of quietly carving out an exception in your main one.

**Hooks and MCP servers run unconstrained regardless of `sandbox.enabled`.** The sandbox covers the Bash tool and its child processes only. Clicky's own `PreToolUse` scope-enforcement hook, the trace-logger hooks, and any MCP server all run outside the sandbox boundary no matter what. This is an acceptable trade-off for Clicky's threat model (these are small, reviewable shell/Python scripts shipped with the plugin, not arbitrary third-party code) but is a real, stated limitation, not something to gloss over.

**Network filtering doesn't inspect TLS by default.** The sandbox's proxy makes allow/deny decisions from the client-supplied hostname without decrypting traffic, so a sufficiently adversarial payload running inside the sandbox could in principle attempt domain fronting against an over-broad `allowedDomains` entry. Keep your allowlist to the actual in-scope target(s), not broad wildcards, for this reason as well as the CIDR one above.

## Where the operator sees this

`commands/pentest.md` Step 1 prints a reminder pointing at this document, with the resolved engagement target(s) substituted in, once `scope.json` is available - a nudge, not an automated settings write. Clicky never modifies your `settings.json` on its own.
