---
name: archive
description: Archive a completed pentest session, moving it out of the active session list
argument-hint: "<session_id>"
arguments: [session_id]
disable-model-invocation: true
allowed-tools: Bash(mkdir:*), Bash(ls:*), Bash(cat:*), Bash(echo:*), Bash(grep:*), Bash(find:*), Bash(head:*), Bash(tail:*), Bash(mv:*), Read(*), Write(*), Grep(*)
model: sonnet
---

# Archive Pentest Session

Session ID: **$session_id**

```bash
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/session-manager.sh archive "$session_id"
```

This moves the whole session directory under `archived/`, sets `status: "completed"`/`phase: "archived"` in its `session.json`, and clears the `.current-session` pointer if it was pointing at this session (so the Stop-hook recovery loop, `pentest-recovery-hook.sh`, stops checking a now-archived/moved session for completion).

`disable-model-invocation: true` here deliberately - archiving moves a directory and is more of a deliberate operator action than `/clicky:sessions`'s read-only status check, so it should only run on an explicit `/clicky:archive` invocation, not something Claude decides to do on its own judgment mid-conversation.

After archiving, the session no longer appears in `/clicky:sessions`' list output, but its status/findings remain fully accessible via `/clicky:sessions <session_id>`.
