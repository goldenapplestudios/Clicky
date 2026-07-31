---
name: session-management
description: Manages penetration testing sessions including state persistence, recovery, and session tracking across all agents
allowed-tools: Bash, Read, Write
---

# Session Management Skill

## Purpose
Provides comprehensive session management for penetration testing workflows, ensuring state persistence, crash recovery, and coordinated tracking across multiple agents.

## Core Functionality

### Session Initialization
Execute session creation for new targets:
```bash
# Create new session - returns SESSION_ID
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/session-manager.sh create "{target_ip}"

# Resume existing session
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/session-manager.sh resume "{session_id}"

# List all sessions
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/session-manager.sh list
```

### State Persistence
Track and persist agent states throughout the engagement - see "Integration with Agents" below for the full store/check-failed/record pattern agents actually use:
```bash
# Record an attempt's outcome (technique, description, success true/false)
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/state-persistence.sh record \
  "$SESSION_ID" "ftp" "anonymous_login" "no credentials found" false

# Check whether a technique already failed, before repeating it
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/state-persistence.sh check-failed "ftp" "anonymous_login"

# Get a session-wide summary of everything recorded so far
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/state-persistence.sh summary "$SESSION_ID"
```

### Recovery Mechanisms
The `Stop` hook (`hooks/hooks.json`) already runs `pentest-recovery-hook.sh` automatically with no arguments (defaults to its `check` action) whenever a session stops - you don't normally invoke this directly. Its real subcommands, for reference:
```bash
# Activate recovery mode after a failure
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/pentest-recovery-hook.sh init "{target}" "{failure_type}"

# Check recovery status and execute the next strategy (what the Stop hook calls automatically)
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/pentest-recovery-hook.sh check

# Deactivate recovery mode
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/pentest-recovery-hook.sh stop
```

## Session Directory Structure

All sessions are organized under `$HOME/.claude/sessions/{session_id}/` (or wherever the `default_session_directory` userConfig option points):
```
{session_id}/
├── session.json        # Target info, timestamps, status (not metadata.json)
├── recon/              # Reconnaissance results
├── exploits/           # Exploitation attempts and results
├── loot/                # Extracted credentials and files
├── reports/             # Generated reports, including reports/findings.json
├── credentials/         # Harvested usernames/passwords/hashes
└── logs/                # Error and hook logs, e.g. logs/scope-enforcement.log
```

## Usage Instructions

### For New Engagements
1. Always create a session before starting reconnaissance
2. Export SESSION_ID environment variable for all subsequent operations
3. Ensure all agents use the same SESSION_ID

### For Agent Coordination
1. Each agent should record its state when starting/completing tasks
2. Check for existing state before performing duplicate work
3. Use state persistence to pass data between agents

### For Recovery
1. Install recovery hooks at session start
2. Create checkpoints before risky operations
3. Use restore function if operations fail

## State Keys Convention

Use standardized state keys for consistency:
- `recon_complete`: Boolean indicating reconnaissance status
- `services_found`: JSON array of discovered services
- `credentials`: JSON object of discovered credentials
- `exploits_tried`: Array of attempted exploits
- `access_level`: Current access (none/user/root)
- `persistence_installed`: Boolean for persistence status

## Integration with Agents

`$SESSION_ID`/`$SESSION_DIR` are set earlier in the workflow (`commands/pentest.md` Step 1 exports them via `session-manager.sh create`) — there's no "get the current session" lookup, use the values already in the environment.

### Reading Session Data
```bash
# Read session metadata (the file is session.json, not metadata.json)
TARGET=$(jq -r .target "$SESSION_DIR/session.json")
```

### Writing Results
```bash
# Save reconnaissance results
echo "$scan_results" > "$SESSION_DIR/recon/nmap_scan.txt"

# Record a discovery for other agents to pick up (store/get-unused, not
# record - record is specifically for attack attempts, see below)
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/state-persistence.sh store \
  "services" '{"open_ports":[21,22,80,443]}' "$SESSION_ID"
```

### Coordinating Between Agents
```bash
# Check if a technique already failed (for a previous agent or a previous
# turn) before repeating it - there's no general "already checked" flag,
# but check-failed covers the common case of not repeating known failures
if ${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/state-persistence.sh check-failed "ftp" "anonymous_login"; then
    echo "Proceeding - no prior failed attempt recorded for this technique"
else
    echo "FTP anonymous login already failed in this session - skip or try a different technique"
fi

# After actually attempting something, record the outcome so later agents
# benefit from this check
${CLAUDE_PLUGIN_ROOT}/skills/session-management/scripts/state-persistence.sh record \
  "$SESSION_ID" "ftp" "anonymous_login" "no credentials found" false
```

## Error Handling

All session management scripts follow these conventions:
- Return 0 on success, non-zero on failure
- Output JSON for structured data
- Log errors to `$SESSION_DIR/errors.log`
- Create automatic backups before modifications

## Best Practices

1. **One Session Per Target**: Don't mix multiple targets in one session
2. **Regular Checkpoints**: Create checkpoints after major milestones
3. **Clean Session Data**: Remove sensitive data after engagement completion
4. **Session Documentation**: Update metadata.json with important discoveries
5. **Timestamp Everything**: All state changes should include timestamps

## Performance Considerations

- Sessions are lightweight JSON/text files
- State queries are optimized for fast lookup
- Checkpoints use incremental backups
- Old sessions can be archived to maintain performance

## Security Notes

- Session data may contain sensitive information
- Ensure proper file permissions (600) on session directories
- Clean up sessions after authorized testing completes
- Never commit session data to version control