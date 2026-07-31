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
scripts/session-manager.sh create "{target_ip}"

# Resume existing session
scripts/session-manager.sh resume "{session_id}"

# List all sessions
scripts/session-manager.sh list
```

### State Persistence
Track and persist agent states throughout the engagement:
```bash
# Record state changes
scripts/state-persistence.sh record "{session_id}" "{agent_name}" "{state_key}" "{state_value}"

# Retrieve state
scripts/state-persistence.sh get "{session_id}" "{agent_name}" "{state_key}"

# Export session state
scripts/state-persistence.sh export "{session_id}"
```

### Recovery Mechanisms
Handle failures and resume operations:
```bash
# Setup recovery hook
scripts/pentest-recovery-hook.sh install "{session_id}"

# Check recovery status
scripts/pentest-recovery-hook.sh status "{session_id}"

# Restore from checkpoint
scripts/pentest-recovery-hook.sh restore "{session_id}"
```

## Session Directory Structure

All sessions are organized under `$HOME/.claude/sessions/{session_id}/`:
```
{session_id}/
├── metadata.json       # Target info, timestamps, status
├── recon/             # Reconnaissance results
├── exploit/           # Exploitation attempts and results
├── privesc/           # Privilege escalation data
├── loot/              # Extracted credentials and files
├── reports/           # Generated reports
└── checkpoints/       # Recovery checkpoints
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

### Reading Session Data
```bash
# Get current session ID
SESSION_ID=$(scripts/session-manager.sh current)

# Read session metadata
SESSION_DIR="$HOME/.claude/sessions/$SESSION_ID"
TARGET=$(jq -r .target "$SESSION_DIR/metadata.json")
```

### Writing Results
```bash
# Save reconnaissance results
echo "$scan_results" > "$SESSION_DIR/recon/nmap_scan.txt"

# Record important findings
scripts/state-persistence.sh record "$SESSION_ID" "recon-agent" "open_ports" "[21,22,80,443]"
```

### Coordinating Between Agents
```bash
# Check if another agent already completed a task
if scripts/state-persistence.sh get "$SESSION_ID" "*" "ftp_checked" | grep -q "true"; then
    echo "FTP already checked by another agent"
else
    # Perform FTP checks
    scripts/state-persistence.sh record "$SESSION_ID" "loot-agent" "ftp_checked" "true"
fi
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