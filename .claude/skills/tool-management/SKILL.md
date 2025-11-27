---
name: tool-management
description: Tool availability checking and fallback management for penetration testing environments
allowed-tools: Bash, Read, Write
---

# Tool Management Skill

## Purpose
Provides tool availability checking and fallback mechanisms to ensure penetration testing can proceed even when preferred tools are unavailable, with intelligent alternatives and workarounds.

## Tool Availability Checking

The skill includes scripts for:
- Checking which penetration testing tools are installed
- Suggesting alternatives when tools are missing
- Providing fallback commands for common operations
- Detecting the environment (Kali, Parrot, Ubuntu, etc.)

## Scripts

### tool-check.sh
Comprehensive tool availability checker that scans for all common penetration testing tools and reports their status.

### tool-fallback.sh
Provides fallback commands and alternatives when primary tools are unavailable.

## Usage

### Check Tool Availability
```bash
~/.claude/skills/tool-management/scripts/tool-check.sh
```

### Get Fallback Commands
```bash
~/.claude/skills/tool-management/scripts/tool-fallback.sh <tool-name>
```

## Integration Notes

- Used by all agents to verify tool availability before operations
- Provides graceful degradation when tools are missing
- Essential for cross-platform penetration testing