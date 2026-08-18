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
${CLAUDE_PLUGIN_ROOT}/skills/tool-management/scripts/tool-check.sh
```

### Get Fallback Commands

Bare tool-name mode - resolves a specific tool to the best available option in
its category (the tool itself if installed, otherwise the best detected
fallback tool name, or `none`/`manual` if nothing is available). This is the
form agents use before invoking a possibly-missing tool; no target is needed
since it returns a tool name, not a ready-to-run command:
```bash
${CLAUDE_PLUGIN_ROOT}/skills/tool-management/scripts/tool-fallback.sh <tool-name>
# e.g. tool-fallback.sh sqlmap  ->  sqlmap | sqlninja | manual
# e.g. tool-fallback.sh hydra   ->  hydra | medusa | ncrack | patator | none
```
Recognized tool names: `sqlmap`/`sqlninja` (sqli), `hydra`/`medusa`/`ncrack`/`patator`
(password), `gobuster`/`ffuf`/`dirb`/`dirbuster`/`wfuzz` (web_enum),
`nmap`/`masscan`/`rustscan`/`zmap` (port_scan), `enum4linux`/`smbclient`/`crackmapexec`/`smbmap`
(smb_enum), `msfconsole` (exploit). An unrecognized name is still checked
against `$PATH` and returns `none` if not found.

Category mode - resolves a tool category to a ready-to-run fallback command
line for a given target:
```bash
${CLAUDE_PLUGIN_ROOT}/skills/tool-management/scripts/tool-fallback.sh get <tool_type> <target> [port]
# tool_type: port_scan | web_enum | smb_enum | sqli | password
```

### List All Detected Tools
```bash
${CLAUDE_PLUGIN_ROOT}/skills/tool-management/scripts/tool-fallback.sh list
```

## Integration Notes

- Used by all agents to verify tool availability before operations
- Provides graceful degradation when tools are missing
- Essential for cross-platform penetration testing