#!/bin/bash

# Tool Availability Checker for Pentest Workflow
# This script checks for required tools and suggests alternatives

echo "═══════════════════════════════════════════════════════════════"
echo "           PENETRATION TESTING TOOL AVAILABILITY CHECK         "
echo "═══════════════════════════════════════════════════════════════"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Environment detection
detect_environment() {
    echo -e "\n${BLUE}[*] Detecting Environment...${NC}"

    # OS Detection
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="Linux"
        if grep -q "kali" /etc/os-release 2>/dev/null; then
            DISTRO="Kali"
        elif grep -q "parrot" /etc/os-release 2>/dev/null; then
            DISTRO="Parrot"
        elif grep -q "ubuntu" /etc/os-release 2>/dev/null; then
            DISTRO="Ubuntu"
        else
            DISTRO="Generic Linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macOS"
        DISTRO="macOS"
    else
        OS="Unknown"
        DISTRO="Unknown"
    fi

    echo "  OS: $OS"
    echo "  Distribution: $DISTRO"

    # Package manager detection
    if command -v apt &> /dev/null; then
        PKG_MGR="apt"
    elif command -v yum &> /dev/null; then
        PKG_MGR="yum"
    elif command -v pacman &> /dev/null; then
        PKG_MGR="pacman"
    elif command -v brew &> /dev/null; then
        PKG_MGR="brew"
    else
        PKG_MGR="none"
    fi
    echo "  Package Manager: $PKG_MGR"

    # Nix detection
    if command -v nix &> /dev/null; then
        echo -e "  ${GREEN}Nix: Available${NC}"
        if nix flake --version &> /dev/null; then
            echo -e "  ${GREEN}Nix Flakes: Available${NC}"
        fi
    else
        echo -e "  ${YELLOW}Nix: Not Available${NC}"
    fi

    # Docker detection
    if command -v docker &> /dev/null; then
        echo -e "  ${GREEN}Docker: Available${NC}"
    else
        echo -e "  ${YELLOW}Docker: Not Available${NC}"
    fi
}

# Tool checking function
check_tool() {
    local tool=$1
    local category=$2
    local alternatives=$3

    if command -v $tool &> /dev/null; then
        version=$(get_version $tool)
        echo -e "  ${GREEN}✓${NC} $tool ${version}"
        return 0
    else
        echo -e "  ${RED}✗${NC} $tool - ${YELLOW}Alternatives: $alternatives${NC}"

        # Kalilix-aware hint, not a generic "try nix-shell -p" suggestion -
        # see the KALILIX_* variables set by check_kalilix() below, which
        # runs once at the top of this script's main flow. This replaces
        # what used to be a per-tool `nix-shell -p $tool --run "which
        # $tool"` probe (a real network/build call on every single
        # missing tool, one at a time) with a single up-front check of
        # whether Kalilix's curated, pinned 32-tool set is actually
        # enabled and covers this specific tool.
        if [ "$KALILIX_ENABLED" = "true" ]; then
            if printf '%s\n' "${KALILIX_TOOLS[@]}" | grep -qx "$tool"; then
                echo -e "    ${GREEN}↳ Provided by Kalilix (tool_provisioning=kalilix) - already available to agents via the gateway${NC}"
            else
                echo -e "    ${YELLOW}↳ Not part of Kalilix's 32-tool set either - see KALI_SHELL.md upstream${NC}"
            fi
        elif [ "$KALILIX_AVAILABLE" = "true" ] && printf '%s\n' "${KALILIX_TOOLS[@]}" | grep -qx "$tool"; then
            echo -e "    ${BLUE}↳ Available via Kalilix (github.com/scopecreep-zip/kalilix) - run tools/clicky-setup.sh to enable tool_provisioning=kalilix${NC}"
        elif command -v nix &> /dev/null; then
            echo -e "    ${BLUE}↳ Available via: nix-shell -p $tool${NC}"
        fi

        # Suggest installation
        suggest_install $tool
        return 1
    fi
}

# Kalilix awareness - run once, cheaply (no network/build calls), reused
# by every check_tool() call above instead of each one probing nix
# separately. Mirrors skills/mcp-gateway/scripts/launch.sh's own
# tool_provisioning read - see that file for why CLAUDE_PLUGIN_OPTION_*
# is the right variable to check (already normalized across all 4
# supported CLI hosts via ~/.clicky/config.json, not just Claude Code).
KALILIX_ENABLED="false"
KALILIX_AVAILABLE="false"
# The 32 tools Kalilix's #kali devShell provides, per its own KALI_SHELL.md
# (confirmed via the real upstream repo, not assumed) - kept as a flat
# list here since this script only needs "is $tool one of these," not
# the categorization KALI_SHELL.md organizes them by.
KALILIX_TOOLS=(
    ffuf gobuster dirb sqlmap nikto wpscan burpsuite
    nmap masscan nc socat
    john hashcat hydra medusa
    enum4linux enum4linux-ng
    dnsenum
    aircrack-ng
    theharvester whatweb recon-ng
    vol volatility2
    radare2 objdump strings binwalk
    metasploit
    wireshark tcpdump
    curl wget
)
check_kalilix() {
    if [ "${CLAUDE_PLUGIN_OPTION_TOOL_PROVISIONING:-none}" = "kalilix" ]; then
        KALILIX_ENABLED="true"
    fi
    if command -v nix &> /dev/null && nix registry list 2>/dev/null | grep -q "kalilix"; then
        KALILIX_AVAILABLE="true"
    fi
}

# Get tool version
get_version() {
    local tool=$1
    case $tool in
        nmap)
            nmap --version 2>/dev/null | head -1 | cut -d' ' -f3 | tr -d '()'
            ;;
        hydra)
            hydra -h 2>&1 | head -1 | cut -d' ' -f2
            ;;
        sqlmap)
            sqlmap --version 2>/dev/null | cut -d' ' -f2
            ;;
        *)
            echo ""
            ;;
    esac
}

# Suggest installation command
suggest_install() {
    local tool=$1
    case $PKG_MGR in
        apt)
            echo -e "    ${BLUE}↳ Install: sudo apt install $tool${NC}"
            ;;
        brew)
            echo -e "    ${BLUE}↳ Install: brew install $tool${NC}"
            ;;
        *)
            echo -e "    ${BLUE}↳ Install: Check package manager or use nix${NC}"
            ;;
    esac
}

# Environment detection runs first - it sets $OS/$DISTRO/$PKG_MGR, which
# the tool-inventory generation below reads. It used to run at the very
# end of this script instead, meaning the inventory's "environment" block
# was always written with those three fields empty (verified) - a plain
# ordering bug, not a logic error in detect_environment() itself.
detect_environment
check_kalilix

# Main checks
echo -e "\n${BLUE}[*] Checking Essential Tools...${NC}"
echo "═══════════════════════════════════════════════════════════════"

# Scanning Tools
echo -e "\n${YELLOW}Scanning Tools:${NC}"
check_tool "nmap" "scanning" "masscan, rustscan, zmap"
check_tool "masscan" "scanning" "nmap, rustscan"
check_tool "rustscan" "scanning" "nmap, masscan"

# Web Tools
echo -e "\n${YELLOW}Web Enumeration:${NC}"
check_tool "gobuster" "web" "feroxbuster, dirb, wfuzz"
check_tool "feroxbuster" "web" "gobuster, dirb"
check_tool "dirb" "web" "gobuster, feroxbuster"
check_tool "sqlmap" "web" "manual SQLi"
check_tool "nikto" "web" "wappalyzer, whatweb"

# Credential Tools
echo -e "\n${YELLOW}Credential Attacks:${NC}"
check_tool "hydra" "creds" "medusa, patator"
check_tool "john" "creds" "hashcat"
check_tool "hashcat" "creds" "john"

# SMB Tools
echo -e "\n${YELLOW}SMB/NetBIOS:${NC}"
check_tool "smbclient" "smb" "smbmap, cifs-utils"
check_tool "enum4linux" "smb" "smbmap, crackmapexec"
check_tool "smbmap" "smb" "enum4linux, smbclient"

# Exploitation
echo -e "\n${YELLOW}Exploitation:${NC}"
check_tool "msfconsole" "exploit" "manual exploits"
check_tool "searchsploit" "exploit" "Google, CVE databases"
check_tool "msfvenom" "exploit" "manual payloads"

# Networking
echo -e "\n${YELLOW}Networking:${NC}"
check_tool "nc" "network" "ncat, socat"
check_tool "socat" "network" "nc, ncat"
check_tool "proxychains" "network" "tsocks, redsocks"

# Summary
echo -e "\n═══════════════════════════════════════════════════════════════"
echo -e "${BLUE}[*] Tool Check Summary${NC}"

# Count available/missing
TOTAL_CHECKED=0
TOTAL_AVAILABLE=0

for tool in nmap gobuster hydra smbclient nc; do
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))
    if command -v $tool &> /dev/null; then
        TOTAL_AVAILABLE=$((TOTAL_AVAILABLE + 1))
    fi
done

echo "  Essential Tools: $TOTAL_AVAILABLE/$TOTAL_CHECKED available"

# Recommendations
echo -e "\n${BLUE}[*] Recommendations:${NC}"

if [ "$TOTAL_AVAILABLE" -lt "$TOTAL_CHECKED" ]; then
    echo "  1. Install missing essential tools"

    if ! command -v nix &> /dev/null; then
        echo "  2. Consider installing Nix for easy tool management:"
        echo "     curl -L https://nixos.org/nix/install | sh"
    fi

    echo "  3. Or use Docker containers for missing tools"
    echo "  4. Create a nix flake for reproducible environment:"
    echo "     nix flake init -t github:numtide/flake-utils"
else
    echo -e "  ${GREEN}✓ All essential tools are available${NC}"
fi

# Generate tool inventory file
echo -e "\n${BLUE}[*] Generating tool inventory...${NC}"
INVENTORY_FILE="$HOME/.claude/cache/tool_inventory.json"
mkdir -p "$(dirname "$INVENTORY_FILE")"

if command -v jq &> /dev/null; then
    # Built via jq -n/--arg throughout, not string-concatenated by hand -
    # the previous version spliced `$(which $tool)`'s raw output directly
    # into a hand-written JSON string with no escaping at all, so any tool
    # path containing a double quote or backslash would have produced a
    # corrupt tool_inventory.json (silently, since nothing here validated
    # the result).
    tools_json="{}"
    for tool in nmap masscan gobuster feroxbuster dirb sqlmap hydra john hashcat smbclient enum4linux nc socat; do
        if command -v "$tool" &> /dev/null; then
            tools_json=$(jq --arg t "$tool" --arg p "$(command -v "$tool")" \
                '.[$t] = {"available": true, "path": $p}' <<< "$tools_json")
        else
            tools_json=$(jq --arg t "$tool" '.[$t] = {"available": false, "path": null}' <<< "$tools_json")
        fi
    done

    jq -n --argjson ts "$(date +%s)" --arg os "$OS" --arg distro "$DISTRO" --arg pkgmgr "$PKG_MGR" \
        --argjson nix "$(command -v nix &> /dev/null && echo true || echo false)" \
        --argjson docker "$(command -v docker &> /dev/null && echo true || echo false)" \
        --argjson tools "$tools_json" \
        '{timestamp: $ts, environment: {os: $os, distro: $distro, package_manager: $pkgmgr,
          nix_available: $nix, docker_available: $docker}, tools: $tools}' \
        > "$INVENTORY_FILE"

    echo "  Tool inventory saved to: $INVENTORY_FILE"
else
    echo "  jq not found - skipping tool_inventory.json generation (the on-screen check above still ran)"
fi

echo -e "\n${GREEN}[✓] Tool check complete!${NC}"
echo "═══════════════════════════════════════════════════════════════"