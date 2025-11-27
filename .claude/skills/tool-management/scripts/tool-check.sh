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

        # Check if available via nix
        if command -v nix &> /dev/null; then
            if nix-shell -p $tool --run "which $tool" &> /dev/null; then
                echo -e "    ${BLUE}↳ Available via: nix-shell -p $tool${NC}"
            fi
        fi

        # Suggest installation
        suggest_install $tool
        return 1
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

cat > "$INVENTORY_FILE" << EOF
{
  "timestamp": $(date +%s),
  "environment": {
    "os": "$OS",
    "distro": "$DISTRO",
    "package_manager": "$PKG_MGR",
    "nix_available": $(command -v nix &> /dev/null && echo "true" || echo "false"),
    "docker_available": $(command -v docker &> /dev/null && echo "true" || echo "false")
  },
  "tools": {
EOF

# Add tool status to JSON
first=true
for tool in nmap masscan gobuster feroxbuster dirb sqlmap hydra john hashcat smbclient enum4linux nc socat; do
    if [ "$first" = false ]; then
        echo "," >> "$INVENTORY_FILE"
    fi
    first=false

    if command -v $tool &> /dev/null; then
        echo -n "    \"$tool\": { \"available\": true, \"path\": \"$(which $tool)\" }" >> "$INVENTORY_FILE"
    else
        echo -n "    \"$tool\": { \"available\": false, \"path\": null }" >> "$INVENTORY_FILE"
    fi
done

cat >> "$INVENTORY_FILE" << EOF

  }
}
EOF

echo "  Tool inventory saved to: $INVENTORY_FILE"

# Run environment detection
detect_environment

echo -e "\n${GREEN}[✓] Tool check complete!${NC}"
echo "═══════════════════════════════════════════════════════════════"