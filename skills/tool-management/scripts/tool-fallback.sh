#!/bin/bash
#
# Tool Fallback Detection System
# Checks for tool availability and returns best alternative
#

set -euo pipefail

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Port scanning tool detection
get_port_scanner() {
    if command_exists nmap; then
        echo "nmap"
    elif command_exists masscan; then
        echo "masscan"
    elif command_exists rustscan; then
        echo "rustscan"
    elif command_exists zmap; then
        echo "zmap"
    elif command_exists nc; then
        echo "nc"
    else
        echo "none"
    fi
}

# Web enumeration tool detection
get_web_enumerator() {
    if command_exists gobuster; then
        echo "gobuster"
    elif command_exists ffuf; then
        echo "ffuf"
    elif command_exists dirb; then
        echo "dirb"
    elif command_exists dirbuster; then
        echo "dirbuster"
    elif command_exists wfuzz; then
        echo "wfuzz"
    else
        echo "none"
    fi
}

# SQL injection tool detection
get_sqli_tool() {
    if command_exists sqlmap; then
        echo "sqlmap"
    elif command_exists sqlninja; then
        echo "sqlninja"
    else
        echo "manual"
    fi
}

# Password attack tool detection
get_password_tool() {
    if command_exists hydra; then
        echo "hydra"
    elif command_exists medusa; then
        echo "medusa"
    elif command_exists ncrack; then
        echo "ncrack"
    elif command_exists patator; then
        echo "patator"
    else
        echo "none"
    fi
}

# SMB enumeration tool detection
get_smb_tool() {
    if command_exists enum4linux; then
        echo "enum4linux"
    elif command_exists smbclient; then
        echo "smbclient"
    elif command_exists crackmapexec; then
        echo "crackmapexec"
    elif command_exists smbmap; then
        echo "smbmap"
    else
        echo "none"
    fi
}

# Exploitation framework detection
get_exploit_framework() {
    if command_exists msfconsole; then
        echo "metasploit"
    elif [ -d "/usr/share/exploitdb" ]; then
        echo "exploitdb"
    else
        echo "manual"
    fi
}

# Get fallback command for specific tool
get_fallback_command() {
    local tool_type="$1"
    local target="${2:-}"
    local port="${3:-}"

    case "$tool_type" in
        port_scan)
            local scanner=$(get_port_scanner)
            case "$scanner" in
                nmap)
                    echo "nmap -sC -sV -Pn $target"
                    ;;
                masscan)
                    echo "masscan -p1-65535 $target --rate=1000"
                    ;;
                rustscan)
                    echo "rustscan -a $target --ulimit 5000 -- -sV"
                    ;;
                zmap)
                    echo "zmap -p 80,443,22,21,445,3306,3389 $target"
                    ;;
                nc)
                    echo "for p in 21 22 80 443 445 3306 3389; do nc -zv $target \$p 2>&1 | grep succeeded; done"
                    ;;
                *)
                    echo "echo 'No port scanner available'"
                    ;;
            esac
            ;;

        web_enum)
            local enumerator=$(get_web_enumerator)
            case "$enumerator" in
                gobuster)
                    echo "gobuster dir -u http://$target -w /usr/share/wordlists/dirb/common.txt"
                    ;;
                ffuf)
                    echo "ffuf -u http://$target/FUZZ -w /usr/share/wordlists/dirb/common.txt"
                    ;;
                dirb)
                    echo "dirb http://$target /usr/share/wordlists/dirb/common.txt"
                    ;;
                *)
                    echo "echo 'No web enumerator available'"
                    ;;
            esac
            ;;

        smb_enum)
            local smb_tool=$(get_smb_tool)
            case "$smb_tool" in
                enum4linux)
                    echo "enum4linux -a $target"
                    ;;
                smbclient)
                    echo "smbclient -L //$target -N"
                    ;;
                crackmapexec)
                    echo "crackmapexec smb $target -u '' -p ''"
                    ;;
                smbmap)
                    echo "smbmap -H $target"
                    ;;
                *)
                    echo "echo 'No SMB enumeration tool available'"
                    ;;
            esac
            ;;

        sqli)
            local sqli_tool=$(get_sqli_tool)
            case "$sqli_tool" in
                sqlmap)
                    echo "sqlmap -u \"$target\" --batch --dbs"
                    ;;
                sqlninja)
                    echo "sqlninja -m t -t $target"
                    ;;
                *)
                    echo "echo 'No automated SQL injection tool available - manual testing required'"
                    ;;
            esac
            ;;

        password)
            local password_tool=$(get_password_tool)
            case "$password_tool" in
                hydra)
                    echo "hydra -L users.txt -P passwords.txt $target"
                    ;;
                medusa)
                    echo "medusa -h $target -U users.txt -P passwords.txt"
                    ;;
                ncrack)
                    echo "ncrack -U users.txt -P passwords.txt $target"
                    ;;
                patator)
                    echo "patator ssh_login host=$target user=FILE0 password=FILE1 0=users.txt 1=passwords.txt"
                    ;;
                *)
                    echo "echo 'No password attack tool available'"
                    ;;
            esac
            ;;

        *)
            echo "echo 'Unknown tool type: $tool_type'"
            ;;
    esac
}

# Main function
main() {
    local action="${1:-list}"

    case "$action" in
        list)
            echo "=== Available Tools ==="
            echo "Port Scanner: $(get_port_scanner)"
            echo "Web Enumerator: $(get_web_enumerator)"
            echo "SQL Injection: $(get_sqli_tool)"
            echo "Password Attack: $(get_password_tool)"
            echo "SMB Enumeration: $(get_smb_tool)"
            echo "Exploit Framework: $(get_exploit_framework)"
            ;;

        get)
            local tool_type="${2:-}"
            local target="${3:-}"
            local port="${4:-}"
            get_fallback_command "$tool_type" "$target" "$port"
            ;;

        *)
            # Bare tool-name mode: tool-fallback.sh <tool-name>
            # Looks up which category the requested tool belongs to and
            # returns the best available option in that category: the
            # requested tool itself if it's installed, otherwise the best
            # detected fallback tool name (e.g. "sqlninja", "medusa"), or
            # "none"/"manual" if nothing usable is found. This mirrors what
            # the agent files call before invoking a possibly-missing tool
            # (e.g. sqlmap, hydra, gobuster) - no target argument required,
            # since only a tool name (not a fallback command line) is
            # returned. Use `get <tool_type> <target> [port]` instead when
            # a ready-to-run fallback command is needed.
            local tool_name="$action"
            local tool_category=""

            case "$tool_name" in
                sqlmap|sqlninja)
                    tool_category="sqli"
                    ;;
                hydra|medusa|ncrack|patator)
                    tool_category="password"
                    ;;
                gobuster|ffuf|dirb|dirbuster|wfuzz)
                    tool_category="web_enum"
                    ;;
                nmap|masscan|rustscan|zmap)
                    tool_category="port_scan"
                    ;;
                enum4linux|smbclient|crackmapexec|smbmap)
                    tool_category="smb_enum"
                    ;;
                msfconsole)
                    tool_category="exploit"
                    ;;
            esac

            if command_exists "$tool_name"; then
                echo "$tool_name"
            elif [ -n "$tool_category" ]; then
                case "$tool_category" in
                    sqli)      get_sqli_tool ;;
                    password)  get_password_tool ;;
                    web_enum)  get_web_enumerator ;;
                    port_scan) get_port_scanner ;;
                    smb_enum)  get_smb_tool ;;
                    exploit)   get_exploit_framework ;;
                esac
            else
                echo "none"
            fi
            ;;
    esac
}

# Only run main if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi