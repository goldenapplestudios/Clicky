#!/bin/bash
#
# Enhanced Environment Detection for Adaptive Pentesting
# Detects OS, package managers, containers, and available tools
#

set -euo pipefail

ENV_CACHE_FILE="$HOME/.claude/cache/environment.json"
TOOL_REGISTRY_FILE="$HOME/.claude/cache/tool-registry.json"

# Initialize cache directory
init_cache() {
    mkdir -p "$(dirname "$ENV_CACHE_FILE")"
    mkdir -p "$(dirname "$TOOL_REGISTRY_FILE")"
}

# Detect operating system and distribution
detect_os() {
    local os="unknown"
    local distro="unknown"
    local version="unknown"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        os="$ID"
        distro="$NAME"
        version="$VERSION_ID"
    elif [ "$(uname)" = "Darwin" ]; then
        os="macos"
        distro="macOS"
        version=$(sw_vers -productVersion)
    elif [ "$(uname)" = "Linux" ]; then
        os="linux"
        if [ -f /etc/debian_version ]; then
            distro="debian-based"
            version=$(cat /etc/debian_version)
        elif [ -f /etc/redhat-release ]; then
            distro="redhat-based"
            version=$(cat /etc/redhat-release | grep -oP '\d+\.\d+')
        fi
    fi

    echo "{\"os\": \"$os\", \"distro\": \"$distro\", \"version\": \"$version\"}"
}

# Detect package managers
detect_package_managers() {
    local managers=()

    # Check common package managers
    command -v apt >/dev/null 2>&1 && managers+=("apt")
    command -v yum >/dev/null 2>&1 && managers+=("yum")
    command -v dnf >/dev/null 2>&1 && managers+=("dnf")
    command -v pacman >/dev/null 2>&1 && managers+=("pacman")
    command -v brew >/dev/null 2>&1 && managers+=("brew")
    command -v snap >/dev/null 2>&1 && managers+=("snap")
    command -v flatpak >/dev/null 2>&1 && managers+=("flatpak")
    command -v nix >/dev/null 2>&1 && managers+=("nix")
    command -v pip >/dev/null 2>&1 && managers+=("pip")
    command -v npm >/dev/null 2>&1 && managers+=("npm")
    command -v cargo >/dev/null 2>&1 && managers+=("cargo")
    command -v gem >/dev/null 2>&1 && managers+=("gem")

    printf '%s\n' "${managers[@]}" | jq -Rs 'split("\n") | map(select(. != ""))'
}

# Detect container/virtualization environment
detect_container() {
    local container_type="none"
    local in_container=false

    # Docker detection
    if [ -f /.dockerenv ]; then
        container_type="docker"
        in_container=true
    elif [ -f /run/.containerenv ]; then
        container_type="podman"
        in_container=true
    elif grep -q "docker\|containerd" /proc/1/cgroup 2>/dev/null; then
        container_type="docker"
        in_container=true
    fi

    # Kubernetes detection
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        container_type="kubernetes"
        in_container=true
    fi

    # LXC/LXD detection
    if [ -f /proc/1/environ ] && grep -q "container=lxc" /proc/1/environ 2>/dev/null; then
        container_type="lxc"
        in_container=true
    fi

    # WSL detection
    if grep -qi microsoft /proc/version 2>/dev/null; then
        container_type="wsl"
    fi

    # VM detection
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt=$(systemd-detect-virt)
        if [ "$virt" != "none" ]; then
            container_type="vm:$virt"
        fi
    fi

    echo "{\"in_container\": $in_container, \"type\": \"$container_type\"}"
}

# Detect available pentest tools
detect_pentest_tools() {
    local tools={}

    # Network tools
    local network_tools=("nmap" "masscan" "rustscan" "zmap" "netcat" "nc" "socat" "tcpdump" "wireshark")
    for tool in "${network_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$(get_tool_version "$tool")
            tools=$(echo "$tools" | jq --arg t "$tool" --arg v "$version" \
                '.network[$t] = {"available": true, "version": $v, "path": "'$(which $tool)'"}')
        fi
    done

    # Web tools
    local web_tools=("gobuster" "dirbuster" "ffuf" "wfuzz" "nikto" "burpsuite" "zaproxy" "sqlmap")
    for tool in "${web_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$(get_tool_version "$tool")
            tools=$(echo "$tools" | jq --arg t "$tool" --arg v "$version" \
                '.web[$t] = {"available": true, "version": $v, "path": "'$(which $tool)'"}')
        fi
    done

    # Exploitation tools
    local exploit_tools=("metasploit" "msfconsole" "searchsploit" "empire" "covenant" "crackmapexec")
    for tool in "${exploit_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$(get_tool_version "$tool")
            tools=$(echo "$tools" | jq --arg t "$tool" --arg v "$version" \
                '.exploitation[$t] = {"available": true, "version": $v, "path": "'$(which $tool)'"}')
        fi
    done

    # Password tools
    local password_tools=("john" "hashcat" "hydra" "medusa" "crowbar" "patator")
    for tool in "${password_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$(get_tool_version "$tool")
            tools=$(echo "$tools" | jq --arg t "$tool" --arg v "$version" \
                '.password[$t] = {"available": true, "version": $v, "path": "'$(which $tool)'"}')
        fi
    done

    # Cloud tools
    local cloud_tools=("aws" "az" "gcloud" "kubectl" "docker" "terraform" "ansible")
    for tool in "${cloud_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$(get_tool_version "$tool")
            tools=$(echo "$tools" | jq --arg t "$tool" --arg v "$version" \
                '.cloud[$t] = {"available": true, "version": $v, "path": "'$(which $tool)'"}')
        fi
    done

    echo "$tools"
}

# Get tool version
get_tool_version() {
    local tool="$1"
    local version="unknown"

    case "$tool" in
        nmap|masscan|john|hashcat|hydra|metasploit|msfconsole)
            version=$($tool --version 2>/dev/null | head -1 || echo "unknown")
            ;;
        aws|az|gcloud|kubectl|docker|terraform)
            version=$($tool version 2>/dev/null | head -1 || $tool --version 2>/dev/null | head -1 || echo "unknown")
            ;;
        *)
            version=$($tool -v 2>/dev/null || $tool --version 2>/dev/null || $tool -V 2>/dev/null || echo "unknown")
            ;;
    esac

    echo "$version"
}

# Register custom tool
register_custom_tool() {
    local name="$1"
    local path="$2"
    local category="${3:-custom}"
    local description="${4:-Custom tool}"

    if [ ! -f "$TOOL_REGISTRY_FILE" ]; then
        echo '{"custom_tools": {}}' > "$TOOL_REGISTRY_FILE"
    fi

    # Check if tool exists
    if [ ! -x "$path" ]; then
        echo "Error: Tool $path is not executable"
        return 1
    fi

    # Add to registry
    jq --arg name "$name" \
       --arg path "$path" \
       --arg cat "$category" \
       --arg desc "$description" \
       --arg ts "$(date +%s)" \
       '.custom_tools[$name] = {
           "path": $path,
           "category": $cat,
           "description": $desc,
           "registered_at": $ts
       }' "$TOOL_REGISTRY_FILE" > "$TOOL_REGISTRY_FILE.tmp" && \
    mv "$TOOL_REGISTRY_FILE.tmp" "$TOOL_REGISTRY_FILE"

    echo "Custom tool '$name' registered successfully"
}

# Get custom tools
get_custom_tools() {
    if [ -f "$TOOL_REGISTRY_FILE" ]; then
        jq '.custom_tools' "$TOOL_REGISTRY_FILE"
    else
        echo '{}'
    fi
}

# Generate full environment report
generate_environment_report() {
    init_cache

    local os_info=$(detect_os)
    local pkg_managers=$(detect_package_managers)
    local container_info=$(detect_container)
    local tools=$(detect_pentest_tools)
    local custom_tools=$(get_custom_tools)

    # Build comprehensive report
    local report=$(jq -n \
        --argjson os "$os_info" \
        --argjson pkg "$pkg_managers" \
        --argjson cont "$container_info" \
        --argjson tools "$tools" \
        --argjson custom "$custom_tools" \
        --arg ts "$(date +%s)" \
        '{
            "timestamp": $ts,
            "system": $os,
            "package_managers": $pkg,
            "container": $cont,
            "available_tools": $tools,
            "custom_tools": $custom,
            "shell": {"type": "'$SHELL'", "version": "'$BASH_VERSION'"}
        }')

    # Cache the report
    echo "$report" > "$ENV_CACHE_FILE"

    echo "$report"
}

# Main function
main() {
    local action="${1:-detect}"

    case "$action" in
        detect)
            generate_environment_report
            ;;
        os)
            detect_os
            ;;
        packages)
            detect_package_managers
            ;;
        container)
            detect_container
            ;;
        tools)
            detect_pentest_tools
            ;;
        register)
            register_custom_tool "$2" "$3" "${4:-custom}" "${5:-}"
            ;;
        custom)
            get_custom_tools
            ;;
        *)
            echo "Usage: $0 {detect|os|packages|container|tools|register|custom}"
            exit 1
            ;;
    esac
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi