#!/bin/bash
#
# Target Validation Script for Penetration Testing
# Ensures safe targets and prevents dangerous operations
#

set -euo pipefail

# Function to validate IP address format
validate_ip() {
    local ip=$1

    # Check basic format
    if ! echo "$ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        return 1
    fi

    # Check each octet
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [ "$octet" -gt 255 ] || [ "$octet" -lt 0 ]; then
            return 1
        fi
    done

    return 0
}

# Function to check if IP is dangerous
is_dangerous_ip() {
    local ip=$1

    # Localhost
    if [[ "$ip" =~ ^127\. ]] || [[ "$ip" == "0.0.0.0" ]]; then
        echo "ERROR: Cannot scan localhost"
        return 0
    fi

    # Cloud metadata services
    if [[ "$ip" == "169.254.169.254" ]]; then
        echo "ERROR: Cannot scan cloud metadata service"
        return 0
    fi

    # Link-local addresses
    if [[ "$ip" =~ ^169\.254\. ]]; then
        echo "ERROR: Cannot scan link-local addresses"
        return 0
    fi

    return 1
}

# Function to check if IP is private
is_private_ip() {
    local ip=$1

    # 10.0.0.0/8
    if [[ "$ip" =~ ^10\. ]]; then
        return 0
    fi

    # 172.16.0.0/12
    if [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        return 0
    fi

    # 192.168.0.0/16
    if [[ "$ip" =~ ^192\.168\. ]]; then
        return 0
    fi

    return 1
}

# Function to validate hostname
validate_hostname() {
    local hostname=$1

    # Check for valid hostname format
    if ! echo "$hostname" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'; then
        return 1
    fi

    # Block dangerous hostnames
    if [[ "$hostname" == "localhost" ]] || [[ "$hostname" == "localhost.localdomain" ]]; then
        echo "ERROR: Cannot scan localhost"
        return 1
    fi

    # Block metadata service hostnames
    if [[ "$hostname" == "metadata.google.internal" ]] || [[ "$hostname" == "metadata.aws.internal" ]]; then
        echo "ERROR: Cannot scan cloud metadata services"
        return 1
    fi

    return 0
}

# Main validation
main() {
    local target="${1:-}"

    if [ -z "$target" ]; then
        echo "ERROR: No target provided"
        exit 1
    fi

    # Remove any shell metacharacters for safety
    target=$(echo "$target" | sed 's/[;&|`$()<>]//g')

    # Check if it's an IP address
    if validate_ip "$target"; then
        # It's a valid IP, check if dangerous
        if is_dangerous_ip "$target"; then
            exit 1
        fi

        # Warn about private IPs
        if is_private_ip "$target"; then
            echo "WARNING: Targeting private IP address: $target"
        fi

        echo "VALID_IP: $target"
        exit 0
    fi

    # Check if it's a hostname
    if validate_hostname "$target"; then
        echo "VALID_HOSTNAME: $target"
        exit 0
    fi

    # Check if it's a CIDR range
    if echo "$target" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$'; then
        # Extract the IP part
        ip_part=$(echo "$target" | cut -d'/' -f1)
        cidr_part=$(echo "$target" | cut -d'/' -f2)

        if validate_ip "$ip_part" && [ "$cidr_part" -ge 0 ] && [ "$cidr_part" -le 32 ]; then
            # Check if the base IP is dangerous
            if is_dangerous_ip "$ip_part"; then
                exit 1
            fi

            echo "VALID_CIDR: $target"
            exit 0
        fi
    fi

    echo "ERROR: Invalid target format: $target"
    exit 1
}

# Run main function
main "$@"